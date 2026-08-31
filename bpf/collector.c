#define SEC(name) __attribute__((section(name), used))
#define ALWAYS_INLINE inline __attribute__((always_inline))

#include "protocol.h"

enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_ANY = 0,
};

struct sched_process_fork_context {
    __u64 common;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

struct sched_process_exec_context {
    __u64 common;
    __u32 filename;
    __s32 pid;
    __s32 old_pid;
};

struct sched_process_exit_context {
    __u64 common;
    char comm[16];
    __s32 pid;
    __s32 priority;
};

struct raw_syscalls_enter_context {
    __u64 common;
    __s64 id;
    __u64 arguments[6];
};

struct raw_syscalls_exit_context {
    __u64 common;
    __s64 id;
    __s64 result;
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf_map_def SEC("maps") TARGET_CGROUP = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") EVENTS = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 0,
};

struct bpf_map_def SEC("maps") SYSCALL_OPERATIONS = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__s64),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

struct bpf_map_def SEC("maps") PENDING_SYSCALLS = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct execwake_event),
    .max_entries = 32768,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_perf_event_output)(void *context, void *map, __u64 flags,
                                     const void *data, __u64 size) = (void *)25;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_probe_read_kernel_str)(void *destination, __u32 size,
                                         const void *source) = (void *)115;
static long (*bpf_probe_read_user)(void *destination, __u32 size,
                                   const void *source) = (void *)112;
static long (*bpf_probe_read_user_str)(void *destination, __u32 size,
                                       const void *source) = (void *)114;

static ALWAYS_INLINE int in_target_cgroup(void) {
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&TARGET_CGROUP, &key);
    return target && bpf_get_current_cgroup_id() == *target;
}

static ALWAYS_INLINE void initialize_event(struct execwake_event_header *event,
                                            __u16 kind) {
    __u64 process = bpf_get_current_pid_tgid();
    event->version = EXECWAKE_PROTOCOL_VERSION;
    event->kind = kind;
    event->size = sizeof(*event);
    event->monotonic_ns = bpf_ktime_get_ns();
    event->tgid = process >> 32;
    event->tid = (__u32)process;
    event->result = EXECWAKE_RESULT_UNKNOWN;
    event->data_length = 0;
    event->flags = 0;
}

static ALWAYS_INLINE void capture_address(struct execwake_event *event,
                                           const void *address, __u64 length) {
    if (!address || !length)
        return;
    struct execwake_socket_data *data = (void *)event->data;
    __u32 captured = length;
    captured &= 0xff;
    if (captured > sizeof(data->address))
        captured = sizeof(data->address);
    if (length > sizeof(data->address)) {
        captured = sizeof(data->address);
        event->header.flags |= EXECWAKE_DATA_TRUNCATED;
    }
    if (bpf_probe_read_user(data->address, captured, address) == 0) {
        data->address_length = captured;
        event->header.flags |= EXECWAKE_DATA_HAS_ADDRESS;
    }
}

static ALWAYS_INLINE void capture_payload(struct execwake_event *event,
                                           const void *payload, __u64 length) {
    if (!payload || !length)
        return;
    struct execwake_socket_data *data = (void *)event->data;
    __u32 captured = length;
    captured &= 0xff;
    if (captured > sizeof(data->payload))
        captured = sizeof(data->payload);
    if (length > sizeof(data->payload)) {
        captured = sizeof(data->payload);
        event->header.flags |= EXECWAKE_DATA_TRUNCATED;
    }
    if (bpf_probe_read_user(data->payload, captured, payload) == 0) {
        data->payload_length = captured;
        event->header.flags |= EXECWAKE_DATA_HAS_PAYLOAD;
    }
}

static ALWAYS_INLINE void capture_first_path(struct execwake_event *event,
                                              const void *path) {
    if (!path)
        return;
    struct execwake_path_data *data = (void *)event->data;
    long length = bpf_probe_read_user_str(data->first, sizeof(data->first), path);
    if (length > 0) {
        data->first_length = length - 1;
        event->header.flags |= EXECWAKE_DATA_HAS_FIRST_PATH;
        if (length == sizeof(data->first))
            event->header.flags |= EXECWAKE_DATA_TRUNCATED;
    }
}

static ALWAYS_INLINE void capture_second_path(struct execwake_event *event,
                                               const void *path) {
    if (!path)
        return;
    struct execwake_path_data *data = (void *)event->data;
    long length = bpf_probe_read_user_str(data->second, sizeof(data->second), path);
    if (length > 0) {
        data->second_length = length - 1;
        event->header.flags |= EXECWAKE_DATA_HAS_SECOND_PATH;
        if (length == sizeof(data->second))
            event->header.flags |= EXECWAKE_DATA_TRUNCATED;
    }
}

static ALWAYS_INLINE void capture_path_data(struct execwake_event *event,
                                             __u32 operation) {
    if (operation == EXECWAKE_SYSCALL_OPEN_AT ||
        operation == EXECWAKE_SYSCALL_OPEN_AT_2 ||
        operation == EXECWAKE_SYSCALL_UNLINK_AT ||
        operation == EXECWAKE_SYSCALL_MAKE_DIRECTORY_AT ||
        operation == EXECWAKE_SYSCALL_STAT_AT ||
        operation == EXECWAKE_SYSCALL_READ_LINK_AT) {
        capture_first_path(event, (void *)event->header.arguments[1]);
    } else if (operation == EXECWAKE_SYSCALL_RENAME_AT ||
               operation == EXECWAKE_SYSCALL_LINK_AT) {
        capture_first_path(event, (void *)event->header.arguments[1]);
        capture_second_path(event, (void *)event->header.arguments[3]);
    } else if (operation == EXECWAKE_SYSCALL_SYMLINK_AT) {
        capture_first_path(event, (void *)event->header.arguments[0]);
        capture_second_path(event, (void *)event->header.arguments[2]);
    } else if (operation == EXECWAKE_SYSCALL_TRUNCATE ||
               operation == EXECWAKE_SYSCALL_CHANGE_DIRECTORY ||
               operation == EXECWAKE_SYSCALL_OPEN ||
               operation == EXECWAKE_SYSCALL_CREATE ||
               operation == EXECWAKE_SYSCALL_UNLINK ||
               operation == EXECWAKE_SYSCALL_MAKE_DIRECTORY ||
               operation == EXECWAKE_SYSCALL_REMOVE_DIRECTORY ||
               operation == EXECWAKE_SYSCALL_STAT) {
        capture_first_path(event, (void *)event->header.arguments[0]);
    } else if (operation == EXECWAKE_SYSCALL_RENAME ||
               operation == EXECWAKE_SYSCALL_LINK ||
               operation == EXECWAKE_SYSCALL_SYMLINK) {
        capture_first_path(event, (void *)event->header.arguments[0]);
        capture_second_path(event, (void *)event->header.arguments[1]);
    }
}

static ALWAYS_INLINE void capture_enter_data(struct execwake_event *event,
                                              __u32 operation) {
    if (operation == EXECWAKE_SYSCALL_OPEN_AT_2) {
        __u64 flags = 0;
        if (bpf_probe_read_user(&flags, sizeof(flags),
                                (void *)event->header.arguments[2]) == 0)
            event->header.arguments[2] = flags;
    }
    if (operation == EXECWAKE_SYSCALL_BIND ||
        operation == EXECWAKE_SYSCALL_CONNECT) {
        capture_address(event, (void *)event->header.arguments[1],
                        event->header.arguments[2]);
    } else if (operation == EXECWAKE_SYSCALL_SENDTO) {
        capture_address(event, (void *)event->header.arguments[4],
                        event->header.arguments[5]);
        capture_payload(event, (void *)event->header.arguments[1],
                        event->header.arguments[2]);
    } else if (operation == EXECWAKE_SYSCALL_WRITE) {
        capture_payload(event, (void *)event->header.arguments[1],
                        event->header.arguments[2]);
    }
    capture_path_data(event, operation);
}

static ALWAYS_INLINE void capture_exit_data(struct execwake_event *event,
                                             __u32 operation, __s64 result) {
    if (result <= 0)
        return;
    if (operation == EXECWAKE_SYSCALL_RECVFROM) {
        __u32 address_length = 0;
        if (event->header.arguments[5] &&
            bpf_probe_read_user(&address_length, sizeof(address_length),
                                (void *)event->header.arguments[5]) == 0) {
            capture_address(event, (void *)event->header.arguments[4],
                            address_length);
        }
        capture_payload(event, (void *)event->header.arguments[1], result);
    } else if (operation == EXECWAKE_SYSCALL_ACCEPT) {
        __u32 address_length = 0;
        if (event->header.arguments[2] &&
            bpf_probe_read_user(&address_length, sizeof(address_length),
                                (void *)event->header.arguments[2]) == 0) {
            capture_address(event, (void *)event->header.arguments[1],
                            address_length);
        }
    } else if (operation == EXECWAKE_SYSCALL_READ) {
        capture_payload(event, (void *)event->header.arguments[1], result);
    }
}

SEC("tracepoint/sched_process_fork")
int observe_process_fork(struct sched_process_fork_context *context) {
    if (!in_target_cgroup())
        return 0;

    struct execwake_event_header event = {};
    initialize_event(&event, EXECWAKE_EVENT_PROCESS_FORK);
    event.arguments[0] = context->parent_pid;
    event.arguments[1] = context->child_pid;
    bpf_perf_event_output(context, &EVENTS, 0xffffffffULL, &event,
                          sizeof(event));
    return 0;
}

SEC("tracepoint/sched_process_exec")
int observe_process_exec(struct sched_process_exec_context *context) {
    if (!in_target_cgroup())
        return 0;

    struct execwake_event event = {};
    initialize_event(&event.header, EXECWAKE_EVENT_PROCESS_EXEC);
    event.header.arguments[0] = context->pid;
    event.header.arguments[1] = context->old_pid;
    __u32 offset = context->filename & 0xffff;
    long length = bpf_probe_read_kernel_str(event.data, sizeof(event.data),
                                            (void *)context + offset);
    __u32 output_size = sizeof(event.header);
    if (length > 0) {
        event.header.data_length = length;
        output_size += length;
    }
    if (output_size > sizeof(event))
        return 0;
    event.header.size = output_size;
    bpf_perf_event_output(context, &EVENTS, 0xffffffffULL, &event,
                          output_size);
    return 0;
}

SEC("tracepoint/sched_process_exit")
int observe_process_exit(struct sched_process_exit_context *context) {
    if (!in_target_cgroup())
        return 0;

    struct execwake_event_header event = {};
    initialize_event(&event, EXECWAKE_EVENT_PROCESS_EXIT);
    event.arguments[0] = context->pid;
    bpf_perf_event_output(context, &EVENTS, 0xffffffffULL, &event,
                          sizeof(event));
    return 0;
}

SEC("tracepoint/raw_syscalls_sys_enter")
int observe_syscall_enter(struct raw_syscalls_enter_context *context) {
    if (!in_target_cgroup())
        return 0;

    __s64 syscall_id = context->id;
    __u32 *operation = bpf_map_lookup_elem(&SYSCALL_OPERATIONS, &syscall_id);
    if (!operation)
        return 0;

    __u64 key = bpf_get_current_pid_tgid();
    struct execwake_event event = {};
    initialize_event(&event.header, EXECWAKE_EVENT_SYSCALL);
    event.header.flags = *operation & EXECWAKE_SYSCALL_OPERATION_MASK;
    event.header.arguments[0] = context->arguments[0];
    event.header.arguments[1] = context->arguments[1];
    event.header.arguments[2] = context->arguments[2];
    event.header.arguments[3] = context->arguments[3];
    event.header.arguments[4] = context->arguments[4];
    event.header.arguments[5] = context->arguments[5];
    capture_enter_data(&event, *operation);
    if (event.header.flags &
        (EXECWAKE_DATA_HAS_ADDRESS | EXECWAKE_DATA_HAS_PAYLOAD |
         EXECWAKE_DATA_HAS_FIRST_PATH | EXECWAKE_DATA_HAS_SECOND_PATH)) {
        event.header.data_length = sizeof(event.data);
        event.header.size = sizeof(event);
    }
    bpf_map_update_elem(&PENDING_SYSCALLS, &key, &event, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls_sys_exit")
int observe_syscall_exit(struct raw_syscalls_exit_context *context) {
    if (!in_target_cgroup())
        return 0;

    __u64 key = bpf_get_current_pid_tgid();
    struct execwake_event *event = bpf_map_lookup_elem(&PENDING_SYSCALLS, &key);
    if (!event)
        return 0;
    __u32 operation = event->header.flags & EXECWAKE_SYSCALL_OPERATION_MASK;
    event->header.result = context->result;
    capture_exit_data(event, operation, context->result);
    if (event->header.flags &
        (EXECWAKE_DATA_HAS_ADDRESS | EXECWAKE_DATA_HAS_PAYLOAD)) {
        event->header.data_length = sizeof(event->data);
        event->header.size = sizeof(*event);
    }
    __u32 output_size = event->header.size;
    if (output_size < sizeof(event->header) || output_size > sizeof(*event)) {
        bpf_map_delete_elem(&PENDING_SYSCALLS, &key);
        return 0;
    }
    bpf_perf_event_output(context, &EVENTS, 0xffffffffULL, event,
                          output_size);
    bpf_map_delete_elem(&PENDING_SYSCALLS, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
