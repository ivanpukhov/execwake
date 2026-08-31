#define SEC(name) __attribute__((section(name), used))

#include "protocol.h"

enum {
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
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

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_perf_event_output)(void *context, void *map, __u64 flags,
                                     const void *data, __u64 size) = (void *)25;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_probe_read_kernel_str)(void *destination, __u32 size,
                                         const void *source) = (void *)115;

static __inline int in_target_cgroup(void) {
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&TARGET_CGROUP, &key);
    return target && bpf_get_current_cgroup_id() == *target;
}

static __inline void initialize_event(struct execwake_event_header *event,
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

char LICENSE[] SEC("license") = "GPL";
