#define SEC(name) __attribute__((section(name), used))

typedef unsigned int __u32;
typedef unsigned long long __u64;

enum {
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
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
    .max_entries = 128,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_perf_event_output)(void *context, void *map, __u64 flags,
                                     const void *data, __u64 size) = (void *)25;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;

SEC("raw_tracepoint/sys_enter")
int observe_sys_enter(void *context) {
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&TARGET_CGROUP, &key);
    if (!target || bpf_get_current_cgroup_id() != *target)
        return 0;

    __u64 process = bpf_get_current_pid_tgid();
    bpf_perf_event_output(context, &EVENTS, 0xffffffffULL, &process,
                          sizeof(process));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
