#ifndef EXECWAKE_BPF_PROTOCOL_H
#define EXECWAKE_BPF_PROTOCOL_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

enum execwake_event_kind {
    EXECWAKE_EVENT_HEARTBEAT = 0,
    EXECWAKE_EVENT_PROCESS_FORK = 1,
    EXECWAKE_EVENT_PROCESS_EXEC = 2,
    EXECWAKE_EVENT_PROCESS_EXIT = 3,
    EXECWAKE_EVENT_SYSCALL = 4,
};

enum {
    EXECWAKE_PROTOCOL_VERSION = 1,
    EXECWAKE_EVENT_DATA_BYTES = 384,
};

struct execwake_event_header {
    __u16 version;
    __u16 kind;
    __u32 size;
    __u64 monotonic_ns;
    __u32 tgid;
    __u32 tid;
    __s64 result;
    __u64 arguments[6];
    __u32 data_length;
    __u32 flags;
};

struct execwake_event {
    struct execwake_event_header header;
    __u8 data[EXECWAKE_EVENT_DATA_BYTES];
};

_Static_assert(sizeof(struct execwake_event_header) == 88,
               "unexpected event header size");
_Static_assert(sizeof(struct execwake_event) == 472,
               "unexpected event size");

#endif
