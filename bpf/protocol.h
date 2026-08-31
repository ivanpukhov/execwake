#ifndef EXECWAKE_BPF_PROTOCOL_H
#define EXECWAKE_BPF_PROTOCOL_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;

enum execwake_event_kind {
    EXECWAKE_EVENT_HEARTBEAT = 0,
    EXECWAKE_EVENT_PROCESS_FORK = 1,
    EXECWAKE_EVENT_PROCESS_EXEC = 2,
    EXECWAKE_EVENT_PROCESS_EXIT = 3,
    EXECWAKE_EVENT_SYSCALL = 4,
};

enum execwake_syscall_operation {
    EXECWAKE_SYSCALL_SOCKET = 1,
    EXECWAKE_SYSCALL_BIND = 2,
    EXECWAKE_SYSCALL_CONNECT = 3,
    EXECWAKE_SYSCALL_LISTEN = 4,
    EXECWAKE_SYSCALL_ACCEPT = 5,
    EXECWAKE_SYSCALL_CLOSE = 6,
    EXECWAKE_SYSCALL_DUP = 7,
    EXECWAKE_SYSCALL_FCNTL = 8,
    EXECWAKE_SYSCALL_SENDTO = 9,
    EXECWAKE_SYSCALL_RECVFROM = 10,
    EXECWAKE_SYSCALL_WRITE = 11,
    EXECWAKE_SYSCALL_READ = 12,
};

enum {
    EXECWAKE_PROTOCOL_VERSION = 1,
    EXECWAKE_EVENT_DATA_BYTES = 384,
    EXECWAKE_SOCKET_ADDRESS_BYTES = 128,
    EXECWAKE_SOCKET_PAYLOAD_BYTES = 248,
    EXECWAKE_SYSCALL_OPERATION_MASK = 0xffff,
    EXECWAKE_DATA_HAS_ADDRESS = 1 << 16,
    EXECWAKE_DATA_HAS_PAYLOAD = 1 << 17,
    EXECWAKE_DATA_TRUNCATED = 1 << 18,
};

#define EXECWAKE_RESULT_UNKNOWN (-9223372036854775807LL - 1)

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

struct execwake_socket_data {
    __u32 address_length;
    __u32 payload_length;
    __u8 address[EXECWAKE_SOCKET_ADDRESS_BYTES];
    __u8 payload[EXECWAKE_SOCKET_PAYLOAD_BYTES];
};

_Static_assert(sizeof(struct execwake_event_header) == 88,
               "unexpected event header size");
_Static_assert(sizeof(struct execwake_event) == 472,
               "unexpected event size");

#endif
