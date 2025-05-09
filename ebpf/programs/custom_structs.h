#ifndef __CUSTOM_STRUCTS_H__
#define __CUSTOM_STRUCTS_H__

#define MAX_FILENAME_LEN 256
#define MAX_ARG_LEN 256
#define MAX_DATA_SIZE 256
#define MAX_ARGS 20

struct execve_event {
    __u32 eventId;
    __u32 pid;
    __u32 ppid;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][MAX_ARG_LEN];
    char envp[MAX_DATA_SIZE];
    char command[64];
    // REDUNDANT DELETE LATER
    __u8 args_count;
    //Namespace Awareness
    __u32 pid_ns_id;
};

struct openat_event {
    __u32 eventId;
    __u32 host_pid;
    __u32 host_ppid;
    char filename[MAX_FILENAME_LEN];
    __u64 flags;
    __u64 mode;
};

struct read_event{
    __u32 eventId;
    __u32 host_pid;
    __u32 host_ppid;
    __u64 fd;
    char buf[MAX_DATA_SIZE];
    __u64 count;
};

struct socket_event{
    __u32 eventId;
    __u32 host_pid;
    __u32 host_ppid;
    int family;
    int type;
    int protocol;
};


#endif // __CUSTOM_STRUCTS_H__