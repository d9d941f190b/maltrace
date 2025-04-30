#ifndef __CUSTOM_STRUCTS_H__
#define __CUSTOM_STRUCTS_H__

#define MAX_FILENAME_LEN 256
#define MAX_ARG_LEN 256
#define MAX_DATA_SIZE 256
#define MAX_ARGS 20

struct execve_event {
    __u8 eventId;
    __u32 host_pid;
    __u32 host_ppid;
    char filename[256];
    char args[MAX_ARGS][MAX_ARG_LEN];
    char envp[MAX_DATA_SIZE];
    __u8 args_count;
};

struct openat_event {
    __u8 eventId;
    __u32 host_pid;
    __u32 host_ppid;
    char filename[256];
    __u64 flags;
    __u64 mode;
};

#endif // __CUSTOM_STRUCTS_H__