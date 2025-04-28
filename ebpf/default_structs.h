#ifndef __DEFAULT_STRUCTS_H__
#define __DEFAULT_STRUCTS_H__

struct format_syscall_execve {
    __u64 __unused;
    int syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};


struct format_syscall_openat {



};

#endif // __DEFAULT_STRUCTS_H__