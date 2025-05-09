#ifndef __DEFAULT_STRUCTS_H__
#define __DEFAULT_STRUCTS_H__

struct format_syscall_execve {
    unsigned short common_type;       
    unsigned char common_flags;       
    unsigned char common_preempt_count; 
    int common_pid;                   
    int __syscall_nr;                 
    
    const char *filename;             
    const char *const *argv;          
    const char *const *envp;          
};


struct format_syscall_openat {
    short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    
    long long dfd;                    
    const char *filename;             
    long long flags;                  
    long long mode;                   
};

struct format_syscall_socket{
    short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;

    int family;
    int type;
    int protocol;
};


// This is dangerous, as read syscall will flood your analysis
struct format_syscall_read {
    __s32 __syscall_nr;
    uint64_t fd;
    uint64_t *buf;
    uint64_t count;
};

#endif 