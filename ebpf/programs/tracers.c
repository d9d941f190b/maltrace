#include "../../include/vmlinux.h"

// BPF
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


// Structs
#include "default_structs.h"
#include "custom_structs.h"

#define MAX_ARG_LEN 256
/*IMPLEMENT CUSTOM MAP FOR THIS IN C AND TAKE VARIABLES FROM HERE*/
#define EVENT_TYPE_EXECVE 59
#define EVENT_TYPE_OPENAT 257

// BPF ringbuf map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256  * 1024 /* 256 KB */);
} events SEC(".maps");

/*Later add process namespace information -> user, network info*/

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_syscall(struct format_syscall_execve *ctx){
    // Buffer initialization, eventId setup
    struct execve_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->eventId = EVENT_TYPE_EXECVE;
    e->args_count=0;

    // Host and Parent tasks
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
    u64 tgid = bpf_get_current_pid_tgid();

    // Get Host and Parent PID
    e->host_pid = tgid >>32;
    e->host_ppid = BPF_CORE_READ(parent_task, pid);
    // Get filename path
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);
    u8 local_args_count = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        e->args[i][0] = '\0';
    }

    // Read arguments until hitting MAX_ARGS
    const char *arg_ptr;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
     // Read the pointer to the current argument
        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &ctx->argv[i]) < 0 || !arg_ptr) {
            break;
        }
        

    // Read the argument string into our buffer 
        if (bpf_probe_read_user_str(e->args[i], MAX_ARG_LEN, arg_ptr) > 0) {
             local_args_count++;
        }
    }
    e->args_count = local_args_count;
    // Submit event to userspace
    bpf_ringbuf_submit(e, 0);
    return 0;
      
}


SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_syscall(struct format_syscall_openat *ctx)
{
    struct openat_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->eventId = EVENT_TYPE_OPENAT;

    // Host and Parent tasks
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
    u64 tgid = bpf_get_current_pid_tgid();

    // Get Host and Parent PID
    e->host_pid = tgid >>32;
    e->host_ppid = BPF_CORE_READ(parent_task, pid);

    // Get filename path
    // char *filename_ptr = (char *)ctx->filename;
    // bpf_core_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    const char *filename_ptr;
    bpf_probe_read_user(&filename_ptr, sizeof(filename_ptr), &ctx->filename);
    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    }


    // Parse flags and mdoe
    e->flags = (u64)ctx->flags;    
    e->mode = (u64)ctx->mode;

    // Submit event to userspace
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";