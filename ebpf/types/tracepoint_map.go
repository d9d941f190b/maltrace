package ebpf

// Syscall list
const (
	SYS_EXECVE = "sys_enter_execve"
	FN_EXECVE  = "trace_execve_syscall"

	SYS_OPENAT = "sys_enter_openat"
	FN_OPENAT  = "trace_openat_syscall"
)

// Functions to Syscall map
var FnToSys = map[string]string{
	FN_EXECVE: SYS_EXECVE,
	FN_OPENAT: SYS_OPENAT,
}

var SysToName = map[uint32]string{
	/*Group by operatio ntype -> network,process,filesystem*/
	0: "execve",
	1: "openat",
}
