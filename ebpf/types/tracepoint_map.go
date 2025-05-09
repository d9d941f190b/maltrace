package types

// Syscall list
const (
	SYS_EXECVE = "sys_enter_execve"
	FN_EXECVE  = "trace_execve_syscall"

	SYS_OPENAT = "sys_enter_openat"
	FN_OPENAT  = "trace_openat_syscall"

	SYS_READ = "sys_enter_read"
	FN_READ  = "trace_read_syscall"

	SYS_SOCKET = "sys_enter_socket"
	FN_SOCKET  = "trace_socket_syscall"
)

// Functions to Syscall map
var FnToSys = map[string]string{
	FN_EXECVE: SYS_EXECVE,
	FN_OPENAT: SYS_OPENAT,
	// FN_READ:   SYS_READ,
	FN_SOCKET: SYS_SOCKET,
}

// This mapping is used to convert syscall numbers to syscall names,
// this is referenced in C code and custom_structs header file.
//
// Reference is Linux kernel v6.7: https://github.com/torvalds/linux/blob/v6.7/arch/x86/entry/syscalls/syscall_64.tbl
var SysToName = map[uint32]string{
	/*Integrate later*/
	/*Group by operatio ntype -> network,process,filesystem*/
	0:   "read",
	59:  "execve",
	257: "openat",
	41:  "socket",
}
