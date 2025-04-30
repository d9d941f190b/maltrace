package types

import (
	"time"
)

const (
	MAX_FILENAME_LEN = 256
	MAX_ARGS         = 20
	MAX_DATA_SIZE    = 256
	MAX_ARG_LEN      = 256
)

// General syscall event structure
// type SyscallEvent struct {
// 	EventID     uint32
// 	Pid         uint32
// 	Tgid        uint32
// 	Uid         uint32
// 	ReturnValue int64
// 	SyscallID   uint32
// 	Comm        [MAX_DATA_SIZE]byte
// 	Timestamp   uint64
// 	Args        [6]uint64
// }

type ExecveEvent struct {
	EventID   uint32
	Pid       uint32
	PPid      uint32
	Filename  [MAX_FILENAME_LEN]byte
	Args      [MAX_ARGS][MAX_ARG_LEN]byte
	Envp      [MAX_DATA_SIZE]byte
	ArgsCount uint8
}

type OpenatEvent struct {
	EventID  uint32
	Pid      uint32
	PPid     uint32
	Filename [MAX_FILENAME_LEN]byte
	Flags    uint32
	Mode     uint32
}

type EventType uint32

const (
	EVENT_EXECVE = 5
	EVENT_OPENAT = 6
)

type Event struct {
	EventID    uint32
	Type       EventType
	Execve     ExecveEvent
	Openat     OpenatEvent
	Timestamp  time.Time
	LogMessage string
}
