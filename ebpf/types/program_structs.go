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

type ExecveEvent struct {
	EventID   uint32
	Pid       uint32
	PPid      uint32
	Filename  [256]byte
	Args      [MAX_ARGS][MAX_ARG_LEN]byte
	Envp      [MAX_DATA_SIZE]byte
	Command   [64]byte
	ArgsCount uint8 // Changed from uint32 to uint8 to match the C structure
	// Timestamp    uint64 // errors with bpf_ktime_get_ns() https://github.com/iovisor/bcc/issues/578
	PIDNamespace uint32 // Added namespace awareness
}

type ExecveLog struct {
	EventID   uint32    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	// latter to be merged with type
	EventName   string        `json:"syscall_name"`
	ProcessInfo ExecveProcess `json:"process"`
}

type ExecveProcess struct {
	Pid      uint32 `json:"pid"`
	Filename string `json:"filename"`
	Hash     string `json:"hash,omitempty"`
	Command  string `json:"cmdline"`
	Ppid     uint32 `json:"parent_pid"`
}

type OpenatEvent struct {
	EventID  uint32
	Pid      uint32
	PPid     uint32
	Filename [MAX_FILENAME_LEN]byte
	Flags    uint64
	Mode     uint64
}

type OpenatLog struct {
	EventID     uint32        `json:"event_id"`
	Timestamp   time.Time     `json:"timestamp"`
	EventType   string        `json:"event_type"`
	EventName   string        `json:"syscall_name"`
	ProcessInfo OpenatProcess `json:"process"`
}

type OpenatProcess struct {
	Pid      uint32   `json:"pid"`
	Filename string   `json:"filename"`
	Flags    []string `json:"flags"`
	Mode     uint64   `json:"mode"`
	Ppid     uint32   `json:"parent_pid"`
}

type SocketEvent struct {
	EventID  uint32
	Pid      uint32
	PPid     uint32
	Family   uint32
	Type     uint32
	Protocol uint32
}

type SocketLog struct {
	EventID     uint32        `json:"event_id"`
	Timestamp   time.Time     `json:"timestamp"`
	EventType   string        `json:"event_type"`
	EventName   string        `json:"syscall_name"`
	ProcessInfo SocketProcess `json:"process"`
}

type SocketProcess struct {
	Pid      uint32 `json:"pid"`
	Ppid     uint32 `json:"parent_pid"`
	Family   uint32 `json:"socket_family"`
	Type     uint32 `json:"socket_type"`
	Protocol uint32 `json:"protocol"`
}

type ReadEvent struct {
	EventID uint32
	Pid     uint32
	PPid    uint32
	Buf     [MAX_DATA_SIZE]byte
	Count   uint64
}

type EventType uint32

/*INTEGRATE: THIS IS REDUNDANT NECESSARY CHANGES SHOULD BE MADE*/
const (
	EVENT_READ   = 0
	EVENT_EXECVE = 59
	EVENT_OPENAT = 257
	EVENT_SOCKET = 41
)

type Event struct {
	EventID    uint32
	Type       EventType
	Execve     ExecveEvent
	Openat     OpenatEvent
	Socket     SocketEvent
	Read       ReadEvent
	Timestamp  time.Time
	LogMessage string
}
