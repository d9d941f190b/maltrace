package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	types "bpf-dev/ebpf/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	objectFilePath   = "./output/tracers.o" // Path to the eBPF object file
	MAX_FILENAME_LEN = 256
	MAX_ARGS         = 20
	MAX_ARG_LEN      = 256
	MAX_DATA_SIZE    = 256
)

// EBPFProgram represents a loaded eBPF program with maps and ring buffers
type EBPFProgram struct {
	module       *bpf.Module
	ringBuf      *bpf.RingBuffer
	events       chan types.Event
	programs     map[string]*bpf.BPFProg
	links        map[string]*bpf.BPFLink
	logs         []string            // All logs
	syscallLogs  map[uint32][]string // Logs organized by syscall ID
	mu           sync.Mutex
	stopChan     chan struct{}
	logRetention int
}

// NewEBPFProgram creates a new EBPFProgram with custom options
func NewEBPFProgram(procTTL time.Duration, logRetention int) *EBPFProgram {
	if procTTL == 0 {
		procTTL = 10 * time.Minute // Default: keep process info for 10 minutes
	}

	if logRetention == 0 {
		logRetention = 10000 // Default: keep last 10,000 logs
	}

	return &EBPFProgram{
		programs:     make(map[string]*bpf.BPFProg),
		links:        make(map[string]*bpf.BPFLink),
		logs:         make([]string, 0, logRetention),
		syscallLogs:  make(map[uint32][]string),
		events:       make(chan types.Event, 1000),
		stopChan:     make(chan struct{}),
		logRetention: logRetention,
	}
}

// LoadEBPFProgram loads and initializes the eBPF program
func LoadEBPFProgram() (*EBPFProgram, error) {
	return LoadEBPFProgramWithOptions(10*time.Minute, 10000)
}

// LoadEBPFProgramWithOptions loads with custom options
func LoadEBPFProgramWithOptions(procTTL time.Duration, logRetention int) (*EBPFProgram, error) {

	// Check if eBPF object file exists

	if _, err := os.Stat(objectFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("eBPF object file not found at %s", objectFilePath)
	}

	// Create a new BPF module
	module, err := bpf.NewModuleFromFile(objectFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF module: %w", err)
	}

	// Initialize our EBPFProgram struct
	prog := NewEBPFProgram(procTTL, logRetention)
	prog.module = module

	// Resize maps if needed (adjust buffer sizes)
	if err := resizeMap(module, "events", 8192); err != nil {
		module.Close()
		return nil, fmt.Errorf("failed to resize events map: %w", err)
	}

	// Load the BPF object
	if err := module.BPFLoadObject(); err != nil {
		module.Close()
		return nil, fmt.Errorf("failed to load BPF object: %w", err)
	}

	return prog, nil
}

// AttachTracepoints attaches the eBPF programs to syscall tracepoints
func (p *EBPFProgram) AttachTracepoints() error {
	// Attach specific syscall tracers using the mapping
	for fnName, sysName := range types.FnToSys {
		parts := strings.Split(sysName, "_")
		if len(parts) < 3 {
			return fmt.Errorf("invalid syscall name format: %s", sysName)
		}

		category := "syscalls"

		if err := p.attachTracepoint(fnName, category, sysName); err != nil {
			log.Printf("Warning: failed to attach %s: %v", fnName, err)
			/*Implement this part*/
			// Continue with other tracers
		}
	}

	// Initialize the ring buffer
	rawChannel := make(chan []byte)
	ringBuf, err := p.module.InitRingBuf("events", rawChannel)
	if err != nil {
		return fmt.Errorf("failed to initialize ring buffer: %w", err)
	}
	p.ringBuf = ringBuf

	// Start processing events
	go p.processRawEvents(rawChannel)

	// Start the ring buffer
	ringBuf.Start()

	return nil
}

// attachTracepoint attaches a specific BPF program to a tracepoint
func (p *EBPFProgram) attachTracepoint(progName, category, tracepoint string) error {
	prog, err := p.module.GetProgram(progName)
	if err != nil {
		// Program not found, which is fine - maybe this specific tracer isn't included
		log.Printf("Warning: Program %s not found, skipping", progName)
		return err
	}

	link, err := prog.AttachTracepoint(category, tracepoint)
	if err != nil {
		return err
	}

	p.programs[progName] = prog
	p.links[progName] = link
	return nil
}

// processRawEvents processes raw events from the ring buffer
func (p *EBPFProgram) processRawEvents(rawChannel chan []byte) {
	for {
		select {
		case data := <-rawChannel:
			if len(data) < 1 {
				continue
			}

			// First byte indicates event type
			eventType := types.EventType(data[0])
			event := types.Event{
				Type:      eventType,
				Timestamp: time.Now(),
			}

			// Parse event based on type
			switch eventType {
			case types.EVENT_EXECVE:
				var execve types.ExecveEvent
				if err := binary.Read(bytes.NewBuffer(data[1:]), binary.LittleEndian, &execve); err != nil {
					log.Printf("Failed to parse execve event: %v", err)
					continue
				}
				event.Execve = execve
				event.LogMessage = p.logExecveEvent(&execve)

			case types.EVENT_OPENAT:
				var openat types.OpenatEvent
				if err := binary.Read(bytes.NewBuffer(data[1:]), binary.LittleEndian, &openat); err != nil {
					log.Printf("Failed to parse openat event: %v", err)
					continue
				}
				event.Openat = openat
				event.LogMessage = p.logOpenatEvent(&openat)

			default:
				log.Printf("Unknown event type: %d", eventType)
				continue
			}

			// Send the event to the channel
			select {
			case p.events <- event:
				// Event sent successfully
			default:
				// Channel is full, log and move on
				log.Printf("Event channel is full, dropping event")
			}

		case <-p.stopChan:
			return
		}
	}
}

// logSyscallEvent creates a log entry for a syscall event
func (p *EBPFProgram) logSyscallEvent(event *types.SyscallEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	syscallName := "unknown"
	if name, ok := types.SysToName[event.SyscallID]; ok {
		syscallName = name
	}

	comm := nullTerminatedByteArrayToString(event.Comm[:])
	logEntry := fmt.Sprintf(
		"[%s] PID: %d, Comm: %s, Syscall: %s(%d), Return: %d, Args: [0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x]",
		time.Unix(0, int64(event.Timestamp)),
		event.Pid,
		comm,
		syscallName,
		event.SyscallID,
		event.ReturnValue,
		event.Args[0], event.Args[1], event.Args[2],
		event.Args[3], event.Args[4], event.Args[5],
	)

	// Add to general logs
	p.addLogEntry(logEntry)

	// Add to syscall-specific logs
	if _, ok := p.syscallLogs[event.SyscallID]; !ok {
		p.syscallLogs[event.SyscallID] = make([]string, 0, 100)
	}
	p.syscallLogs[event.SyscallID] = append(p.syscallLogs[event.SyscallID], logEntry)

	// Trim if needed
	if len(p.syscallLogs[event.SyscallID]) > p.logRetention/10 {
		p.syscallLogs[event.SyscallID] = p.syscallLogs[event.SyscallID][1:]
	}

	return logEntry
}

// logExecveEvent creates a detailed log entry for an execve syscall
func (p *EBPFProgram) logExecveEvent(event *types.ExecveEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	filename := nullTerminatedByteArrayToString(event.Filename[:])
	args := make([]string, 0, int(event.ArgsCount))

	for i := 0; i < int(event.ArgsCount) && i < MAX_ARGS; i++ {
		arg := nullTerminatedByteArrayToString(event.Args[i][:])
		args = append(args, arg)
	}

	logEntry := fmt.Sprintf(
		"[EXECVE] PID: %d, PPID: %d, Command: %s, Args: [%s]",
		event.Pid, event.PPid, filename, strings.Join(args, " "),
	)

	p.addLogEntry(logEntry)

	// Add to syscall-specific logs for execve (59)
	if _, ok := p.syscallLogs[59]; !ok {
		p.syscallLogs[59] = make([]string, 0, 100)
	}
	p.syscallLogs[59] = append(p.syscallLogs[59], logEntry)

	return logEntry
}

// logOpenatEvent creates a detailed log entry for an openat syscall
func (p *EBPFProgram) logOpenatEvent(event *types.OpenatEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	filename := nullTerminatedByteArrayToString(event.Filename[:])
	flagsStr := formatOpenFlags(uint32(event.Flags))

	logEntry := fmt.Sprintf(
		"[OPENAT] PID: %d, PPID: %d, File: %s, Flags: %s, Mode: %o",
		event.Pid, event.PPid, filename, flagsStr, event.Mode,
	)

	p.addLogEntry(logEntry)

	// Add to syscall-specific logs for openat (257)
	if _, ok := p.syscallLogs[257]; !ok {
		p.syscallLogs[257] = make([]string, 0, 100)
	}
	p.syscallLogs[257] = append(p.syscallLogs[257], logEntry)

	return logEntry
}

// addLogEntry adds a log entry with rotation if needed
func (p *EBPFProgram) addLogEntry(logEntry string) {
	p.logs = append(p.logs, logEntry)

	// Trim logs if exceeding retention limit
	if len(p.logs) > p.logRetention {
		p.logs = p.logs[1:]
	}
}

// formatOpenFlags converts open flags to a human-readable string
func formatOpenFlags(flags uint32) string {
	var results []string

	// Common open flags
	flagMap := map[uint32]string{
		0x0000: "O_RDONLY",
		0x0001: "O_WRONLY",
		0x0002: "O_RDWR",
		0x0040: "O_CREAT",
		0x0080: "O_EXCL",
		0x0200: "O_TRUNC",
		0x0400: "O_APPEND",
		0x0800: "O_NONBLOCK",
		0x1000: "O_SYNC",
	}

	// Check for read/write flags first
	switch flags & 0x3 {
	case 0x0:
		results = append(results, "O_RDONLY")
	case 0x1:
		results = append(results, "O_WRONLY")
	case 0x2:
		results = append(results, "O_RDWR")
	}

	// Check for other flags
	for flag, name := range flagMap {
		if flag != 0x0 && flag != 0x1 && flag != 0x2 && (flags&flag) == flag {
			results = append(results, name)
		}
	}

	if len(results) == 0 {
		return fmt.Sprintf("0x%x", flags)
	}

	return strings.Join(results, "|")
}

// StreamEvents returns a channel of parsed events
func (p *EBPFProgram) StreamEvents() <-chan types.Event {
	return p.events
}

// StreamLogs returns a channel that provides logs as they are collected
func (p *EBPFProgram) StreamLogs() <-chan string {
	ch := make(chan string)
	go func() {
		var lastIndex int
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.mu.Lock()
				logs := p.logs
				if lastIndex < len(logs) {
					for _, log := range logs[lastIndex:] {
						select {
						case ch <- log:
							// Log sent successfully
						case <-p.stopChan:
							p.mu.Unlock()
							close(ch)
							return
						}
					}
					lastIndex = len(logs)
				}
				p.mu.Unlock()
			case <-p.stopChan:
				close(ch)
				return
			}
		}
	}()
	return ch
}

// GetLogs returns all collected logs
func (p *EBPFProgram) GetLogs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.logs...)
}

// GetSyscallLogs returns logs for a specific syscall
func (p *EBPFProgram) GetSyscallLogs(syscallID uint32) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if logs, ok := p.syscallLogs[syscallID]; ok {
		return append([]string{}, logs...)
	}
	return []string{}
}

// GetSyscallCount returns the number of syscalls recorded
// func (p *EBPFProgram) GetSyscallCount() int {
// 	p.mu.Lock()
// 	defer p.mu.Unlock()
// 	return p.syscallCount
// }

// GetProcessInfo returns process information
// func (p *EBPFProgram) GetProcessInfo(pid uint32) (*ProcessInfo, bool) {
// 	p.procMu.RLock()
// 	defer p.procMu.RUnlock()

// 	info, exists := p.processes[pid]
// 	if !exists {
// 		return nil, false
// 	}

// 	// Create a copy to avoid race conditions
// 	infoCopy := &ProcessInfo{
// 		Pid:          info.Pid,
// 		ParentPid:    info.ParentPid,
// 		Comm:         info.Comm,
// 		FirstSeen:    info.FirstSeen,
// 		LastSeen:     info.LastSeen,
// 		SyscallCount: make(map[uint32]int),
// 		ChildPids:    make([]uint32, len(info.ChildPids)),
// 	}

// 	for k, v := range info.SyscallCount {
// 		infoCopy.SyscallCount[k] = v
// 	}

// 	copy(infoCopy.ChildPids, info.ChildPids)

// 	return infoCopy, true
// }

// // GetExecutionTree returns the entire process execution tree
// func (p *EBPFProgram) GetExecutionTree() map[uint32][]uint32 {
// 	p.procMu.RLock()
// 	defer p.procMu.RUnlock()

// 	// Create a copy to avoid race conditions
// 	treeCopy := make(map[uint32][]uint32)
// 	for ppid, children := range p.execTree {
// 		treeCopy[ppid] = make([]uint32, len(children))
// 		copy(treeCopy[ppid], children)
// 	}

// 	return treeCopy
// }

// // GetAllProcesses returns all tracked processes
// func (p *EBPFProgram) GetAllProcesses() map[uint32]*ProcessInfo {
// 	p.procMu.RLock()
// 	defer p.procMu.RUnlock()

// 	// Create a copy to avoid race conditions
// 	processesCopy := make(map[uint32]*ProcessInfo)
// 	for pid, info := range p.processes {
// 		infoCopy := &ProcessInfo{
// 			Pid:          info.Pid,
// 			ParentPid:    info.ParentPid,
// 			Comm:         info.Comm,
// 			FirstSeen:    info.FirstSeen,
// 			LastSeen:     info.LastSeen,
// 			SyscallCount: make(map[uint32]int),
// 			ChildPids:    make([]uint32, len(info.ChildPids)),
// 		}

// 		for k, v := range info.SyscallCount {
// 			infoCopy.SyscallCount[k] = v
// 		}

// 		copy(infoCopy.ChildPids, info.ChildPids)
// 		processesCopy[pid] = infoCopy
// 	}

// 	return processesCopy
// }

// Close cleans up all resources used by the eBPF program
func (p *EBPFProgram) Close() error {
	// Signal the goroutines to stop
	close(p.stopChan)

	// Stop and close the ring buffer
	if p.ringBuf != nil {
		p.ringBuf.Stop()
		p.ringBuf.Close()
	}

	// Close all links
	for name, link := range p.links {
		if err := link.Destroy(); err != nil {
			log.Printf("Error destroying link %s: %v", name, err)
		}
	}

	// Close the module
	if p.module != nil {
		p.module.Close()
	}

	return nil
}

// Helper functions
func nullTerminatedByteArrayToString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}
	if err = m.Resize(size); err != nil {
		return err
	}
	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}
	return nil
}
