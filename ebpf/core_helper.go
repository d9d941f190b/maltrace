package ebpf

import (
	types "bpf-dev/ebpf/types"
	utils "bpf-dev/runner/utils"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

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
	logs         []string
	syscallLogs  map[uint32][]string
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	logRetention int
	randSource   *rand.Rand
}

// NewEBPFProgram creates a new EBPFProgram with custom options
func NewEBPFProgram(procTTL time.Duration, logRetention int) *EBPFProgram {
	if procTTL == 0 {
		procTTL = 10 * time.Minute // Default: keep process info for 10 minutes
	}

	if logRetention == 0 {
		logRetention = 10000 // Default: keep last 10,000 logs
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &EBPFProgram{
		programs:     make(map[string]*bpf.BPFProg),
		links:        make(map[string]*bpf.BPFLink),
		logs:         make([]string, 0, logRetention),
		syscallLogs:  make(map[uint32][]string),
		events:       make(chan types.Event, 1000),
		ctx:          ctx,
		cancel:       cancel,
		logRetention: logRetention,
		randSource:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// LoadEBPFProgram loads and initializes the eBPF program
func LoadEBPFProgram() (*EBPFProgram, error) {
	return LoadEBPFProgramWithOptions(10*time.Minute, 10000)
}

func (p *EBPFProgram) generateRandomID() uint64 {
	return p.randSource.Uint64()
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
	var attachErrors []string
	// Attach specific syscall tracers using the mapping
	for fnName, sysName := range types.FnToSys {
		parts := strings.Split(sysName, "_")
		if len(parts) < 3 {
			return fmt.Errorf("invalid syscall name format: %s", sysName)
		}

		category := "syscalls"

		if err := p.attachTracepoint(fnName, category, sysName); err != nil {
			log.Printf("Warning: failed to attach %s: %v", fnName, err)
			/*Further implement other tracers such as kprobes or uprobes*/
			attachErrors = append(attachErrors, fmt.Sprintf("%s: %v", fnName, err))
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

	if len(attachErrors) > 0 {
		return fmt.Errorf("some tracepoints failed to attach: %s", strings.Join(attachErrors, "; "))
	}

	return nil
}

// attachTracepoint attaches a specific BPF program to a tracepoint
func (p *EBPFProgram) attachTracepoint(progName, category, tracepoint string) error {
	prog, err := p.module.GetProgram(progName)
	if err != nil {
		// Program not found, which is fine - maybe this specific tracer isn't included
		log.Printf("Program %s not found, skipping", progName)
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
			if len(data) < 4 {
				continue
			}
			// First 4  indicate event type
			eventType := types.EventType(binary.LittleEndian.Uint32(data[0:4]))
			// Check if the event type is valid
			_, exists := types.SysToName[uint32(eventType)]
			if !exists {
				log.Printf("Unknown event type: %d", eventType)
				continue
			}
			// Create a new event struct
			event := types.Event{
				Type:      eventType,
				EventID:   uint32(eventType),
				Timestamp: time.Now(),
			}

			// Parse event based on type
			switch eventType {
			case types.EVENT_EXECVE:
				var execve types.ExecveEvent
				reader := bytes.NewReader(data)
				if err := binary.Read(reader, binary.LittleEndian, &execve); err != nil {
					log.Printf("Failed to parse execve event: %v", err)
					continue
				}
				event.Execve = execve
				event.LogMessage = p.logExecveEvent(&execve)
			case types.EVENT_OPENAT:
				var openat types.OpenatEvent
				reader := bytes.NewReader(data)
				if err := binary.Read(reader, binary.LittleEndian, &openat); err != nil {
					log.Printf("Failed to parse openat event: %v", err)
					continue
				}
				event.Openat = openat
				event.LogMessage = p.logOpenatEvent(&openat)
			// case types.EVENT_READ:
			// 	var read types.ReadEvent
			// 	if err := binary.Read(bytes.NewBuffer(data[0:]), binary.LittleEndian, &read); err != nil {
			// 		log.Printf("Failed to parse openat event: %v", err)
			// 		continue
			// 	}
			// 	event.Read = read
			// 	event.LogMessage = p.logReadEvent(&read)
			case types.EVENT_SOCKET:
				var socket types.SocketEvent
				reader := bytes.NewReader(data)
				if err := binary.Read(reader, binary.LittleEndian, &socket); err != nil {
					log.Printf("Failed to parse socket event: %v", err)
					continue
				}
				event.Socket = socket
				event.LogMessage = p.logSocketEvent(&socket)
			default:
				log.Printf("Unknown event: %d", eventType)
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

		case <-p.ctx.Done():
			return
		}
	}
}
func (p *EBPFProgram) logSocketEvent(event *types.SocketEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	timestamp, _ := utils.GetProcessStartTime(event.Pid)
	/* Incorrectly parsed!*/
	jsonentry := types.SocketLog{
		Timestamp: timestamp,
		EventType: "syscall",
		EventName: "socket",
		ProcessInfo: types.SocketProcess{
			Pid:      event.Pid,
			Ppid:     event.PPid,
			Family:   event.Family,
			Type:     event.Type,
			Protocol: event.Protocol,
		},
	}
	jsonLog, err := json.Marshal(jsonentry)
	if err != nil {
		fmt.Printf("Error marshaling execve log to JSON: %v\n", err)
		return ""
	}
	jsonLogStr := string(jsonLog)
	p.addLogEntry(jsonLogStr)

	// Add to syscall-specific logs for socket (41)
	if _, ok := p.syscallLogs[41]; !ok {
		p.syscallLogs[41] = make([]string, 0, 100)
	}
	p.syscallLogs[41] = append(p.syscallLogs[41], jsonLogStr)

	return jsonLogStr
}

// logExecveEvent creates a detailed log entry for an execve syscall
func (p *EBPFProgram) logExecveEvent(event *types.ExecveEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	executablePath := nullTerminatedByteArrayToString(event.Filename[:])
	executableHash, err := utils.CalculateFileHash(executablePath)
	if err != nil {
		if os.IsNotExist(err) {
			executableHash = ""
		}
	}
	timestamp, _ := utils.GetProcessStartTime(event.Pid)

	args := make([]string, 0, MAX_ARGS)
	for i := 0; i < MAX_ARGS; i++ {
		arg := nullTerminatedByteArrayToString(event.Args[i][:])
		if arg != "" {
			args = append(args, arg)
		}
	}
	command := nullTerminatedByteArrayToString(event.Command[:]) + " " + strings.Join(args, " ")

	jsonentry := types.ExecveLog{
		Timestamp: timestamp,
		EventType: "syscall",
		EventName: "execve",
		ProcessInfo: types.ExecveProcess{
			Pid:      event.Pid,
			Filename: executablePath,
			Hash:     executableHash,
			Command:  command,
			Ppid:     event.PPid,
		},
	}
	jsonLog, err := json.Marshal(jsonentry)
	if err != nil {
		fmt.Printf("Error marshaling execve log to JSON: %v\n", err)
		return ""
	}
	jsonLogStr := string(jsonLog)
	p.addLogEntry(jsonLogStr)
	// p.addLogEntry(logEntry)

	// Add to syscall-specific logs for execve (59)
	if _, ok := p.syscallLogs[59]; !ok {
		p.syscallLogs[59] = make([]string, 0, 100)
	}
	p.syscallLogs[59] = append(p.syscallLogs[59], jsonLogStr)

	return jsonLogStr
}

// logOpenatEvent creates a detailed log entry for an openat syscall
func (p *EBPFProgram) logOpenatEvent(event *types.OpenatEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	filename := nullTerminatedByteArrayToString(event.Filename[:])
	flags := formatOpenFlags(event.Flags)
	/*Temporary deleted, causes self loop*/
	/*After implementation of PID tracking mechanism exclude the maltrace agent from tracing*/

	// timestamp, _ := utils.GetProcessStartTime(event.Pid)

	logEntry := fmt.Sprintf(
		"[OPENAT] PID: %d, PPID: %d, File: %s, Flags: %s, Mode: %o",
		event.Pid, event.PPid, filename, flags, event.Mode,
	)

	jsonentry := types.OpenatLog{
		EventType: "syscall",
		EventName: "openat",
		ProcessInfo: types.OpenatProcess{
			Pid:      event.Pid,
			Filename: filename,
			Flags:    strings.Split(flags, "|"),
			Mode:     event.Mode,
			Ppid:     event.PPid,
		},
	}
	jsonLog, err := json.Marshal(jsonentry)
	if err != nil {
		fmt.Printf("Error marshaling execve log to JSON: %v\n", err)
		return ""
	}
	jsonLogStr := string(jsonLog)

	p.addLogEntry(jsonLogStr)

	if _, ok := p.syscallLogs[257]; !ok {
		p.syscallLogs[257] = make([]string, 0, 100)
	}
	p.syscallLogs[257] = append(p.syscallLogs[257], logEntry)

	return logEntry
}

func (p *EBPFProgram) logReadEvent(event *types.ReadEvent) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	buffer := nullTerminatedByteArrayToString(event.Buf[:])

	logEntry := fmt.Sprintf(
		"[READ] PID: %d, PPID: %d, Buffer: %s, Count: %d",
		event.Pid, event.PPid, buffer, event.Count,
	)

	p.addLogEntry(logEntry)

	// Add to syscall-specific logs for openat (257)
	if _, ok := p.syscallLogs[0]; !ok {
		p.syscallLogs[0] = make([]string, 0, 100)
	}
	p.syscallLogs[0] = append(p.syscallLogs[0], logEntry)

	return logEntry

}

// addLogEntry adds a log entry with rotation if needed
func (p *EBPFProgram) addLogEntry(jsonLogEntry string) {
	var logData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonLogEntry), &logData); err == nil {
		// Add the hostname to the log data
		hostname, err := utils.GetHostname()
		if err == nil {
			logData["hostname"] = hostname
		} else {
			fmt.Printf("Error getting hostname: %v\n", err)
			logData["hostname"] = ""
		}
		// generate a random Id then add paranthesis signs to it
		logData["event_id"] = fmt.Sprintf("\"%d\"", p.generateRandomID())
		updatedJSON, err := json.Marshal(logData)
		if err == nil {
			p.logs = append(p.logs, string(updatedJSON))
			if len(p.logs) > p.logRetention {
				p.logs = p.logs[1:]
			}
			return
		} else {
			fmt.Printf("Error remarshaling with EventId: %v\n", err)
		}
	} else {
		fmt.Printf("Error unmarshaling for EventId: %v\n", err)
	}
	// If errors happen
	p.logs = append(p.logs, jsonLogEntry)
	if len(p.logs) > p.logRetention {
		p.logs = p.logs[1:]
	}
}

// formatOpenFlags converts open flags to a human-readable string
func formatOpenFlags(flags uint64) string {
	var results []string

	// Complete open flags map
	flagMap := map[uint64]string{
		0x0000:      "O_RDONLY",
		0x0001:      "O_WRONLY",
		0x0002:      "O_RDWR",
		0x0040:      "O_CREAT",
		0x0080:      "O_EXCL",
		0x0100:      "O_NOCTTY",
		0x0200:      "O_TRUNC",
		0x0400:      "O_APPEND",
		0x0800:      "O_NONBLOCK",
		0x1000:      "O_SYNC",
		0x2000:      "O_ASYNC",
		0x4000:      "O_DIRECT",
		0x8000:      "O_LARGEFILE", // 0x8000 (32-bit) or 0x100000 (64-bit systems)
		0x10000:     "O_DIRECTORY",
		0x20000:     "O_NOFOLLOW",
		0x40000:     "O_NOATIME",
		0x80000:     "O_CLOEXEC", // 0x80000 (32-bit) or 0x200000 (64-bit systems)
		0x100000:    "O_PATH",
		0x200000:    "O_TMPFILE",
		0x100000000: "O_LARGEFILE_64BIT", // 64-bit specific value
		0x200000000: "O_CLOEXEC_64BIT",   // 64-bit specific value
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

	// If unrecognized flags remain, add them as hex
	remainingFlags := flags
	for flag := range flagMap {
		if (flags & flag) == flag {
			remainingFlags &= ^flag
		}
	}

	if remainingFlags != 0 {
		results = append(results, fmt.Sprintf("0x%x", remainingFlags))
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
						case <-p.ctx.Done():
							p.mu.Unlock()
							close(ch)
							return
						}
					}
					lastIndex = len(logs)
				}
				p.mu.Unlock()
			case <-p.ctx.Done():
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

// Close cleans up all resources used by the eBPF program
func (p *EBPFProgram) Close() error {
	// Signal the goroutines to stop
	p.cancel()

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
	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}
	return nil
}
