// import (
// 	"bytes"
// 	"encoding/binary"
// 	"fmt"
// 	"log"
// 	"os"
// 	"os/signal"
// 	"strings"
// 	"syscall"

// 	bpf "github.com/aquasecurity/libbpfgo"
// )

// const (
// 	MAX_FILENAME_LEN = 256
// 	MAX_ARGS         = 20
// 	MAX_DATA_SIZE    = 256
// 	MAX_ARG_LEN      = 256
// )

// // ExecveEvent must match the C structure exactly
// type ExecveEvent struct {
// 	Pid       uint32
// 	PPid      uint32
// 	Filename  [MAX_FILENAME_LEN]byte
// 	Args      [MAX_ARGS][MAX_ARG_LEN]byte
// 	Envp      [MAX_DATA_SIZE]byte
// 	ArgsCount uint8 // Changed from uint32 to uint8 to match the C structure
// }

// func (e ExecveEvent) GetFilename() string {
// 	return nullTerminatedByteArrayToString(e.Filename[:])
// }

// func (e ExecveEvent) GetArgs() []string {
// 	var args []string

// 	// Use ArgsCount to determine how many arguments to process
// 	count := int(e.ArgsCount)
// 	if count > MAX_ARGS {
// 		count = MAX_ARGS
// 	}

// 	// Convert each null-terminated byte array to string
// 	for i := 0; i < count; i++ {
// 		arg := nullTerminatedByteArrayToString(e.Args[i][:])
// 		args = append(args, arg)
// 	}

// 	return args
// }

// func (e ExecveEvent) GetArgsString() string {
// 	return strings.Join(e.GetArgs(), " ")
// }

// func nullTerminatedByteArrayToString(b []byte) string {
// 	n := bytes.IndexByte(b, 0)
// 	if n < 0 {
// 		return string(b)
// 	}
// 	return string(b[:n])
// }

// func resizeMap(module *bpf.Module, name string, size uint32) error {
// 	m, err := module.GetMap(name)
// 	if err != nil {
// 		return err
// 	}
// 	if err = m.Resize(size); err != nil {
// 		return err
// 	}
// 	if actual := m.GetMaxEntries(); actual != size {
// 		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
// 	}
// 	return nil
// }

// func main() {
// 	// Load the BPF module
// 	bpfModule, err := bpf.NewModuleFromFile("./output/tracers.o")
// 	if err != nil {
// 		log.Fatalf("Failed to load BPF module: %v", err)
// 	}
// 	defer bpfModule.Close()

// 	// Resize the ring buffer if needed
// 	if err := resizeMap(bpfModule, "events", 8192); err != nil {
// 		log.Fatalf("Failed to resize map: %v", err)
// 	}

// 	// Load the BPF object
// 	if err := bpfModule.BPFLoadObject(); err != nil {
// 		log.Fatalf("Failed to load BPF object: %v", err)
// 	}

// 	// Get the program
// 	prog, err := bpfModule.GetProgram("trace_execve_syscall")
// 	if err != nil {
// 		log.Fatalf("Failed to get program: %v", err)
// 	}

// 	// Attach the program to the tracepoint
// 	if _, err := prog.AttachTracepoint("syscalls", "sys_enter_execve"); err != nil {
// 		log.Fatalf("Failed to attach tracepoint: %v", err)
// 	}

// 	// Initialize the ring buffer
// 	eventsChannel := make(chan []byte)
// 	ringBuf, err := bpfModule.InitRingBuf("events", eventsChannel)
// 	if err != nil {
// 		log.Fatalf("Failed to initialize ring buffer: %v", err)
// 	}

// 	// Start the ring buffer
// 	ringBuf.Start()
// 	defer func() {
// 		ringBuf.Stop()
// 		ringBuf.Close()
// 	}()

// 	// Set up signal handling for graceful shutdown
// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

// 	fmt.Println("Tracing execve syscalls... Press Ctrl+C to exit")

// 	// Process events
// 	for {
// 		select {
// 		case data := <-eventsChannel:
// 			var event ExecveEvent
// 			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
// 				log.Printf("Failed to parse event: %v", err)
// 				continue
// 			}

// 			// Print each argument separately for clarity
// 			log.Printf("ParentPID: %d, PID: %d, Command: %s,",
// 				event.PPid, event.Pid, event.GetArgsString())
// 			log.Println("---")

// 		case <-sigChan:
// 			fmt.Println("\nReceived signal, exiting...")
// 			return
// 		}
// 	}
// }