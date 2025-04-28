package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	ebpf "bpf-dev/ebpf"
	taskType "bpf-dev/runner/tasktypes"
)

// Run executes the given task within the provided context
func Run(ctx context.Context, task *taskType.Task) (*taskType.TaskResult, error) {
	fmt.Println("Starting task execution...")
	startTime := time.Now()

	// Build eBPF program
	if err := buildEBPF(); err != nil {
		return nil, fmt.Errorf("failed to build eBPF program: %w", err)
	}

	// Load eBPF programgo
	ebpfProgram, err := ebpf.LoadEBPFProgram()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}
	defer ebpfProgram.Close()

	// Attach tracepoints
	if err := ebpfProgram.AttachTracepoints(); err != nil {
		return nil, fmt.Errorf("failed to attach tracepoints: %w", err)
	}
	fmt.Println("eBPF program loaded and tracepoints attached")

	/* Current collection implementation is with goroutine */
	result := &taskType.TaskResult{
		Logs: make([]string, 0),
	}

	// Execute the target file with timeout
	execCtx, cancel := context.WithTimeout(ctx, task.GetTimeout())
	defer cancel()

	// Start the log collection
	logChan := ebpfProgram.StreamLogs()
	go func() {
		for log := range logChan {
			result.Logs = append(result.Logs, log)
			// Print logs in real-time
			fmt.Println(log)
		}
	}()

	// Execute the target file
	fmt.Printf("Executing file: %s with timeout %v\n", task.GetFilePath(), task.GetTimeout())
	execResult := executeFile(execCtx, task.GetFilePath())
	result.Success = (execResult == nil)

	// Give some time for final logs to be collected
	time.Sleep(1 * time.Second)

	// Collect results
	result.ElapsedTime = time.Since(startTime)
	fmt.Printf("Task completed in %v.\n", result.ElapsedTime)
	return result, nil
}

// buildEBPF runs make clean and make to build the eBPF program
func buildEBPF() error {
	fmt.Println("Cleaning previous build...")
	cleanCmd := exec.Command("make", "clean")
	cleanCmd.Stdout = os.Stdout
	cleanCmd.Stderr = os.Stderr
	if err := cleanCmd.Run(); err != nil {
		return fmt.Errorf("make clean failed: %w", err)
	}

	fmt.Println("Building eBPF program...")
	buildCmd := exec.Command("make")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("make failed: %w", err)
	}

	return nil
}

/*No stats no collectEvents func ;) */
// collectEvents processes events from the eBPF program and updates result stats
// func collectEvents(ctx context.Context, program *ebpf.EBPFProgram, result *taskType.TaskResult, done chan struct{}) {
// 	defer close(done)

// 	eventChan := program.StreamEvents()

// 	// Process events until context is canceled or channel is closed
// 	for {
// 		select {
// 		case event, ok := <-eventChan:
// 			if !ok {
// 				return // Channel closed
// 			}

// 			// Process based on event type
// 			switch event.Type {
// 			case programStructs.EVENT_EXECVE:
// 				if event.Syscall != nil {
// 					// Update syscall stats
// 					syscallID := event.Syscall.SyscallID
// 					stat, exists := result.SyscallStats[syscallID]
// 					if !exists {
// 						stat = SyscallStat{
// 							Name:    getSyscallName(syscallID),
// 							Count:   0,
// 							MinTime: time.Duration(1<<63 - 1), // Max duration
// 						}
// 					}

// 					stat.Count++
// 					// Here we would update timing stats if we had entry/exit pairs

// 					result.SyscallStats[syscallID] = stat
// 				}

// 			case ebpf.EVENT_EXECVE:
// 				result.ExecveCount++

// 			case ebpf.EVENT_OPEN:
// 				result.OpenCount++
// 			}

// 		case <-ctx.Done():
// 			return
// 		}
// 	}
// }

// executeFile runs the target file and monitors its execution
func executeFile(ctx context.Context, filePath string) error {
	fmt.Printf("Executing file: %s\n", filePath)

	// Check if file exists and is executable
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file access error: %w", err)
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("path points to a directory, not an executable file")
	}

	// Make the file executable if it's not already
	if fileInfo.Mode()&0111 == 0 {
		if err := os.Chmod(filePath, fileInfo.Mode()|0111); err != nil {
			return fmt.Errorf("failed to make file executable: %w", err)
		}
	}

	// Get absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	/* Implement the functionality of running the file with custom parameters*/

	// Execute the file
	cmd := exec.CommandContext(ctx, absPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Starting target process...")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	// Wait for the command to complete or context to be canceled
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("process execution failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		// Try to kill the process if context is canceled
		if err := cmd.Process.Kill(); err != nil {
			fmt.Printf("Failed to kill process: %v\n", err)
		}
		return ctx.Err()
	}
}

// collectLogs reads logs from the eBPF program and sends them to logChan
// func collectLogs(program *ebpf.EBPFProgram, logChan chan<- string, doneChan chan<- struct{}) {
// 	for log := range program.StreamLogs() {
// 		logChan <- log
// 		// You can do additional processing with the logs here
// 		fmt.Println(log)
// 	}
// 	close(doneChan)
// }
