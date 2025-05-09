package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"bpf-dev/ebpf"
	taskType "bpf-dev/runner/tasktypes"
)

// Run executes the given task within the provided context
func Run(ctx context.Context, task *taskType.Task) (*taskType.TaskResult, error) {
	fmt.Println("Starting task execution...")
	startTime := time.Now()

	// Load eBPF programgik
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

	// Current collection implementation is with goroutine
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
		}
	}()

	// Execute the target file
	fmt.Printf("Executing file: %s with timeout %v\n", task.GetFilePath(), task.GetTimeout())
	execResult := executeFile(execCtx, task.GetFilePath())
	result.Success = (execResult == nil)

	// Wait until timeout
	fullTimeout := task.GetTimeout()
	time.Sleep(fullTimeout)

	// Give some time for final logs to be collected
	time.Sleep(1 * time.Second)

	// Collect results
	result.ElapsedTime = time.Since(startTime)
	fmt.Printf("Task completed in %v.\n", result.ElapsedTime)
	return result, nil
}

// executeFile runs the target file and monitors its execution
func executeFile(ctx context.Context, filePath string) error {
	// Sleep for a bit to allow the eBPF program to initialize
	time.Sleep(2 * time.Second)
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
