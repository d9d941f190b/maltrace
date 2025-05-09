package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bpf-dev/runner"
	types "bpf-dev/runner/tasktypes"
)

const asciiArt = `
███╗   ███╗ █████╗ ██╗  ████████╗██████╗  █████╗  ██████╗███████╗
████╗ ████║██╔══██╗██║  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██╔████╔██║███████║██║     ██║   ██████╔╝███████║██║     █████╗  
██║╚██╔╝██║██╔══██║██║     ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
██║ ╚═╝ ██║██║  ██║███████╗██║   ██║  ██║██║  ██║╚██████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
`

func main() {
	// Print ASCII art
	fmt.Println(asciiArt)

	// Define command line flags
	timeout := flag.Duration("t", time.Second, "timeout for the malware execution")
	path := flag.String("p", "", "path to the malware file")
	output := flag.String("o", "", "path to output file for logs (optional)")
	help := flag.Bool("help", false, "show help message")

	// Parse flags
	flag.Parse()

	// Show help if requested
	if *help {
		printHelp()
		os.Exit(0)
	}

	// Validate required flags
	if *path == "" {
		fmt.Println("Error: -p flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Create a context that is cancelled when the program receives an interrupt signal
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived termination signal, shutting down...")
		cancel()
		os.Exit(0)
	}()

	// Create new task
	task := &types.Task{
		Timeout:  *timeout,
		FilePath: *path,
	}

	// Run the task within the context
	result, err := runner.Run(ctx, task)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Task execution error: %v\n", err)
		os.Exit(1)
	}

	// Save logs to file if output is specified
	if *output != "" {
		if err := saveLogsToFile(result.Logs, *output); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save logs: %v\n", err)
		} else {
			fmt.Printf("Logs saved to %s\n", *output)
		}
	}
}

// printHelp displays usage information
func printHelp() {
	fmt.Println("Usage: maltrace [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  -p string")
	fmt.Println("        path to the malware file (required)")
	fmt.Println("  -t duration")
	fmt.Println("        timeout for the execution (default 120s)")
	fmt.Println("  -o string")
	fmt.Println("        path to output file for logs (optional)")
	fmt.Println("  -help")
	fmt.Println("        show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  maltrace -p ./suspicious_file -t 1m")
	fmt.Println("  maltrace -p /path/to/binary -t 450s -o logs.json")
}

// saveLogsToFile saves the logs to a file
func saveLogsToFile(logs []string, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	// Add indentation for readability
	encoder.SetIndent("", "  ")

	output := map[string][]interface{}{
		"events": make([]interface{}, 0, len(logs)),
	}

	for _, logEntry := range logs {
		var obj interface{}
		if err := json.Unmarshal([]byte(logEntry), &obj); err == nil {
			output["events"] = append(output["events"], obj)
		} else {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal log entry: %v - %s\n", err, logEntry)
			output["events"] = append(output["events"], logEntry)
		}
	}

	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode final JSON structure: %w", err)
	}

	fmt.Printf("Logs saved to %s in JSON format.\n", outputPath)
	return nil
}
