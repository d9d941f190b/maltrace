package main

import (
	"context"
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
   _____           .__    __                                   
  /     \  _____   |  | _/  |_ _______ _____     ____   ____   
 /  \ /  \ \__  \  |  | \   __\_  __ \\__  \   /  _ \ /    \  
/    Y    \ / __ \_|  |__|  |   |  | \/ / __ \_|  <_> )   |  \ 
\____|__  /(____  /|____/|__|   |__|   (____  /|____/|___|  / 
        \/      \/                          \/            \/                                                 
`

func main() {
	// Print ASCII art
	fmt.Println(asciiArt)

	// Define command line flags
	timeout := flag.Duration("t", 30*time.Second, "timeout for the malware execution")
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
	fmt.Println("  maltrace -p /path/to/binary -t 450s -o logs.txt")
}

// saveLogsToFile saves the logs to a file
func saveLogsToFile(logs []string, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, log := range logs {
		if _, err := fmt.Fprintln(file, log); err != nil {
			return err
		}
	}

	return nil
}
