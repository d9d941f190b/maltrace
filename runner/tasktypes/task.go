package types

import (
	"time"
)

// Task represents the information about a task received by the Runner.
type Task struct {
	Timeout  time.Duration
	FilePath string
}

type TaskResult struct {
	Success      bool
	SyscallCount int
	Logs         []string
	ElapsedTime  time.Duration
}

// GetTimeout returns the timeout of the task.
func (t *Task) GetTimeout() time.Duration {
	return t.Timeout
}

// GetFilePath returns the file path of the task.
func (t *Task) GetFilePath() string {
	return t.FilePath
}
