package utils

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func GetProcessStartTime(pid uint32) (time.Time, error) {
	// Read process stat file
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	content, err := os.ReadFile(statPath)
	if err != nil {
		return time.Time{}, err
	}

	// Parse the fields
	fields := strings.Fields(string(content))
	if len(fields) < 22 {
		return time.Time{}, errors.New("not enough fields in /proc/[pid]/stat")
	}

	// Get start time in jiffies
	startTimeJiffies, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse start time: %w", err)
	}

	// Get boot time using sysinfo
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return time.Time{}, fmt.Errorf("failed to get system info: %w", err)
	}

	// Calculate boot time
	bootTime := time.Now().Add(-time.Duration(info.Uptime) * time.Second)

	// Jiffies to seconds
	const HZ = 100
	processStartSeconds := int64(startTimeJiffies / HZ)

	// Calculate process start time
	processStartTime := bootTime.Add(time.Duration(processStartSeconds) * time.Second)

	return processStartTime, nil
}

func CalculateFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

