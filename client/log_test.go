package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLogFormatting(t *testing.T) {
	var logs []string
	appendTestLog := func(msg string) {
		timestamp := time.Now().Format("15:04:05")
		logs = append(logs, fmt.Sprintf("[%s] %s", timestamp, msg))
	}

	longError := "Server error: file busy in /path/to/very/long/directory/structure/and/conflict/message/with/detail"
	appendTestLog(longError)

	if len(logs) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(logs))
	}
	if !strings.Contains(logs[0], "Server error: file busy") {
		t.Errorf("Expected log to contain error text, got: %s", logs[0])
	}
}
