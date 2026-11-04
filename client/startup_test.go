package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStartupFileGenerationLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Testing Linux startup creation only on Linux")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Could not get home dir: %v", err)
	}

	desktopFile := filepath.Join(homeDir, ".config", "autostart", "linnas-client.desktop")
	// Clean up any existing
	_ = os.Remove(desktopFile)

	err = SetRunOnStartup(true)
	if err != nil {
		t.Fatalf("SetRunOnStartup(true) failed: %v", err)
	}

	if !IsRunOnStartupEnabled() {
		t.Fatal("IsRunOnStartupEnabled should be true after enabling")
	}

	data, err := os.ReadFile(desktopFile)
	if err != nil || len(data) == 0 {
		t.Fatalf("Expected desktop autostart file to exist: %v", err)
	}

	// Disable
	err = SetRunOnStartup(false)
	if err != nil {
		t.Fatalf("SetRunOnStartup(false) failed: %v", err)
	}

	if IsRunOnStartupEnabled() {
		t.Fatal("IsRunOnStartupEnabled should be false after disabling")
	}
}
