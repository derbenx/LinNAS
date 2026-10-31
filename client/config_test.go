package main

import (
	"os"
	"testing"
)

func TestClientConfigPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	cfg := LoadConfig()
	cfg.ServerEndpoint = "192.168.1.100:8080"
	cfg.Username = "tester"
	cfg.PasswordHash = HashPassword("secret123")
	cfg.SyncIntervalSec = 45
	cfg.ThrottleKBps = 1000
	cfg.SelectedFolders = map[string]bool{
		"docs":        true,
		"docs/work":   true,
		"photos/2026": true,
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	loaded := LoadConfig()
	if loaded.ServerEndpoint != "192.168.1.100:8080" {
		t.Errorf("Expected endpoint %s, got %s", "192.168.1.100:8080", loaded.ServerEndpoint)
	}
	if loaded.Username != "tester" {
		t.Errorf("Expected username tester, got %s", loaded.Username)
	}
	if loaded.PasswordHash != HashPassword("secret123") {
		t.Errorf("Password hash mismatch")
	}
	if loaded.SyncIntervalSec != 45 {
		t.Errorf("Expected sync interval 45, got %d", loaded.SyncIntervalSec)
	}
	if !loaded.SelectedFolders["docs/work"] {
		t.Errorf("Expected docs/work to be selected")
	}
}

func TestSelectiveSyncPathFiltering(t *testing.T) {
	// 1. When no folders are checked, all are selected (root default)
	emptySelected := make(map[string]bool)
	if !IsFolderSelected("anything", emptySelected) {
		t.Errorf("Expected empty selected map to sync all")
	}

	// 2. Selective filter
	selected := map[string]bool{
		"documents":      true,
		"documents/work": true,
		"music":          true,
	}

	// Direct match
	if !IsFolderSelected("documents", selected) {
		t.Errorf("Expected documents to be selected")
	}
	// Subfolder under selected
	if !IsFolderSelected("documents/work", selected) {
		t.Errorf("Expected documents/work to be selected")
	}
	if !IsFolderSelected("documents/personal", selected) {
		t.Errorf("Expected subfolder documents/personal to be selected because parent documents is checked")
	}
	// Unselected folder
	if IsFolderSelected("videos", selected) {
		t.Errorf("Expected videos to NOT be selected")
	}
	if IsFolderSelected("pictures/vacation", selected) {
		t.Errorf("Expected pictures/vacation to NOT be selected")
	}
}
