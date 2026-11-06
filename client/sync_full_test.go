package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientSyncEngineState(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client_sync_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ClientConfig{
		ServerEndpoint:  "127.0.0.1:8080",
		Username:        "admin",
		LocalSyncDir:    tmpDir,
		SyncEnabled:     true,
		SelectedFolders: map[string]bool{"excluded_dir": false},
	}

	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine failed: %v", err)
	}

	// Verify IsFolderSelected
	if !IsFolderSelected("docs/file.txt", engine.cfg.SelectedFolders) {
		t.Fatalf("docs should be selected")
	}
	if IsFolderSelected("excluded_dir/file.txt", engine.cfg.SelectedFolders) {
		t.Fatalf("excluded_dir should not be selected")
	}

	// Test per-folder .cloud_data creation and tracking
	subDir := filepath.Join(tmpDir, "docs")
	_ = os.MkdirAll(subDir, 0755)
	filePath := filepath.Join(subDir, "report.pdf")
	_ = os.WriteFile(filePath, []byte("%PDF-1.4 mock"), 0644)

	RecordClientFileUpdate(tmpDir, "docs/report.pdf", "created", "admin", time.Now().Unix(), 14, "mockhash")

	meta := loadClientDirMeta(tmpDir, "docs")
	if _, ok := meta.Files["report.pdf"]; !ok {
		t.Fatalf("expected report.pdf in docs/.cloud_data")
	}

	// Verify RecycleBin path is not rejected
	rBinDir := filepath.Join(tmpDir, "RecycleBin")
	_ = os.MkdirAll(rBinDir, 0755)
	if !IsFolderSelected("RecycleBin", engine.cfg.SelectedFolders) {
		t.Fatalf("RecycleBin should be selected by default")
	}
}
