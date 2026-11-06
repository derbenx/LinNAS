package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyncEnginePerFolderTrackingAndClockOffset(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client_sync_integ_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := ClientConfig{
		LocalSyncDir:    tmpDir,
		SelectedFolders: map[string]bool{"archived": false}, // opt-out "archived"
	}

	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine failed: %v", err)
	}

	// 1. Create a local folder and file
	docsDir := filepath.Join(tmpDir, "docs")
	_ = os.MkdirAll(docsDir, 0755)
	filePath := filepath.Join(docsDir, "resume.txt")
	_ = os.WriteFile(filePath, []byte("My experience"), 0644)

	// 2. Record update using RecordClientFileUpdate
	mTime := time.Now().Unix()
	RecordClientFileUpdate(tmpDir, "docs/resume.txt", "created", "alice", mTime, 13, "hash123")

	// 3. Verify per-folder .cloud_data was generated inside "docs"
	cloudDataFile := filepath.Join(docsDir, ".cloud_data")
	if _, err := os.Stat(cloudDataFile); err != nil {
		t.Fatalf("expected .cloud_data in docs directory: %v", err)
	}

	meta := loadClientDirMeta(tmpDir, "docs")
	if meta.Files["resume.txt"].Size != 13 {
		t.Fatalf("expected file size 13 in .cloud_data, got %d", meta.Files["resume.txt"].Size)
	}

	// 4. Test LoadAllClientMeta loads into manifest
	allMeta := LoadAllClientMeta(tmpDir)
	if tf, ok := allMeta["docs/resume.txt"]; !ok || tf.Size != 13 {
		t.Fatalf("LoadAllClientMeta failed to read docs/resume.txt: %+v", allMeta)
	}

	// 5. Test cleanupUncheckedFolders removes "archived" locally
	archDir := filepath.Join(tmpDir, "archived")
	_ = os.MkdirAll(archDir, 0755)
	_ = os.WriteFile(filepath.Join(archDir, "old.txt"), []byte("old"), 0644)
	engine.manifest["archived/old.txt"] = TrackedFile{RelPath: "archived/old.txt"}

	engine.cleanupUncheckedFolders()
	if _, err := os.Stat(archDir); !os.IsNotExist(err) {
		t.Fatalf("expected opted-out archived directory to be removed")
	}
	if _, ok := engine.manifest["archived/old.txt"]; ok {
		t.Fatalf("expected archived manifest entry to be cleared")
	}

	// 6. Test clock offset normalization functions
	serverTime := int64(1700000100)
	clientTime := int64(1700000000)
	offset := ComputeClockOffset(serverTime, clientTime)
	if offset != 100 {
		t.Fatalf("expected offset 100, got %d", offset)
	}
	localMod := int64(1700000050)
	normMod := NormalizeClientModTime(localMod, offset)
	if normMod != 1700000150 {
		t.Fatalf("expected normalized mod time 1700000150, got %d", normMod)
	}
}
