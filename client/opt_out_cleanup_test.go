package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUncheckedFolderCleanup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "optout_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	subFolder := filepath.Join(tmpDir, "photos")
	_ = os.MkdirAll(subFolder, 0755)
	_ = os.WriteFile(filepath.Join(subFolder, "photo1.jpg"), []byte("photo-data"), 0644)

	// User unchecks photos
	cfg := ClientConfig{
		LocalSyncDir:    tmpDir,
		SelectedFolders: map[string]bool{"photos": false},
	}
	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine failed: %v", err)
	}

	// Add photo to manifest
	engine.manifest["photos/photo1.jpg"] = TrackedFile{RelPath: "photos/photo1.jpg", Size: 10}

	// Run cleanupUncheckedFolders
	engine.cleanupUncheckedFolders()

	// Verify photos directory was removed locally
	if _, statErr := os.Stat(subFolder); !os.IsNotExist(statErr) {
		t.Fatalf("expected photos folder to be erased locally upon unchecking")
	}

	// Verify manifest entries under photos were cleared
	if _, exists := engine.manifest["photos/photo1.jpg"]; exists {
		t.Fatalf("expected photos/photo1.jpg to be removed from engine manifest")
	}
}
