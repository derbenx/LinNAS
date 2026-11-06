package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPerFolderClientMeta(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client_meta_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	subFolder := filepath.Join(tmpDir, "docs")
	_ = os.MkdirAll(subFolder, 0755)

	// Record an added file
	RecordClientFileUpdate(tmpDir, "docs/test.txt", "created", "alice", 12345678, 42, "abcd1234")

	meta := loadClientDirMeta(tmpDir, "docs")
	if meta.Files["test.txt"].Size != 42 {
		t.Fatalf("expected size 42, got %d", meta.Files["test.txt"].Size)
	}
	if len(meta.Ledger) != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", len(meta.Ledger))
	}

	// LoadAllClientMeta
	manifest := LoadAllClientMeta(tmpDir)
	if tf, ok := manifest["docs/test.txt"]; !ok || tf.ModTime != 12345678 {
		t.Fatalf("failed to load from LoadAllClientMeta: %+v", manifest)
	}

	// Record deletion
	RecordClientFileUpdate(tmpDir, "docs/test.txt", "deleted", "alice", 0, 0, "")
	manifestDel := LoadAllClientMeta(tmpDir)
	if tf, ok := manifestDel["docs/test.txt"]; !ok || !tf.Deleted {
		t.Fatalf("expected deleted file in manifest, got %+v", tf)
	}
}
