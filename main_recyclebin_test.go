package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleCloudDeleteProtectsRecycleBinAndArchivesFolder(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "linnas_cloud_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cloudConfigMu.Lock()
	cloudConfig = CloudConfig{
		Enabled:    true,
		Folder:     tmpDir,
		VolumeUUID: getVolumeUUID(tmpDir),
	}
	cloudConfigMu.Unlock()

	// 1. Attempt to delete root RecycleBin folder -> must be rejected
	reqBody1, _ := json.Marshal(map[string]interface{}{"path": "RecycleBin"})
	req1 := httptest.NewRequest(http.MethodPost, "/api/cloud/delete", bytes.NewReader(reqBody1))
	w1 := httptest.NewRecorder()
	handleCloudDelete(w1, req1)
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request deleting RecycleBin, got %d", w1.Code)
	}

	// 2. Create a folder with contents and delete it -> should be moved to RecycleBin
	targetFolder := filepath.Join(tmpDir, "docs")
	_ = os.MkdirAll(targetFolder, 0755)
	_ = os.WriteFile(filepath.Join(targetFolder, "note.txt"), []byte("important"), 0644)

	reqBody2, _ := json.Marshal(map[string]interface{}{"path": "docs", "client_id": "testclient"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/cloud/delete", bytes.NewReader(reqBody2))
	w2 := httptest.NewRecorder()
	handleCloudDelete(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK deleting folder, got %d (body: %s)", w2.Code, w2.Body.String())
	}

	// Check original folder is gone
	if _, err := os.Stat(targetFolder); !os.IsNotExist(err) {
		t.Fatalf("expected docs folder to be moved from original location")
	}

	// Check RecycleBin has the archived directory and file
	recycleRoot := filepath.Join(tmpDir, "RecycleBin")
	entries, _ := os.ReadDir(recycleRoot)
	foundDir := false
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) > 4 && e.Name()[:4] == "docs" {
			foundDir = true
			nestedFile := filepath.Join(recycleRoot, e.Name(), "note.txt")
			if _, sErr := os.Stat(nestedFile); sErr != nil {
				t.Fatalf("nested file missing in archived directory: %v", sErr)
			}
			// Check restore info metadata
			restoreInfo := filepath.Join(recycleRoot, e.Name()+".restore_info.json")
			if _, rErr := os.Stat(restoreInfo); rErr != nil {
				t.Fatalf("restore info missing: %v", rErr)
			}
			break
		}
	}
	if !foundDir {
		t.Fatalf("archived docs folder not found in RecycleBin")
	}
}
