package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSpecialFoldersPermissions(t *testing.T) {
	tempCloud, err := os.MkdirTemp("", "linnas_cloud_spec_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempCloud)

	cloudConfigMu.Lock()
	cloudConfig = CloudConfig{
		Enabled: true,
		Folder:  tempCloud,
		SpecialFolders: map[string]string{
			"photos":  "add_only",
			"archive": "read_only",
		},
	}
	cloudConfigMu.Unlock()

	// 1. In read_only folder: save should return HTTP 403 Forbidden
	reqBody, _ := json.Marshal(map[string]interface{}{
		"path":        "archive/file.txt",
		"content_b64": base64.StdEncoding.EncodeToString([]byte("hello")),
		"mod_time":    time.Now().Unix(),
		"client_time": time.Now().Unix(),
		"client_id":   "client1",
	})
	req := httptest.NewRequest("POST", "/api/cloud/save", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	handleCloudSave(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for save in read_only folder, got %d", w.Code)
	}

	// 2. In add_only folder: first save should succeed
	reqBody2, _ := json.Marshal(map[string]interface{}{
		"path":        "photos/pic1.jpg",
		"content_b64": base64.StdEncoding.EncodeToString([]byte("picture 1")),
		"mod_time":    time.Now().Unix(),
		"client_time": time.Now().Unix(),
		"client_id":   "client1",
	})
	req2 := httptest.NewRequest("POST", "/api/cloud/save", bytes.NewReader(reqBody2))
	w2 := httptest.NewRecorder()
	handleCloudSave(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for new file save in add_only folder, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. In add_only folder: overwrite attempt should return HTTP 409 Conflict with status "file_exists"
	reqBody3, _ := json.Marshal(map[string]interface{}{
		"path":        "photos/pic1.jpg",
		"content_b64": base64.StdEncoding.EncodeToString([]byte("picture 1 modified")),
		"mod_time":    time.Now().Unix() + 10,
		"client_time": time.Now().Unix(),
		"client_id":   "client1",
	})
	req3 := httptest.NewRequest("POST", "/api/cloud/save", bytes.NewReader(reqBody3))
	w3 := httptest.NewRecorder()
	handleCloudSave(w3, req3)
	if w3.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 for overwrite in add_only folder, got %d", w3.Code)
	}

	var resp3 map[string]interface{}
	_ = json.Unmarshal(w3.Body.Bytes(), &resp3)
	if resp3["status"] != "file_exists" {
		t.Fatalf("expected status 'file_exists' in conflict response, got %+v", resp3)
	}

	// 4. In add_only folder: delete should return HTTP 403 Forbidden
	delBody, _ := json.Marshal(map[string]interface{}{
		"path":        "photos/pic1.jpg",
		"client_time": time.Now().Unix(),
		"client_id":   "client1",
	})
	delReq := httptest.NewRequest("POST", "/api/cloud/delete", bytes.NewReader(delBody))
	delW := httptest.NewRecorder()
	handleCloudDelete(delW, delReq)
	if delW.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for delete in add_only folder, got %d", delW.Code)
	}

	// 5. Verify rule is written to .cloud_data
	photosMeta := loadCloudDirMeta(tempCloud, "photos")
	if photosMeta.Rule != "add_only" {
		t.Fatalf("expected Rule 'add_only' in photos/.cloud_data, got '%s'", photosMeta.Rule)
	}
}
