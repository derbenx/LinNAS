package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpecialFoldersClientHandling(t *testing.T) {
	clientDir, err := os.MkdirTemp("", "linnas_special_client_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(clientDir)

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(derBytes)

	// Create a dummy server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/crypto/pubkey":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"public_key": pubB64,
			})
		case "/api/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":       true,
				"session_token": "token123",
			})
		case "/api/cloud/list":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"items": []ServerItem{
					{Name: "docs", RelPath: "docs", IsDir: true},
					{Name: "archive", RelPath: "archive", IsDir: true},
					{Name: "existing.txt", RelPath: "docs/existing.txt", IsDir: false, ModTime: time.Now().Unix(), Size: 10},
				},
				"special_folders": map[string]string{
					"docs":    "add_only",
					"archive": "read_only",
				},
				"timestamp": time.Now().Unix(),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := ClientConfig{
		ServerEndpoint:  ts.URL,
		Username:        "admin",
		LocalSyncDir:    clientDir,
		SyncEnabled:     true,
		SelectedFolders: map[string]bool{},
	}

	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create sync engine: %v", err)
	}
	engine.crypto.serverURL = ts.URL
	engine.crypto.pubKey = &rsaPriv.PublicKey

	// 1. Verify conflict callback on read_only violation
	var conflictReceived SpecialFolderConflict
	engine.onFolderConflict = func(c SpecialFolderConflict) {
		conflictReceived = c
	}

	// Create a new local file in archive (read_only)
	archiveDir := filepath.Join(clientDir, "archive")
	_ = os.MkdirAll(archiveDir, 0755)
	_ = os.WriteFile(filepath.Join(archiveDir, "new_file.txt"), []byte("read only test"), 0644)

	err = engine.PerformSync("")
	if err != nil {
		t.Fatalf("PerformSync failed: %v", err)
	}

	if conflictReceived.Conflict != "read_only_local" || conflictReceived.Folder != "archive" {
		t.Errorf("expected read_only_local conflict for archive, got %+v", conflictReceived)
	}

	// 2. Verify dismiss marks file as ignored in .cloud_data
	SetClientFileIgnored(clientDir, "archive/new_file.txt", true)
	if !IsClientFileIgnored(clientDir, "archive/new_file.txt") {
		t.Errorf("expected archive/new_file.txt to be marked as ignored")
	}

	// Reset conflict receiver
	conflictReceived = SpecialFolderConflict{}

	// Sync again; ignored file should NOT trigger conflict
	err = engine.PerformSync("")
	if err != nil {
		t.Fatalf("PerformSync failed: %v", err)
	}
	if conflictReceived.Conflict != "" {
		t.Errorf("expected no conflict for ignored file, got %+v", conflictReceived)
	}
}
