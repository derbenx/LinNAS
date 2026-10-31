package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper to encrypt payload like the client crypto.js
func testEncryptPayload(pubKey *rsa.PublicKey, payload interface{}) (string, []byte, error) {
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", nil, err
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", nil, err
	}

	encAesKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return "", nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, jsonBytes, nil)
	combined := append(nonce, ciphertext...)

	randomBytes := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, randomBytes)

	encPayload := EncryptedPayload{
		EncryptedKey:  base64.StdEncoding.EncodeToString(encAesKey),
		EncryptedData: base64.StdEncoding.EncodeToString(combined),
		Nonce:         fmt.Sprintf("nonce-%d-%s", time.Now().UnixNano(), hex.EncodeToString(randomBytes)),
		Timestamp:     time.Now().Unix(),
	}

	bodyBytes, err := json.Marshal(encPayload)
	return string(bodyBytes), aesKey, err
}

func testDecryptResponse(aesKey []byte, respBytes []byte) ([]byte, error) {
	var resp struct {
		Encrypted     bool   `json:"encrypted"`
		EncryptedData string `json:"encrypted_data"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil || !resp.Encrypted {
		return respBytes, nil
	}

	dataBytes, err := base64.StdEncoding.DecodeString(resp.EncryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce := dataBytes[:nonceSize]
	ciphertext := dataBytes[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func TestLocalCloudServiceLifecycleAndStop(t *testing.T) {
	initRSAKeys()
	tmpCloudDir := t.TempDir()

	// Initial state: Stopped
	_ = saveCloudConfig(CloudConfig{
		Enabled: false,
		Folder:  tmpCloudDir,
	})

	// Try listing when stopped -> should return 503
	req := httptest.NewRequest(http.MethodGet, "/api/cloud/list", nil)
	w := httptest.NewRecorder()
	handleCloudList(w, req)
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 when cloud is stopped, got %d", w.Result().StatusCode)
	}

	// Try saving when stopped -> should return 503
	saveBody := `{"path":"test.txt","content_text":"hello"}`
	reqSave := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveBody))
	wSave := httptest.NewRecorder()
	handleCloudSave(wSave, reqSave)
	if wSave.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503 when saving while stopped, got %d", wSave.Result().StatusCode)
	}

	// Start the service via /api/cloud/config
	cfgBody := fmt.Sprintf(`{"folder":%q,"enabled":true}`, tmpCloudDir)
	reqCfg := httptest.NewRequest(http.MethodPost, "/api/cloud/config", strings.NewReader(cfgBody))
	wCfg := httptest.NewRecorder()
	handleCloudConfig(wCfg, reqCfg)
	if wCfg.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on config start, got %d: %s", wCfg.Result().StatusCode, wCfg.Body.String())
	}

	// Status should now be enabled
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/cloud/status", nil)
	wStatus := httptest.NewRecorder()
	handleCloudStatus(wStatus, reqStatus)
	var statusResp map[string]interface{}
	_ = json.NewDecoder(wStatus.Body).Decode(&statusResp)
	if statusResp["enabled"] != true {
		t.Fatalf("Expected cloud status enabled true")
	}
}

func TestLocalCloudPathTraversalProtection(t *testing.T) {
	initRSAKeys()
	tmpCloudDir := t.TempDir()
	_ = saveCloudConfig(CloudConfig{
		Enabled:    true,
		Folder:     tmpCloudDir,
		VolumeUUID: getVolumeUUID(tmpCloudDir),
	})

	// Test ../ path traversal on save
	traversalPaths := []string{
		"../../escape.txt",
		"/etc/passwd",
		"sub/../../../root.txt",
		".cloud_meta/secret.txt",
	}

	for _, p := range traversalPaths {
		saveReq := fmt.Sprintf(`{"path":%q,"content_text":"malicious"}`, p)
		req := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveReq))
		w := httptest.NewRecorder()
		handleCloudSave(w, req)
		if w.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for path %q, got status %d", p, w.Result().StatusCode)
		}
	}

	// Test path traversal on list
	for _, p := range []string{"../../", "/etc", ".cloud_meta"} {
		req := httptest.NewRequest(http.MethodGet, "/api/cloud/list?path="+p, nil)
		w := httptest.NewRecorder()
		handleCloudList(w, req)
		if w.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for list traversal %q, got status %d", p, w.Result().StatusCode)
		}
	}
}

func TestLocalCloudFileSaveLoadDeleteAndRecycleBin(t *testing.T) {
	initRSAKeys()
	tmpCloudDir := t.TempDir()
	_ = saveCloudConfig(CloudConfig{
		Enabled:    true,
		Folder:     tmpCloudDir,
		VolumeUUID: getVolumeUUID(tmpCloudDir),
	})

	// 1. Save new file
	fileContent := "Cloud sync test payload content"
	nowTs := time.Now().Unix()
	saveReq := fmt.Sprintf(`{"path":"documents/notes.txt","content_text":%q,"mod_time":%d}`, fileContent, nowTs)
	reqSave := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveReq))
	wSave := httptest.NewRecorder()
	handleCloudSave(wSave, reqSave)

	if wSave.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on save, got %d: %s", wSave.Result().StatusCode, wSave.Body.String())
	}

	// Verify file was written to disk
	savedDiskPath := filepath.Join(tmpCloudDir, "documents", "notes.txt")
	diskData, err := os.ReadFile(savedDiskPath)
	if err != nil || string(diskData) != fileContent {
		t.Fatalf("File content mismatch on disk: err=%v, content=%s", err, string(diskData))
	}

	// Verify metadata JSON exists
	mac := getPrimaryMAC()
	metaPath := filepath.Join(tmpCloudDir, ".cloud_meta", "documents", fmt.Sprintf(".cloud-%s.json", mac))
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Fatalf("Expected metadata JSON file at %s, but does not exist", metaPath)
	}

	// 2. Overwrite file with newer version -> should copy old version to RecycleBin
	newContent := "Updated version 2 content"
	newerTs := nowTs + 100
	saveReq2 := fmt.Sprintf(`{"path":"documents/notes.txt","content_text":%q,"mod_time":%d}`, newContent, newerTs)
	reqSave2 := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveReq2))
	wSave2 := httptest.NewRecorder()
	handleCloudSave(wSave2, reqSave2)

	if wSave2.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on overwrite, got %d: %s", wSave2.Result().StatusCode, wSave2.Body.String())
	}

	// Check RecycleBin has the overwritten version
	recycleDir := filepath.Join(tmpCloudDir, "RecycleBin", "documents")
	entries, err := os.ReadDir(recycleDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("Expected backup in RecycleBin, found none: %v", err)
	}

	// 3. Attempt to save an OLDER version -> should conflict (409) and save incoming to RecycleBin
	olderTs := nowTs - 500
	olderContent := "Ancient version"
	saveReqOlder := fmt.Sprintf(`{"path":"documents/notes.txt","content_text":%q,"mod_time":%d}`, olderContent, olderTs)
	reqOlder := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveReqOlder))
	wOlder := httptest.NewRecorder()
	handleCloudSave(wOlder, reqOlder)

	if wOlder.Result().StatusCode != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict for older file upload, got %d: %s", wOlder.Result().StatusCode, wOlder.Body.String())
	}

	// 4. Load the file
	reqLoad := httptest.NewRequest(http.MethodGet, "/api/cloud/load?path=documents/notes.txt", nil)
	wLoad := httptest.NewRecorder()
	handleCloudLoad(wLoad, reqLoad)
	if wLoad.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on load, got %d: %s", wLoad.Result().StatusCode, wLoad.Body.String())
	}
	var loadResp struct {
		ContentB64 string `json:"content_b64"`
	}
	_ = json.NewDecoder(wLoad.Body).Decode(&loadResp)
	decoded, _ := base64.StdEncoding.DecodeString(loadResp.ContentB64)
	if string(decoded) != newContent {
		t.Fatalf("Expected loaded content %q, got %q", newContent, string(decoded))
	}

	// 5. Delete the file -> should move to RecycleBin
	reqDel := httptest.NewRequest(http.MethodPost, "/api/cloud/delete", strings.NewReader(`{"path":"documents/notes.txt"}`))
	wDel := httptest.NewRecorder()
	handleCloudDelete(wDel, reqDel)
	if wDel.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on delete, got %d: %s", wDel.Result().StatusCode, wDel.Body.String())
	}

	if _, err := os.Stat(savedDiskPath); !os.IsNotExist(err) {
		t.Fatalf("Expected original file to be removed after delete")
	}
}

func TestLocalCloudConcurrentFileLocking(t *testing.T) {
	initRSAKeys()
	tmpCloudDir := t.TempDir()
	_ = saveCloudConfig(CloudConfig{
		Enabled:    true,
		Folder:     tmpCloudDir,
		VolumeUUID: getVolumeUUID(tmpCloudDir),
	})

	filePath := "busyfile.dat"
	// Manually acquire lock as if another thread is writing
	if !acquireCloudFileLock(filePath) {
		t.Fatalf("Failed to acquire initial lock")
	}

	// Try saving to the locked file concurrently
	saveReq := fmt.Sprintf(`{"path":%q,"content_text":"hello"}`, filePath)
	reqSave := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveReq))
	wSave := httptest.NewRecorder()
	handleCloudSave(wSave, reqSave)

	if wSave.Result().StatusCode != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict/busy for locked file, got %d: %s", wSave.Result().StatusCode, wSave.Body.String())
	}

	// Release lock
	releaseCloudFileLock(filePath)

	// Now saving should succeed
	reqSave2 := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(saveReq))
	wSave2 := httptest.NewRecorder()
	handleCloudSave(wSave2, reqSave2)
	if wSave2.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on save after lock release, got %d: %s", wSave2.Result().StatusCode, wSave2.Body.String())
	}
}

func TestLocalCloudEncryptedPayloadRoundtrip(t *testing.T) {
	initRSAKeys()
	tmpCloudDir := t.TempDir()
	_ = saveCloudConfig(CloudConfig{
		Enabled:    true,
		Folder:     tmpCloudDir,
		VolumeUUID: getVolumeUUID(tmpCloudDir),
	})

	// Encrypt save request
	rawPayload := map[string]interface{}{
		"path":         "secret/top_secret.txt",
		"content_text": "Classified local cloud data",
		"mod_time":     time.Now().Unix(),
	}

	encBody, aesKey, err := testEncryptPayload(&rsaPrivateKey.PublicKey, rawPayload)
	if err != nil {
		t.Fatalf("Failed to encrypt test payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/cloud/save", strings.NewReader(encBody))
	w := httptest.NewRecorder()
	handleCloudSave(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on encrypted save, got %d: %s", w.Result().StatusCode, w.Body.String())
	}

	// Server response should be encrypted with aesKey
	decryptedResp, err := testDecryptResponse(aesKey, w.Body.Bytes())
	if err != nil {
		t.Fatalf("Failed to decrypt server response: %v", err)
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(decryptedResp, &respMap); err != nil {
		t.Fatalf("Failed to decode decrypted JSON: %v, raw: %s", err, string(decryptedResp))
	}
	if respMap["success"] != true {
		t.Fatalf("Expected decrypted response success true, got: %v", respMap)
	}

	// Now load the file using encrypted request
	loadReqPayload := map[string]interface{}{
		"path": "secret/top_secret.txt",
	}
	encLoadBody, loadAesKey, err := testEncryptPayload(&rsaPrivateKey.PublicKey, loadReqPayload)
	if err != nil {
		t.Fatalf("Failed to encrypt load payload: %v", err)
	}

	reqLoad := httptest.NewRequest(http.MethodPost, "/api/cloud/load", strings.NewReader(encLoadBody))
	wLoad := httptest.NewRecorder()
	handleCloudLoad(wLoad, reqLoad)

	if wLoad.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 on encrypted load, got %d", wLoad.Result().StatusCode)
	}

	decryptedLoadResp, err := testDecryptResponse(loadAesKey, wLoad.Body.Bytes())
	if err != nil {
		t.Fatalf("Failed to decrypt load response: %v", err)
	}

	var loadData struct {
		Success    bool   `json:"success"`
		ContentB64 string `json:"content_b64"`
	}
	if err := json.Unmarshal(decryptedLoadResp, &loadData); err != nil {
		t.Fatalf("Failed to unmarshal load response: %v", err)
	}
	decodedContent, _ := base64.StdEncoding.DecodeString(loadData.ContentB64)
	if string(decodedContent) != "Classified local cloud data" {
		t.Fatalf("Decrypted content mismatch: %q", string(decodedContent))
	}
}
