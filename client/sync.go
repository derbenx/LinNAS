package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type SmartDiskInfo struct {
	Device   string `json:"device"`
	Model    string `json:"model"`
	Capacity string `json:"capacity"`
	Health   string `json:"health"` // "PASSED", "FAILED", "UNKNOWN"
	TempC    int    `json:"temp_c,omitempty"`
	RawInfo  string `json:"raw_info,omitempty"`
}

type SyncEngine struct {
	cfg          ClientConfig
	crypto       *ClientCrypto
	httpClient   *http.Client
	cookieJar    *cookiejar.Jar
	syncLock     sync.Mutex
	isLoggedIn   bool
	stopChan     chan struct{}
	lastActive   time.Time
	statusMsg    string
	statusMu     sync.RWMutex
	onStatus     func(string)
	onSmartAlert func(string)
	manifest     map[string]TrackedFile // relPath -> tracked state
	manifestMu   sync.Mutex
}

type TrackedFile struct {
	RelPath string `json:"rel_path"`
	ModTime int64  `json:"mod_time"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

type ServerItem struct {
	Name    string `json:"name"`
	RelPath string `json:"rel_path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
	SHA256  string `json:"sha256,omitempty"`
}

type ServerDeletedItem struct {
	RelPath   string `json:"rel_path"`
	DeletedAt int64  `json:"deleted_at"`
}

func NewSyncEngine(cfg ClientConfig) (*SyncEngine, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
	serverURL := cfg.ServerEndpoint
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "http://" + serverURL
	}
	engine := &SyncEngine{
		cfg:        cfg,
		crypto:     NewClientCrypto(serverURL),
		httpClient: client,
		cookieJar:  jar,
		stopChan:   make(chan struct{}),
		lastActive: time.Now(),
		statusMsg:  "Idle",
		manifest:   make(map[string]TrackedFile),
	}
	engine.loadManifest()
	return engine, nil
}

func (s *SyncEngine) getManifestPath() string {
	binDir := filepath.Dir(s.cfg.LocalSyncDir)
	if execPath, err := os.Executable(); err == nil {
		binDir = filepath.Dir(execPath)
	}
	return filepath.Join(binDir, "sync_manifest.json")
}

func (s *SyncEngine) loadManifest() {
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	data, err := os.ReadFile(s.getManifestPath())
	if err == nil && len(data) > 0 {
		var list []TrackedFile
		if err := json.Unmarshal(data, &list); err == nil {
			for _, tf := range list {
				s.manifest[tf.RelPath] = tf
			}
		}
	}
}

func (s *SyncEngine) saveManifest() {
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	list := make([]TrackedFile, 0, len(s.manifest))
	for _, tf := range s.manifest {
		list = append(list, tf)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		_ = os.WriteFile(s.getManifestPath(), data, 0644)
	}
}

func (s *SyncEngine) SetStatus(msg string) {
	s.statusMu.Lock()
	s.statusMsg = msg
	s.statusMu.Unlock()
	if s.onStatus != nil {
		s.onStatus(msg)
	}
}

func (s *SyncEngine) GetStatus() string {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.statusMsg
}

func (s *SyncEngine) UpdateConfig(cfg ClientConfig) {
	s.syncLock.Lock()
	defer s.syncLock.Unlock()
	s.cfg = cfg
	serverURL := cfg.ServerEndpoint
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "http://" + serverURL
	}
	s.crypto = NewClientCrypto(serverURL)
	s.isLoggedIn = false
}

func (s *SyncEngine) EnsureAuthenticated(password string) error {
	if s.isLoggedIn {
		return nil
	}

	serverURL := s.crypto.serverURL
	loginURL := serverURL + "/api/login"

	payload := map[string]string{
		"username": s.cfg.Username,
	}

	if password != "" {
		payload["password"] = password
	} else if s.cfg.PasswordHash != "" {
		payload["password_hash"] = s.cfg.PasswordHash
	}

	if s.cfg.SessionToken != "" {
		payload["session_token"] = s.cfg.SessionToken
	}

	encBody, _, err := s.crypto.EncryptPayload(payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt login payload: %w", err)
	}

	resp, err := s.httpClient.Post(loginURL, "application/json", bytes.NewReader(encBody))
	if err != nil {
		return fmt.Errorf("network error during login: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		s.writeClientDebugLog("EnsureAuthenticated failed HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("login failed with HTTP %d", resp.StatusCode)
	}

	var loginData struct {
		Success      bool   `json:"success"`
		SessionToken string `json:"session_token"`
	}
	if json.Unmarshal(bodyBytes, &loginData) == nil && loginData.SessionToken != "" {
		if s.cfg.SessionToken != loginData.SessionToken {
			s.cfg.SessionToken = loginData.SessionToken
			_ = SaveConfig(s.cfg)
		}
	}

	s.isLoggedIn = true
	return nil
}

func (s *SyncEngine) writeClientDebugLog(format string, args ...interface{}) {
	entry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	binDir := filepath.Dir(s.cfg.LocalSyncDir)
	if execPath, err := os.Executable(); err == nil {
		binDir = filepath.Dir(execPath)
	}
	logFile := filepath.Join(binDir, "debug.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.WriteString(entry)
		_ = f.Close()
	}
}

// FetchServerFolderTree retrieves directory items from server for selective sync
func (s *SyncEngine) FetchServerFolderTree() ([]ServerItem, error) {
	serverURL := s.crypto.serverURL
	listURL := serverURL + "/api/cloud/list?recursive=true"

	s.writeClientDebugLog("Fetching server folder tree from %s", listURL)
	resp, err := s.httpClient.Get(listURL)
	if err != nil {
		s.writeClientDebugLog("FetchServerFolderTree HTTP error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.writeClientDebugLog("FetchServerFolderTree ReadAll error: %v", err)
		return nil, err
	}
	s.writeClientDebugLog("FetchServerFolderTree status=%d body_len=%d", resp.StatusCode, len(bodyBytes))

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, fmt.Errorf("server cloud service is currently stopped")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized - please check username and password")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var data struct {
		Success bool         `json:"success"`
		Items   []ServerItem `json:"items"`
		Error   string       `json:"error,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		s.writeClientDebugLog("FetchServerFolderTree JSON unmarshal failed on body '%s': %v", string(bodyBytes), err)
		return nil, fmt.Errorf("failed to parse folder tree JSON: %w (raw response: %s)", err, string(bodyBytes))
	}

	if !data.Success && data.Error != "" {
		return nil, fmt.Errorf("server error: %s", data.Error)
	}

	var dirsOnly []ServerItem
	for _, it := range data.Items {
		if it.IsDir && !strings.HasPrefix(it.RelPath, "RecycleBin") {
			dirsOnly = append(dirsOnly, it)
		}
	}
	return dirsOnly, nil
}

// CheckSMARTDriveHealth queries server SMART health status
func (s *SyncEngine) CheckSMARTDriveHealth() (bool, []SmartDiskInfo, error) {
	serverURL := s.crypto.serverURL
	resp, err := s.httpClient.Get(serverURL + "/api/cloud/smart")
	if err != nil {
		return true, nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Success        bool            `json:"success"`
		OverallHealthy bool            `json:"overall_healthy"`
		Disks          []SmartDiskInfo `json:"disks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return true, nil, err
	}

	if !data.OverallHealthy && s.onSmartAlert != nil {
		s.onSmartAlert("SMART Alert: One or more server storage drives report errors!")
	}

	return data.OverallHealthy, data.Disks, nil
}

// PerformSync runs a single pass of lazy two-way sync with deletion tracking
func (s *SyncEngine) PerformSync(password string) error {
	s.syncLock.Lock()
	defer s.syncLock.Unlock()

	if !s.cfg.SyncEnabled {
		s.SetStatus("Sync Paused")
		return nil
	}

	if s.cfg.LocalSyncDir == "" {
		s.SetStatus("Error: Local sync folder not configured")
		return fmt.Errorf("local sync directory not configured")
	}

	s.SetStatus("Connecting & checking authentication...")
	if err := s.EnsureAuthenticated(password); err != nil {
		s.SetStatus("Authentication failed: " + err.Error())
		return err
	}

	leisurelyDelay := func() {
		if s.cfg.ThrottleKBps > 0 {
			time.Sleep(100 * time.Millisecond)
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}

	_ = os.MkdirAll(s.cfg.LocalSyncDir, 0755)

	s.SetStatus("Fetching server file index...")
	serverURL := s.crypto.serverURL
	listURL := serverURL + "/api/cloud/list?recursive=true"
	s.writeClientDebugLog("PerformSync listURL: %s", listURL)
	resp, err := s.httpClient.Get(listURL)
	if err != nil {
		s.writeClientDebugLog("PerformSync contact error: %v", err)
		s.SetStatus("Failed to contact server: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.writeClientDebugLog("PerformSync ReadAll error: %v", err)
		s.SetStatus("Failed to read server response: " + err.Error())
		return err
	}

	if resp.StatusCode == http.StatusServiceUnavailable {
		s.SetStatus("Cloud Service Offline (Stopped on Server)")
		return fmt.Errorf("server cloud service is stopped")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		s.SetStatus("Unauthorized: Invalid credentials")
		return fmt.Errorf("server returned 401 unauthorized")
	}
	if resp.StatusCode != http.StatusOK {
		s.SetStatus(fmt.Sprintf("Server error %d: %s", resp.StatusCode, string(bodyBytes)))
		return fmt.Errorf("server error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var listData struct {
		Success bool                `json:"success"`
		Items   []ServerItem        `json:"items"`
		Deleted []ServerDeletedItem `json:"deleted"`
		Error   string              `json:"error,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &listData); err != nil {
		s.writeClientDebugLog("PerformSync unmarshal error: %v", err)
		s.SetStatus("Failed to parse server list: " + err.Error())
		return err
	}
	if !listData.Success && listData.Error != "" {
		s.SetStatus("Server error: " + listData.Error)
		return fmt.Errorf("server reported error: %s", listData.Error)
	}

	serverMap := make(map[string]ServerItem)
	for _, it := range listData.Items {
		if strings.HasPrefix(it.RelPath, "RecycleBin") {
			continue
		}
		serverMap[it.RelPath] = it
	}

	serverDeletedMap := make(map[string]int64)
	for _, d := range listData.Deleted {
		serverDeletedMap[d.RelPath] = d.DeletedAt
	}

	// -------------------------------------------------------------
	// STEP A: Detect Local Deletions (present in manifest, now missing locally)
	// -------------------------------------------------------------
	s.manifestMu.Lock()
	for relPath, tf := range s.manifest {
		if tf.Deleted {
			continue
		}
		parentDir := filepath.Dir(relPath)
		if !IsFolderSelected(parentDir, s.cfg.SelectedFolders) {
			continue
		}

		localPath := filepath.Join(s.cfg.LocalSyncDir, filepath.FromSlash(relPath))
		if _, statErr := os.Stat(localPath); os.IsNotExist(statErr) {
			// File existed previously in manifest, but is now gone locally -> User deleted it locally
			s.writeClientDebugLog("Detected local deletion: %s. Propagating delete to server.", relPath)
			s.SetStatus(fmt.Sprintf("Syncing deletion of %s...", filepath.Base(relPath)))
			if delErr := s.deleteRemoteFile(relPath); delErr == nil {
				tf.Deleted = true
				s.manifest[relPath] = tf
			}
		}
	}
	s.manifestMu.Unlock()
	s.saveManifest()

	// -------------------------------------------------------------
	// STEP B: Process Server Deletions (server reports deleted or absent from server)
	// -------------------------------------------------------------
	for delRel, delTime := range serverDeletedMap {
		localPath := filepath.Join(s.cfg.LocalSyncDir, filepath.FromSlash(delRel))
		if lInfo, lErr := os.Stat(localPath); lErr == nil {
			// If local file has not been modified AFTER the deletion timestamp, safely move to local RecycleBin
			if lInfo.ModTime().Unix() <= delTime {
				s.writeClientDebugLog("Server deleted file: %s (deletedAt=%d). Moving local copy to RecycleBin.", delRel, delTime)
				s.SetStatus(fmt.Sprintf("Archiving deleted file %s...", filepath.Base(delRel)))
				s.moveLocalToRecycle(localPath, delRel, lInfo)
				s.manifestMu.Lock()
				s.manifest[delRel] = TrackedFile{RelPath: delRel, Deleted: true}
				s.manifestMu.Unlock()
			}
		}
	}

	// -------------------------------------------------------------
	// STEP C: Download Server Files to Local (if server version is newer)
	// -------------------------------------------------------------
	for _, sItem := range listData.Items {
		if sItem.IsDir || strings.HasPrefix(sItem.RelPath, "RecycleBin") {
			continue
		}

		parentDir := filepath.Dir(sItem.RelPath)
		if !IsFolderSelected(parentDir, s.cfg.SelectedFolders) {
			continue
		}

		s.manifestMu.Lock()
		tracked, wasTracked := s.manifest[sItem.RelPath]
		s.manifestMu.Unlock()

		localPath := filepath.Join(s.cfg.LocalSyncDir, filepath.FromSlash(sItem.RelPath))
		localInfo, err := os.Stat(localPath)

		shouldDownload := false
		if os.IsNotExist(err) {
			// If user deleted it locally, do not resurrect unless server has a NEWER version than when tracked
			if wasTracked && tracked.Deleted {
				if sItem.ModTime > tracked.ModTime {
					// Server has updated the file since client deletion
					shouldDownload = true
				}
			} else {
				// New file on server
				shouldDownload = true
			}
		} else if err == nil {
			// Compare modification times: download only if server timestamp is newer
			if sItem.ModTime > localInfo.ModTime().Unix() {
				shouldDownload = true
			}
		}

		if shouldDownload {
			s.SetStatus(fmt.Sprintf("Downloading %s...", sItem.Name))
			if err := s.downloadFile(sItem.RelPath, localPath, sItem.ModTime); err == nil {
				s.manifestMu.Lock()
				s.manifest[sItem.RelPath] = TrackedFile{
					RelPath: sItem.RelPath,
					ModTime: sItem.ModTime,
					Size:    sItem.Size,
					SHA256:  sItem.SHA256,
					Deleted: false,
				}
				s.manifestMu.Unlock()
			} else {
				// Failed download is not added to manifest, so it remains queued to retry on next sync cycle
				s.writeClientDebugLog("Download failed for %s: %v (will retry on next sync interval)", sItem.RelPath, err)
			}
			leisurelyDelay()
		}
	}

	// -------------------------------------------------------------
	// STEP D: Scan Local Files and Upload to Server
	// -------------------------------------------------------------
	s.SetStatus("Scanning local changes...")
	err = filepath.Walk(s.cfg.LocalSyncDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.cfg.LocalSyncDir, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if strings.HasPrefix(relSlash, ".cloud_meta") || strings.HasPrefix(relSlash, "RecycleBin") {
			return nil
		}

		parentDir := filepath.Dir(relSlash)
		if !IsFolderSelected(parentDir, s.cfg.SelectedFolders) {
			return nil
		}

		sItem, existsOnServer := serverMap[relSlash]
		localMod := info.ModTime().Unix()

		shouldUpload := false
		if !existsOnServer {
			// If server recorded this as deleted, only upload if local file was modified AFTER the deletion
			if delTime, isServerDeleted := serverDeletedMap[relSlash]; isServerDeleted {
				if localMod > delTime {
					shouldUpload = true
				}
			} else {
				shouldUpload = true
			}
		} else if localMod > sItem.ModTime {
			shouldUpload = true
		}

		if shouldUpload {
			s.SetStatus(fmt.Sprintf("Uploading %s...", info.Name()))
			if err := s.uploadFile(path, relSlash, localMod); err == nil {
				s.manifestMu.Lock()
				s.manifest[relSlash] = TrackedFile{
					RelPath: relSlash,
					ModTime: localMod,
					Size:    info.Size(),
					Deleted: false,
				}
				s.manifestMu.Unlock()
			} else {
				// Failed upload (e.g. server busy/file locked) is not marked in manifest, staying queued for next interval retry
				s.writeClientDebugLog("Upload failed for %s: %v (will retry on next sync interval)", relSlash, err)
			}
			leisurelyDelay()
		} else {
			// Update manifest for in-sync local file
			s.manifestMu.Lock()
			s.manifest[relSlash] = TrackedFile{
				RelPath: relSlash,
				ModTime: localMod,
				Size:    info.Size(),
				Deleted: false,
			}
			s.manifestMu.Unlock()
		}

		return nil
	})

	s.saveManifest()
	s.SetStatus("Up to Date")
	return err
}

func (s *SyncEngine) moveLocalToRecycle(localPath, relPath string, info os.FileInfo) {
	dateTag := time.Now().Format("2006-01-02_150405")
	baseName := filepath.Base(relPath)
	relDir := filepath.Dir(relPath)
	if relDir == "." {
		relDir = ""
	}
	recycleDir := filepath.Join(s.cfg.LocalSyncDir, "RecycleBin", relDir)
	_ = os.MkdirAll(recycleDir, 0755)
	destPath := filepath.Join(recycleDir, fmt.Sprintf("%s.deleted.%s", baseName, dateTag))

	// Move file into RecycleBin
	if err := os.Rename(localPath, destPath); err != nil {
		if data, rErr := os.ReadFile(localPath); rErr == nil {
			_ = os.WriteFile(destPath, data, 0644)
			_ = os.Remove(localPath)
		}
	}
	s.writeClientDebugLog("Moved local deleted file %s to RecycleBin at %s", relPath, destPath)
}

func (s *SyncEngine) deleteRemoteFile(relPath string) error {
	delReq := map[string]string{"path": relPath}
	encBody, _, err := s.crypto.EncryptPayload(delReq)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Post(s.crypto.serverURL+"/api/cloud/delete", "application/json", bytes.NewReader(encBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("delete failed with HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *SyncEngine) downloadFile(relPath, localDest string, modTime int64) error {
	loadReq := map[string]string{"path": relPath}
	encBody, aesKey, err := s.crypto.EncryptPayload(loadReq)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Post(s.crypto.serverURL+"/api/cloud/load", "application/json", bytes.NewReader(encBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	decrypted, err := s.crypto.DecryptResponse(aesKey, respBody)
	if err != nil {
		return err
	}

	var loadData struct {
		Success    bool   `json:"success"`
		ContentB64 string `json:"content_b64"`
	}
	if err := json.Unmarshal(decrypted, &loadData); err != nil || !loadData.Success {
		return fmt.Errorf("failed to decode server file load")
	}

	fileBytes, err := base64.StdEncoding.DecodeString(loadData.ContentB64)
	if err != nil {
		return err
	}

	_ = os.MkdirAll(filepath.Dir(localDest), 0755)
	if err := os.WriteFile(localDest, fileBytes, 0644); err != nil {
		return err
	}

	if modTime > 0 {
		mTime := time.Unix(modTime, 0)
		_ = os.Chtimes(localDest, mTime, mTime)
	}

	return nil
}

func (s *SyncEngine) uploadFile(localPath, relPath string, modTime int64) error {
	contentBytes, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	saveReq := map[string]interface{}{
		"path":        relPath,
		"content_b64": base64.StdEncoding.EncodeToString(contentBytes),
		"mod_time":    modTime,
	}

	encBody, aesKey, err := s.crypto.EncryptPayload(saveReq)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Post(s.crypto.serverURL+"/api/cloud/save", "application/json", bytes.NewReader(encBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	decrypted, _ := s.crypto.DecryptResponse(aesKey, respBody)

	// If conflict_older_version was returned (409), server newer file is in payload
	if resp.StatusCode == http.StatusConflict {
		var conflictResp struct {
			Status        string `json:"status"`
			ServerModTime int64  `json:"server_mod_time"`
			ServerFileB64 string `json:"server_file_b64"`
		}
		if json.Unmarshal(decrypted, &conflictResp) == nil && conflictResp.ServerFileB64 != "" {
			if sBytes, bErr := base64.StdEncoding.DecodeString(conflictResp.ServerFileB64); bErr == nil {
				_ = os.WriteFile(localPath, sBytes, 0644)
				if conflictResp.ServerModTime > 0 {
					tVal := time.Unix(conflictResp.ServerModTime, 0)
					_ = os.Chtimes(localPath, tVal, tVal)
				}
			}
		}
	}

	return nil
}
