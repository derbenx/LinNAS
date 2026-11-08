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
	Device        string `json:"device"`
	PartLabel     string `json:"part_label,omitempty"`
	FirstPartName string `json:"first_part_name,omitempty"`
	Model         string `json:"model"`
	Serial        string `json:"serial,omitempty"`
	Capacity      string `json:"capacity"`
	Health        string `json:"health"` // "PASSED", "FAILED", "UNKNOWN"
	TempC         int    `json:"temp_c,omitempty"`
	HostName      string `json:"hostname,omitempty"`
	IP            string `json:"ip,omitempty"`
	RawInfo       string `json:"raw_info,omitempty"`
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
	onSmartAlert func(alertMsg string, isTest bool)
	smartMuteUntil time.Time
	smartMuteMu    sync.RWMutex
	manifest     map[string]TrackedFile // relPath -> tracked state
	manifestMu   sync.Mutex
}

type TrackedFile struct {
	RelPath   string `json:"rel_path"`
	ModTime   int64  `json:"mod_time"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
	DeletedAt int64  `json:"deleted_at,omitempty"`
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

type ServerLedgerEntry struct {
	RelPath   string `json:"rel_path"`
	Action    string `json:"action"` // "created", "modified", "deleted", "restored"
	Timestamp int64  `json:"timestamp"`
	ModTime   int64  `json:"mod_time"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
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

const clientCloudDataHeader = "# DO NOT DELETE - this file is used by LinNAS Cloud #\n"

func (s *SyncEngine) getManifestPath() string {
	// Store in .cloud_data at root of the local sync directory with "# DO NOT DELETE..." header
	if s.cfg.LocalSyncDir != "" {
		return filepath.Join(s.cfg.LocalSyncDir, ".cloud_data")
	}
	binDir := filepath.Dir(s.cfg.LocalSyncDir)
	if execPath, err := os.Executable(); err == nil {
		binDir = filepath.Dir(execPath)
	}
	return filepath.Join(binDir, "sync_manifest.json")
}

func (s *SyncEngine) loadManifest() {
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()

	// 1. Load from all per-folder .cloud_data files in LocalSyncDir
	if s.cfg.LocalSyncDir != "" {
		folderMeta := LoadAllClientMeta(s.cfg.LocalSyncDir)
		for k, v := range folderMeta {
			s.manifest[k] = v
		}
	}

	// 2. Also load/merge root .cloud_data or legacy sync_manifest.json
	p := s.getManifestPath()
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		if s.cfg.LocalSyncDir != "" {
			data, _ = os.ReadFile(filepath.Join(s.cfg.LocalSyncDir, ".cloud_meta", ".client_meta.json"))
		}
		if len(data) == 0 {
			if execPath, err2 := os.Executable(); err2 == nil {
				data, _ = os.ReadFile(filepath.Join(filepath.Dir(execPath), "sync_manifest.json"))
			}
		}
	}
	if len(data) > 0 {
		raw := string(data)
		if strings.HasPrefix(raw, clientCloudDataHeader) {
			raw = strings.TrimPrefix(raw, clientCloudDataHeader)
		}
		var list []TrackedFile
		if err := json.Unmarshal([]byte(raw), &list); err == nil {
			for _, tf := range list {
				if _, exists := s.manifest[tf.RelPath]; !exists {
					s.manifest[tf.RelPath] = tf
				}
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
		contentWithHeader := append([]byte(clientCloudDataHeader), data...)
		_ = os.WriteFile(s.getManifestPath(), contentWithHeader, 0644)
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

// MuteSmartAlerts mutes popup alerts for a given duration
func (s *SyncEngine) MuteSmartAlerts(duration time.Duration) {
	s.smartMuteMu.Lock()
	defer s.smartMuteMu.Unlock()
	s.smartMuteUntil = time.Now().Add(duration)
}

// IsSmartAlertMuted returns whether alerts are currently suppressed
func (s *SyncEngine) IsSmartAlertMuted() bool {
	s.smartMuteMu.RLock()
	defer s.smartMuteMu.RUnlock()
	return time.Now().Before(s.smartMuteUntil)
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

func (s *SyncEngine) InvalidateSession() {
	s.isLoggedIn = false
	if s.cfg.SessionToken != "" {
		s.cfg.SessionToken = ""
		_ = SaveConfig(s.cfg)
	}
	if jar, err := cookiejar.New(nil); err == nil {
		s.cookieJar = jar
		s.httpClient.Jar = jar
	}
}

func (s *SyncEngine) EnsureAuthenticated(password string) error {
	return s.ensureAuthenticatedInternal(password, true)
}

func (s *SyncEngine) ensureAuthenticatedInternal(password string, allowRetry bool) error {
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

		// If server returned 400 (decryption failed due to server restart changing RSA keys),
		// or 401 (invalid credentials / session token expired), invalidate pubkey & session and retry once.
		if allowRetry && (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) {
			s.crypto.InvalidatePublicKey()
			s.InvalidateSession()
			return s.ensureAuthenticatedInternal(password, false)
		}

		// If authentication failed with a stale session token (e.g. server wiped memory),
		// clear the session token and retry immediately using stored password or password_hash.
		if s.cfg.SessionToken != "" && (password != "" || s.cfg.PasswordHash != "") {
			s.InvalidateSession()
			return s.ensureAuthenticatedInternal(password, false)
		}
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
	if !s.cfg.LogToFile {
		return
	}

	entry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	binDir := filepath.Dir(s.cfg.LocalSyncDir)
	if execPath, err := os.Executable(); err == nil {
		binDir = filepath.Dir(execPath)
	}
	logFile := filepath.Join(binDir, "debug.log")

	// Limit log file to 1MB; rotate down to 500KB when exceeded
	const maxLogSize = 1024 * 1024    // 1MB
	const trimmedLogSize = 500 * 1024 // 500KB
	if fi, err := os.Stat(logFile); err == nil && fi.Size() > maxLogSize {
		data, rErr := os.ReadFile(logFile)
		if rErr == nil && len(data) > trimmedLogSize {
			_ = os.WriteFile(logFile, data[len(data)-trimmedLogSize:], 0644)
		}
	}

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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		s.writeClientDebugLog("FetchServerFolderTree got HTTP %d, re-authenticating...", resp.StatusCode)
		s.crypto.InvalidatePublicKey()
		s.InvalidateSession()
		if aErr := s.EnsureAuthenticated(""); aErr == nil {
			// Retry once after re-authenticating
			retryResp, rErr := s.httpClient.Get(listURL)
			if rErr == nil {
				defer retryResp.Body.Close()
				if retryBytes, rbErr := io.ReadAll(retryResp.Body); rbErr == nil && retryResp.StatusCode == http.StatusOK {
					resp = retryResp
					bodyBytes = retryBytes
				}
			}
		}
	}

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
		if it.IsDir {
			dirsOnly = append(dirsOnly, it)
		}
	}
	return dirsOnly, nil
}

type ClientFailureReport struct {
	Client  string          `json:"client"`
	Failing []SmartDiskInfo `json:"failing"`
}

type ClientDiskSummary struct {
	Client string          `json:"client"`
	Disks  []SmartDiskInfo `json:"disks"`
}

// ReportLocalSMARTHealthToServer reports local disk statuses to the server
func (s *SyncEngine) ReportLocalSMARTHealthToServer(disks []SmartDiskInfo) {
	s.reportLocalSMARTHealthToServerInternal(disks, true)
}

func (s *SyncEngine) reportLocalSMARTHealthToServerInternal(disks []SmartDiskInfo, allowRetry bool) {
	reqData := map[string]interface{}{
		"client_id": s.cfg.Username,
		"disks":     disks,
	}
	encBody, _, err := s.crypto.EncryptPayload(reqData)
	if err != nil {
		return
	}
	resp, err := s.httpClient.Post(s.crypto.serverURL+"/api/cloud/smart/report", "application/json", bytes.NewReader(encBody))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if allowRetry && (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) {
		s.crypto.InvalidatePublicKey()
		s.InvalidateSession()
		if aErr := s.EnsureAuthenticated(""); aErr == nil {
			s.reportLocalSMARTHealthToServerInternal(disks, false)
		}
	}
}

// CheckSMARTDriveHealth queries server SMART health status and reports local disk health
func (s *SyncEngine) CheckSMARTDriveHealth() (bool, bool, []SmartDiskInfo, []ClientFailureReport, error) {
	// Helper to format drive failure line
	formatDriveDetail := func(source string, d SmartDiskInfo) string {
		var parts []string
		parts = append(parts, fmt.Sprintf("Source: %s", source))
		if d.HostName != "" {
			parts = append(parts, fmt.Sprintf("Host: %s", d.HostName))
		}
		if d.IP != "" {
			parts = append(parts, fmt.Sprintf("IP: %s", d.IP))
		}
		parts = append(parts, fmt.Sprintf("Drive: %s", d.Device))
		if d.PartLabel != "" {
			parts = append(parts, fmt.Sprintf("Partition: %s", d.PartLabel))
		}
		if d.Model != "" {
			parts = append(parts, fmt.Sprintf("Model: %s", d.Model))
		}
		if d.Serial != "" {
			parts = append(parts, fmt.Sprintf("Serial: %s", d.Serial))
		}
		if d.TempC > 0 {
			parts = append(parts, fmt.Sprintf("Temp: %d°C", d.TempC))
		}
		parts = append(parts, fmt.Sprintf("Health: %s", d.Health))
		return strings.Join(parts, " | ")
	}

	// 1. Evaluate local disks and synchronously report to server so server has latest status
	localHealthy, localDisks, _ := CheckLocalSMARTHealth()
	s.ReportLocalSMARTHealthToServer(localDisks)

	// Collect local failure details if any
	var localFailDetails []string
	if !localHealthy {
		for _, ld := range localDisks {
			if ld.Health == "FAILED" {
				localFailDetails = append(localFailDetails, formatDriveDetail("This PC (Local)", ld))
			}
		}
	}

	serverURL := s.crypto.serverURL
	resp, err := s.httpClient.Get(serverURL + "/api/cloud/smart")
	if err != nil {
		// Network problems / server offline: ignore network error, but if local disk is failing, trigger alert
		if len(localFailDetails) > 0 && s.onSmartAlert != nil && !s.IsSmartAlertMuted() {
			detailMsg := "• " + strings.Join(localFailDetails, "\n\n• ")
			s.onSmartAlert(detailMsg, false)
		}
		return localHealthy, false, nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		s.writeClientDebugLog("CheckSMARTDriveHealth got HTTP %d, re-authenticating...", resp.StatusCode)
		s.crypto.InvalidatePublicKey()
		s.InvalidateSession()
		if aErr := s.EnsureAuthenticated(""); aErr == nil {
			// Retry after re-authenticating
			retryResp, rErr := s.httpClient.Get(serverURL + "/api/cloud/smart")
			if rErr == nil {
				resp.Body.Close()
				resp = retryResp
				defer resp.Body.Close()
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		// HTTP error: ignore, but if local disk is failing, trigger alert
		if len(localFailDetails) > 0 && s.onSmartAlert != nil && !s.IsSmartAlertMuted() {
			detailMsg := "• " + strings.Join(localFailDetails, "\n\n• ")
			s.onSmartAlert(detailMsg, false)
		}
		return localHealthy, false, nil, nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var data struct {
		Success        bool                  `json:"success"`
		OverallHealthy bool                  `json:"overall_healthy"`
		IsTest         bool                  `json:"is_test"`
		TestMessage    string                `json:"test_message"`
		Disks          []SmartDiskInfo       `json:"disks"`
		ClientReports  []ClientFailureReport `json:"client_reports"`
		ClientDrives   []ClientDiskSummary   `json:"client_drives"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		// Bad/malformed JSON: ignore, but if local disk is failing, trigger alert
		if len(localFailDetails) > 0 && s.onSmartAlert != nil && !s.IsSmartAlertMuted() {
			detailMsg := "• " + strings.Join(localFailDetails, "\n\n• ")
			s.onSmartAlert(detailMsg, false)
		}
		return localHealthy, false, nil, nil, err
	}

	// Trigger alert if server specifically reported errors/test, client failures, OR local failure exists
	serverHasError := data.Success && (!data.OverallHealthy || data.IsTest || len(data.ClientReports) > 0)
	if (serverHasError || len(localFailDetails) > 0) && s.onSmartAlert != nil {
		if !s.IsSmartAlertMuted() {
			var failDetails []string
			// Add server-reported drive failures
			for _, d := range data.Disks {
				if d.Health == "FAILED" {
					failDetails = append(failDetails, formatDriveDetail("Server", d))
				}
			}
			// Add server-reported remote client failure reports
			for _, cr := range data.ClientReports {
				for _, fd := range cr.Failing {
					if fd.IP == "" && strings.Contains(cr.Client, "(") {
						start := strings.LastIndex(cr.Client, "(")
						end := strings.LastIndex(cr.Client, ")")
						if start != -1 && end != -1 && end > start {
							fd.IP = cr.Client[start+1 : end]
						}
					}
					failDetails = append(failDetails, formatDriveDetail(fmt.Sprintf("Client %s", cr.Client), fd))
				}
			}
			// Add local failures
			failDetails = append(failDetails, localFailDetails...)

			detailMsg := strings.Join(failDetails, "\n\n• ")
			if detailMsg != "" {
				detailMsg = "• " + detailMsg
			} else if data.IsTest {
				detailMsg = "• Simulated SMART hardware failure test active on server"
			}
			s.onSmartAlert(detailMsg, data.IsTest)
		}
	}

	// If client_drives was sent and client_reports has missing healthy drives or temp info, merge them
	if len(data.ClientDrives) > 0 {
		existingClients := make(map[string]bool)
		for _, cr := range data.ClientReports {
			existingClients[cr.Client] = true
		}
		for _, cd := range data.ClientDrives {
			if !existingClients[cd.Client] {
				// Include non-failing client report summary so remote drives and their temperatures are visible
				data.ClientReports = append(data.ClientReports, ClientFailureReport{
					Client:  cd.Client,
					Failing: cd.Disks,
				})
			}
		}
	}

	return data.OverallHealthy && localHealthy, data.IsTest, data.Disks, data.ClientReports, nil
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

	// Check server and client SMART health during file check cycle
	go func() {
		_, _, _, _, _ = s.CheckSMARTDriveHealth()
	}()

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
		Success   bool                `json:"success"`
		Items     []ServerItem        `json:"items"`
		Deleted   []ServerDeletedItem `json:"deleted"`
		Ledger    []ServerLedgerEntry `json:"ledger"`
		Timestamp int64               `json:"timestamp"` // Server system timestamp
		Error     string              `json:"error,omitempty"`
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

	// Calculate client-to-server clock offset to compare timestamps accurately
	nowClient := time.Now().Unix()
	clockOffset := ComputeClockOffset(listData.Timestamp, nowClient)
	s.writeClientDebugLog("Clock synchronization: serverTime=%d clientTime=%d offset=%d", listData.Timestamp, nowClient, clockOffset)

	// Clean up any locally unchecked (opted-out) directories on client PC
	s.cleanupUncheckedFolders()

	serverMap := make(map[string]ServerItem)
	for _, it := range listData.Items {
		serverMap[it.RelPath] = it
	}

	serverDeletedMap := make(map[string]int64)
	for _, d := range listData.Deleted {
		serverDeletedMap[d.RelPath] = d.DeletedAt
	}

	// -------------------------------------------------------------
	// STEP A: Check Local Files for Deletions and User Restorations
	// -------------------------------------------------------------
	s.manifestMu.Lock()
	for relPath, tf := range s.manifest {
		parentDir := filepath.Dir(relPath)
		if !IsFolderSelected(parentDir, s.cfg.SelectedFolders) {
			continue
		}

		localPath := filepath.Join(s.cfg.LocalSyncDir, filepath.FromSlash(relPath))
		lInfo, statErr := os.Stat(localPath)

		if os.IsNotExist(statErr) {
			// Special case: if user deleted the root RecycleBin directory locally, do not propagate delete to server.
			// The RecycleBin folder cannot be deleted; it will be re-created/restored from server in Step C.
			if relPath == "RecycleBin" || relPath == "RecycleBin/" {
				delete(s.manifest, relPath)
				continue
			}

			// File is missing locally
			if !tf.Deleted {
				// If a file inside RecycleBin was deleted by user, it permanently deletes from server
				// Otherwise, user deleted normal file -> record deletion and inform server (which moves it to RecycleBin)
				nowUnix := time.Now().Unix()
				s.writeClientDebugLog("Detected local deletion: %s. Propagating delete to server.", relPath)
				s.SetStatus(fmt.Sprintf("Syncing deletion of %s...", filepath.Base(relPath)))
				if delErr := s.deleteRemoteFile(relPath); delErr == nil {
					tf.Deleted = true
					tf.DeletedAt = nowUnix
					s.manifest[relPath] = tf
					RecordClientFileUpdate(s.cfg.LocalSyncDir, relPath, "deleted", s.cfg.Username, 0, 0, "")
				}
			}
		} else if statErr == nil && !lInfo.IsDir() {
			// File EXISTS locally on disk!
			if tf.Deleted {
				// User explicitly restored or copied this file back into the folder!
				s.writeClientDebugLog("User placed previously deleted file back into folder: %s. Revoking deletion.", relPath)
				tf.Deleted = false
				tf.DeletedAt = 0
				tf.ModTime = lInfo.ModTime().Unix()
				tf.Size = lInfo.Size()
				s.manifest[relPath] = tf
				RecordClientFileUpdate(s.cfg.LocalSyncDir, relPath, "restored", s.cfg.Username, tf.ModTime, tf.Size, "")
				// Clear any server deletion tombstone so it won't be deleted in Step B
				delete(serverDeletedMap, relPath)
			}
		}
	}
	s.manifestMu.Unlock()
	s.saveManifest()

	// -------------------------------------------------------------
	// STEP B: Process Server Deletions
	// -------------------------------------------------------------
	for delRel, delTime := range serverDeletedMap {
		localPath := filepath.Join(s.cfg.LocalSyncDir, filepath.FromSlash(delRel))
		if lInfo, lErr := os.Stat(localPath); lErr == nil {
			s.manifestMu.Lock()
			tracked, wasTracked := s.manifest[delRel]
			s.manifestMu.Unlock()

			// Normalize local modTime to server timeline for fair comparison
			normalizedLocalMod := NormalizeClientModTime(tracked.ModTime, clockOffset)

			// Only delete if file was tracked by client before the deletion occurred
			// and has not been un-deleted/placed back by the user
			if wasTracked && !tracked.Deleted && normalizedLocalMod <= delTime {
				s.writeClientDebugLog("Server deleted file: %s (deletedAt=%d).", delRel, delTime)
				// If the file is already inside RecycleBin, remove it permanently without re-recycling
				if strings.HasPrefix(delRel, "RecycleBin/") || delRel == "RecycleBin" {
					_ = os.Remove(localPath)
				} else {
					s.SetStatus(fmt.Sprintf("Archiving deleted file %s...", filepath.Base(delRel)))
					s.moveLocalToRecycle(localPath, delRel, lInfo)
				}
				s.manifestMu.Lock()
				s.manifest[delRel] = TrackedFile{RelPath: delRel, Deleted: true, DeletedAt: delTime}
				s.manifestMu.Unlock()
				RecordClientFileUpdate(s.cfg.LocalSyncDir, delRel, "deleted", s.cfg.Username, 0, 0, "")
			}
		}
	}

	// -------------------------------------------------------------
	// STEP C: Download Server Files to Local (if server version is newer)
	// -------------------------------------------------------------
	for _, sItem := range listData.Items {
		if sItem.IsDir {
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
				effectiveDelTime := tracked.DeletedAt
				if effectiveDelTime <= 0 {
					effectiveDelTime = tracked.ModTime
				}
				// Compare server modTime with normalized deletion time
				normalizedDelTime := NormalizeClientModTime(effectiveDelTime, clockOffset)
				if sItem.ModTime > normalizedDelTime {
					// Server has updated or re-created the file strictly AFTER deletion
					shouldDownload = true
				} else {
					// Server still has the older copy before deletion: do not download, re-propagate deletion to server
					s.writeClientDebugLog("Prevented resurrection of locally deleted file %s (server modTime=%d vs normalizedDelTime=%d)", sItem.RelPath, sItem.ModTime, normalizedDelTime)
					_ = s.deleteRemoteFile(sItem.RelPath)
				}
			} else {
				// New file on server
				shouldDownload = true
			}
		} else if err == nil {
			normalizedLocalMod := NormalizeClientModTime(localInfo.ModTime().Unix(), clockOffset)
			// If previously marked deleted, ensure local file was actually modified after deletion
			if wasTracked && tracked.Deleted && localInfo.ModTime().Unix() <= tracked.DeletedAt {
				// File was restored by accident or pending delete; archive it (or remove if in RecycleBin)
				if strings.HasPrefix(sItem.RelPath, "RecycleBin/") {
					_ = os.Remove(localPath)
				} else {
					s.moveLocalToRecycle(localPath, sItem.RelPath, localInfo)
				}
			} else if sItem.ModTime > normalizedLocalMod {
				// Server file is strictly newer than local file
				shouldDownload = true
			}
		}

		if shouldDownload {
			s.SetStatus(fmt.Sprintf("Downloading %s...", sItem.Name))
			// When setting local mtime, convert server timestamp to local clock timeline
			localMTime := LocalComparableServerModTime(sItem.ModTime, clockOffset)
			if err := s.downloadFile(sItem.RelPath, localPath, localMTime); err == nil {
				s.manifestMu.Lock()
				s.manifest[sItem.RelPath] = TrackedFile{
					RelPath: sItem.RelPath,
					ModTime: localMTime,
					Size:    sItem.Size,
					SHA256:  sItem.SHA256,
					Deleted: false,
				}
				s.manifestMu.Unlock()
				RecordClientFileUpdate(s.cfg.LocalSyncDir, sItem.RelPath, "downloaded", s.cfg.Username, localMTime, sItem.Size, sItem.SHA256)
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
		baseName := filepath.Base(relSlash)
		if strings.HasPrefix(relSlash, ".cloud_meta") || strings.HasPrefix(relSlash, "RecycleBin") ||
			baseName == ".cloud_data" || strings.HasPrefix(baseName, ".cloud-") {
			return nil
		}

		parentDir := filepath.Dir(relSlash)
		if !IsFolderSelected(parentDir, s.cfg.SelectedFolders) {
			return nil
		}

		sItem, existsOnServer := serverMap[relSlash]
		localMod := info.ModTime().Unix()
		normalizedLocalMod := NormalizeClientModTime(localMod, clockOffset)

		shouldUpload := false
		if !existsOnServer {
			shouldUpload = true
		} else if normalizedLocalMod > sItem.ModTime {
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
				RecordClientFileUpdate(s.cfg.LocalSyncDir, relSlash, "uploaded", s.cfg.Username, localMod, info.Size(), "")
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
			RecordClientFileUpdate(s.cfg.LocalSyncDir, relSlash, "in-sync", s.cfg.Username, localMod, info.Size(), "")
		}

		return nil
	})

	s.saveManifest()
	s.SetStatus("Up to Date")
	return err
}

func (s *SyncEngine) moveLocalToRecycle(localPath, relPath string, info os.FileInfo) {
	// Guard against nested RecycleBin
	cleanRel := filepath.ToSlash(relPath)
	if strings.HasPrefix(cleanRel, "RecycleBin/") || cleanRel == "RecycleBin" {
		_ = os.Remove(localPath)
		return
	}

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

	// Write companion restore metadata file (.restore_info.json) so the user knows where to restore the file
	restoreMeta := map[string]interface{}{
		"original_path": relPath,
		"archived_path": filepath.ToSlash(filepath.Join("RecycleBin", relDir, fmt.Sprintf("%s.deleted.%s", baseName, dateTag))),
		"deleted_at":    dateTag,
		"mod_time":      info.ModTime().Unix(),
		"size":          info.Size(),
	}
	if mBytes, mErr := json.MarshalIndent(restoreMeta, "", "  "); mErr == nil {
		_ = os.WriteFile(destPath+".restore_info.json", mBytes, 0644)
	}
	s.writeClientDebugLog("Moved local deleted file %s to RecycleBin at %s (restore metadata saved)", relPath, destPath)
}

func (s *SyncEngine) deleteRemoteFile(relPath string) error {
	delReq := map[string]interface{}{
		"path":        relPath,
		"client_time": time.Now().Unix(),
		"client_id":   s.cfg.Username,
	}
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
		"client_time": time.Now().Unix(),
		"client_id":   s.cfg.Username,
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

// cleanupUncheckedFolders removes local directories on the client PC if they have been opted-out/unchecked by the user.
// Server copies remain untouched. Supports nested subdirectories.
func (s *SyncEngine) cleanupUncheckedFolders() {
	if s.cfg.LocalSyncDir == "" || len(s.cfg.SelectedFolders) == 0 {
		return
	}

	var toRemove []string
	_ = filepath.Walk(s.cfg.LocalSyncDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		rel, rErr := filepath.Rel(s.cfg.LocalSyncDir, path)
		if rErr != nil || rel == "." || rel == "" {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if strings.HasPrefix(relSlash, ".cloud_meta") || filepath.Base(path) == ".cloud_meta" {
			return filepath.SkipDir
		}

		if !IsFolderSelected(relSlash, s.cfg.SelectedFolders) {
			toRemove = append(toRemove, relSlash)
			return filepath.SkipDir
		}
		return nil
	})

	for _, relDir := range toRemove {
		target := filepath.Join(s.cfg.LocalSyncDir, filepath.FromSlash(relDir))
		s.writeClientDebugLog("Cleaning up opted-out local folder: %s", target)
		_ = os.RemoveAll(target)

		// Remove tracked files under this folder from in-memory manifest
		s.manifestMu.Lock()
		prefix := relDir + "/"
		for k := range s.manifest {
			if k == relDir || strings.HasPrefix(k, prefix) {
				delete(s.manifest, k)
			}
		}
		s.manifestMu.Unlock()
	}
}
