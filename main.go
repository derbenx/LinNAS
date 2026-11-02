package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed html
var embeddedHTML embed.FS

type Config struct {
	Port         int               `json:"port"`
	AuthEnabled  bool              `json:"auth_enabled"`
	Username     string            `json:"username"`
	Password     string            `json:"password"`
	PasswordHash string            `json:"password_hash"`
	FeatureToggles map[string]bool `json:"feature_toggles"`
}

type PluginManifest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Default     bool              `json:"default"`
	AptPackage  string            `json:"apt_package,omitempty"`
	CheckCmd    string            `json:"check_cmd,omitempty"`
	InstallCmd  string            `json:"install_cmd,omitempty"`
	RemoveCmd   string            `json:"remove_cmd,omitempty"`
	Commands    map[string]string `json:"commands,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Installed   bool              `json:"installed"`
	Enabled     bool              `json:"enabled"`
}

type ExecRequest struct {
	Plugin string            `json:"plugin"`
	CmdKey string            `json:"cmd_key"`
	Args   map[string]string `json:"args"`
}

type ExecResponse struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

type FileEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	IsDir       bool   `json:"is_dir"`
	Size        int64  `json:"size"`
	Permissions string `json:"permissions,omitempty"`
	ModeOctal   string `json:"mode_octal,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Group       string `json:"group,omitempty"`
	FsType      string `json:"fs_type,omitempty"`
}

type SMBShare struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Comment    string   `json:"comment"`
	ReadOnly   bool     `json:"read_only"`
	Enabled    bool     `json:"enabled"`
	ValidUsers []string `json:"valid_users,omitempty"`
}

type SMBData struct {
	Shares    []SMBShare `json:"shares"`
	HideHomes bool       `json:"hide_homes"`
}

type DNSData struct {
	PrimaryDNS   string `json:"primary_dns"`
	SecondaryDNS string `json:"secondary_dns"`
	BlockRules   string `json:"block_rules"`
}

type DHCPData struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
	StartIP   string `json:"start_ip"`
	EndIP     string `json:"end_ip"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway"`
	LeaseTime string `json:"lease_time"`
}

var (
	appConfig        Config
	sessions         = make(map[string]time.Time)
	isAutostartMode  = false
	sessionsMu    sync.RWMutex
	consoleDirs   = make(map[string]string)
	consoleDirsMu sync.Mutex
	activeStdinPipes   = make(map[string]io.WriteCloser)
	activeStdinPipesMu sync.Mutex
	rsaPrivateKey *rsa.PrivateKey
	usedNonces    = make(map[string]time.Time)
	noncesMu      sync.Mutex
	// Prohibit shell metacharacters $, `, |, &, ;, <, >, (, ), \, *, ?, newlines \r \n
	safeVarReg    = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/\:\ \@\!\#\%\^\=\+\{\}\[\]\~\t]+$`)

	cloudConfigMu sync.RWMutex
	cloudConfig   CloudConfig
	cloudFileLocks   = make(map[string]bool)
	cloudFileLocksMu sync.Mutex
	cloudActivityMu  sync.RWMutex
	cloudLastActivity time.Time

	cloudSmartTestMu sync.RWMutex
	cloudSmartTestSimulated bool
)

type CloudConfig struct {
	Enabled    bool   `json:"enabled"`
	Folder     string `json:"folder"`
	VolumeUUID string `json:"volume_uuid"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

type CloudMetaFile struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	ModTime     int64  `json:"mod_time"`
	SHA256      string `json:"sha256"`
	LastUpdated string `json:"last_updated"`
}

type CloudHistoryEntry struct {
	Action      string `json:"action"` // "overwrite", "delete", "conflict_reject"
	OrigPath    string `json:"orig_path"`
	BackupPath  string `json:"backup_path,omitempty"`
	Timestamp   string `json:"timestamp"`
	ModTime     int64  `json:"mod_time,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Details     string `json:"details,omitempty"`
}

type CloudDeletedItem struct {
	RelPath   string `json:"rel_path"`
	DeletedAt int64  `json:"deleted_at"` // Unix timestamp
}

type CloudDirMeta struct {
	Directory   string                       `json:"directory"`
	ServerMAC   string                       `json:"server_mac"`
	VolumeUUID  string                       `json:"volume_uuid"`
	LastScan    string                       `json:"last_scan"`
	Files       map[string]CloudMetaFile     `json:"files"`
	Deleted     map[string]int64             `json:"deleted,omitempty"` // basename -> deleted_at unix timestamp
	History     []CloudHistoryEntry          `json:"history"`
}

func initRSAKeys() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaPrivateKey = key
}

func handleCryptoPubKey(w http.ResponseWriter, r *http.Request) {
	pubASN1, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		http.Error(w, "Failed to encode public key", http.StatusInternalServerError)
		return
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubASN1)
	jsonResponse(w, map[string]interface{}{"public_key": pubB64})
}

type EncryptedPayload struct {
	EncryptedKey  string `json:"encrypted_key"`
	EncryptedData string `json:"encrypted_data"`
	Nonce         string `json:"nonce"`
	Timestamp     int64  `json:"timestamp"`
}

func checkNonceAndTimestamp(nonce string, timestamp int64) error {
	now := time.Now().Unix()
	if now-timestamp > 60 || timestamp-now > 60 {
		return fmt.Errorf("request timestamp expired or out of sync (%d vs %d)", timestamp, now)
	}

	noncesMu.Lock()
	defer noncesMu.Unlock()

	// Clean up old nonces
	for n, t := range usedNonces {
		if time.Since(t) > 2*time.Minute {
			delete(usedNonces, n)
		}
	}

	if _, exists := usedNonces[nonce]; exists {
		return fmt.Errorf("replay attack detected: nonce %s already used", nonce)
	}

	usedNonces[nonce] = time.Now()
	return nil
}

func decryptPayloadWithKey(body []byte) ([]byte, []byte, error) {
	var encPayload EncryptedPayload
	if err := json.Unmarshal(body, &encPayload); err != nil || encPayload.EncryptedKey == "" {
		// Return unencrypted raw body if payload isn't encrypted
		return body, nil, nil
	}

	if err := checkNonceAndTimestamp(encPayload.Nonce, encPayload.Timestamp); err != nil {
		return nil, nil, err
	}

	keyBytes, err := base64.StdEncoding.DecodeString(encPayload.EncryptedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64 encrypted_key")
	}

	// Decrypt AES key with RSA private key
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, keyBytes, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt AES key with RSA: %v", err)
	}

	dataBytes, err := base64.StdEncoding.DecodeString(encPayload.EncryptedData)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64 encrypted_data")
	}

	if len(dataBytes) < 12 {
		return nil, nil, fmt.Errorf("encrypted_data payload too short for AES-GCM nonce")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(dataBytes) < nonceSize {
		return nil, nil, fmt.Errorf("ciphertext too short")
	}

	aesNonce, ciphertext := dataBytes[:nonceSize], dataBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, aesNonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt AES-GCM data: %v", err)
	}

	return plaintext, aesKey, nil
}

func decryptPayload(body []byte) ([]byte, error) {
	plaintext, _, err := decryptPayloadWithKey(body)
	return plaintext, err
}

func encryptResponseWithAES(aesKey []byte, data []byte) (map[string]interface{}, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	combined := append(nonce, ciphertext...)
	return map[string]interface{}{
		"encrypted":      true,
		"encrypted_data": base64.StdEncoding.EncodeToString(combined),
	}, nil
}

func hashPassword(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

func loadConfig() {
	appConfig = Config{
		Port:           8080,
		AuthEnabled:    true,
		Username:       "admin",
		Password:       "adminpassword",
		FeatureToggles: map[string]bool{"console": true, "editor": true},
	}

	data, err := os.ReadFile("config.json")
	if err == nil {
		_ = json.Unmarshal(data, &appConfig)
	}

	if appConfig.FeatureToggles == nil {
		appConfig.FeatureToggles = map[string]bool{"console": true, "editor": true}
	}

	// Check for linnas.data overrides
	if lData, err := os.ReadFile("linnas.data"); err == nil {
		var lConfig struct {
			Username       string          `json:"username"`
			PasswordHash   string          `json:"password_hash"`
			Port           int             `json:"port"`
			FeatureToggles map[string]bool `json:"feature_toggles"`
		}
		if err := json.Unmarshal(lData, &lConfig); err == nil {
			if lConfig.Username != "" {
				appConfig.Username = lConfig.Username
			}
			if lConfig.PasswordHash != "" {
				appConfig.PasswordHash = lConfig.PasswordHash
			}
			if lConfig.Port > 0 {
				appConfig.Port = lConfig.Port
			}
			if lConfig.FeatureToggles != nil {
				for k, v := range lConfig.FeatureToggles {
					appConfig.FeatureToggles[k] = v
				}
			}
		}
	}

	if appConfig.PasswordHash == "" && appConfig.Password != "" {
		appConfig.PasswordHash = hashPassword(appConfig.Password)
		appConfig.Password = "" // Clear plaintext default password from memory
	}
}

func saveLinnasDataEx(username string, passwordHash string, port int, toggles map[string]bool) error {
	if username == "" {
		username = appConfig.Username
	}
	if passwordHash == "" {
		passwordHash = appConfig.PasswordHash
	}
	if port <= 0 {
		port = appConfig.Port
	}
	if toggles == nil {
		toggles = appConfig.FeatureToggles
	}

	lData, err := json.Marshal(map[string]interface{}{
		"username":        username,
		"password_hash":   passwordHash,
		"port":            port,
		"feature_toggles": toggles,
		"updated_at":      time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}

	appConfig.Username = username
	appConfig.PasswordHash = passwordHash
	appConfig.Port = port
	appConfig.FeatureToggles = toggles

	return os.WriteFile("linnas.data", lData, 0600)
}

func saveLinnasData(username string, passwordHash string) error {
	return saveLinnasDataEx(username, passwordHash, appConfig.Port, appConfig.FeatureToggles)
}

func generateToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isAuthorized(r *http.Request) bool {
	if !appConfig.AuthEnabled {
		return true
	}
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	sessionsMu.RLock()
	expiry, exists := sessions[cookie.Value]
	sessionsMu.RUnlock()

	if !exists || time.Now().After(expiry) {
		return false
	}
	return true
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/api/login" || path == "/api/auth/status" {
			next(w, r)
			return
		}
		if strings.HasPrefix(path, "/login.htm") || strings.HasPrefix(path, "/css/") || strings.HasPrefix(path, "/js/") {
			next(w, r)
			return
		}

		if !isAuthorized(r) {
			// Allow unauthenticated GET requests to static HTML/CSS/JS files and status views
			if r.Method == http.MethodGet && !strings.HasPrefix(path, "/api/") {
				next(w, r)
				return
			}
			if strings.HasPrefix(path, "/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login.htm", http.StatusSeeOther)
			}
			return
		}

		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if os.Getuid() != 0 {
		http.Error(w, "Root privileges required for cron operations", http.StatusForbidden)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var creds struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		PasswordHash string `json:"password_hash"`
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(decryptedBody, &creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	authenticated := false

	// Check if already authenticated by valid existing session token
	if creds.SessionToken != "" {
		sessionsMu.RLock()
		exp, ok := sessions[creds.SessionToken]
		sessionsMu.RUnlock()
		if ok && time.Now().Before(exp) {
			authenticated = true
		}
	}

	// Check credentials (accepts plaintext password OR pre-hashed password_hash)
	if !authenticated && creds.Username == appConfig.Username {
		if creds.PasswordHash != "" && strings.EqualFold(creds.PasswordHash, appConfig.PasswordHash) {
			authenticated = true
		} else if creds.Password != "" {
			providedHash := hashPassword(creds.Password)
			if strings.EqualFold(providedHash, appConfig.PasswordHash) || creds.Password == appConfig.Password {
				authenticated = true
			}
		}
	}

	if authenticated {
		token := creds.SessionToken
		if token == "" {
			token = generateToken()
		}
		// Refresh session expiry (30 days for API/desktop clients)
		sessionsMu.Lock()
		sessions[token] = time.Now().Add(30 * 24 * time.Hour)
		sessionsMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(30 * 24 * time.Hour),
		})
		jsonResponse(w, map[string]interface{}{
			"success":       true,
			"session_token": token,
			"expires_in":    30 * 24 * 3600,
		})
	} else {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
	}
}

func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if os.Getuid() != 0 {
		http.Error(w, "Root privileges required for cron operations", http.StatusForbidden)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.NewPassword == "" {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	currentHash := hashPassword(req.CurrentPassword)
	if currentHash != appConfig.PasswordHash && req.CurrentPassword != appConfig.Password {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "Incorrect current password"})
		return
	}

	newHash := hashPassword(req.NewPassword)
	appConfig.PasswordHash = newHash
	appConfig.Password = "" // Clear plaintext password

	if err := saveLinnasData(appConfig.Username, newHash); err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "Failed to save password hash to linnas.data: " + err.Error()})
		return
	}

	jsonResponse(w, map[string]interface{}{"success": true, "message": "Password updated and saved to linnas.data"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"auth_enabled": appConfig.AuthEnabled,
		"logged_in":    isAuthorized(r),
		"is_root":      os.Getuid() == 0,
	})
}

func checkPackageInstalled(checkCmd string, aptPackage string) bool {
	if checkCmd != "" {
		cmd := exec.Command("sh", "-c", checkCmd)
		return cmd.Run() == nil
	}
	if aptPackage != "" {
		cmd := exec.Command("dpkg-query", "-W", "-f='${Status}'", aptPackage)
		out, err := cmd.Output()
		if err == nil && strings.Contains(string(out), "install ok installed") {
			return true
		}
		cmd2 := exec.Command("which", aptPackage)
		if cmd2.Run() == nil {
			return true
		}
	}
	return false
}

func getPlugins() ([]PluginManifest, error) {
	var plugins []PluginManifest
	entries, err := os.ReadDir("html")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		jsonPath := filepath.Join("html", entry.Name(), "plugin.json")
		if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(jsonPath)
		if err != nil {
			continue
		}

		var manifest PluginManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			continue
		}

		if manifest.ID == "" {
			manifest.ID = entry.Name()
		}

		if manifest.Default {
			manifest.Installed = true
		} else {
			manifest.Installed = checkPackageInstalled(manifest.CheckCmd, manifest.AptPackage)
		}

		manifest.Enabled = true
		if enabled, exists := appConfig.FeatureToggles[manifest.ID]; exists {
			manifest.Enabled = enabled
		}

		// Hide admin-only APT plugin when running in non-root user mode
		if os.Getuid() != 0 && manifest.ID == "apt" {
			continue
		}

		plugins = append(plugins, manifest)
	}

	return plugins, nil
}

func handleListPlugins(w http.ResponseWriter, r *http.Request) {
	plugins, err := getPlugins()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, plugins)
}

func handleExecPluginCmd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req ExecRequest
	if err := json.Unmarshal(decryptedBody, &req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, req.Plugin); !matched {
		jsonResponse(w, ExecResponse{Success: false, Error: "Invalid plugin ID"})
		return
	}

	// Block execution if plugin feature is disabled
	if enabled, exists := appConfig.FeatureToggles[req.Plugin]; exists && !enabled {
		jsonResponse(w, ExecResponse{Success: false, Error: fmt.Sprintf("Plugin '%s' is currently disabled", req.Plugin)})
		return
	}

	// Validate command key ends strictly with _cmd or _sudo
	isSudoCmd := strings.HasSuffix(req.CmdKey, "_sudo")
	isStandardCmd := strings.HasSuffix(req.CmdKey, "_cmd")

	if !isSudoCmd && !isStandardCmd {
		jsonResponse(w, ExecResponse{Success: false, Error: "Only keys ending with '_cmd' or '_sudo' can be executed"})
		return
	}

	jsonPath := filepath.Join("html", req.Plugin, "plugin.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		jsonResponse(w, ExecResponse{Success: false, Error: "Plugin manifest not found"})
		return
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		jsonResponse(w, ExecResponse{Success: false, Error: "Failed to parse plugin manifest"})
		return
	}

	cmdTemplate := ""
	if val, ok := rawMap[req.CmdKey].(string); ok {
		cmdTemplate = val
	} else if cmds, ok := rawMap["commands"].(map[string]interface{}); ok {
		if val, ok := cmds[req.CmdKey].(string); ok {
			cmdTemplate = val
		}
	}

	// Fallback mapping for install/remove commands
	if cmdTemplate == "" {
		if req.CmdKey == "install_cmd" || req.CmdKey == "install_sudo" {
			if val, ok := rawMap["install_sudo"].(string); ok {
				cmdTemplate = val
			} else if val, ok := rawMap["install_cmd"].(string); ok {
				cmdTemplate = val
			}
		} else if req.CmdKey == "remove_cmd" || req.CmdKey == "remove_sudo" {
			if val, ok := rawMap["remove_sudo"].(string); ok {
				cmdTemplate = val
			} else if val, ok := rawMap["remove_cmd"].(string); ok {
				cmdTemplate = val
			}
		}
	}

	if cmdTemplate == "" {
		jsonResponse(w, ExecResponse{Success: false, Error: fmt.Sprintf("Command key %s not found in plugin", req.CmdKey)})
		return
	}

	finalCmd := cmdTemplate
	for k, v := range req.Args {
		if len(v) > 0 && !safeVarReg.MatchString(v) {
			jsonResponse(w, ExecResponse{Success: false, Error: fmt.Sprintf("Invalid or dangerous character in parameter %s", k)})
			return
		}
		finalCmd = strings.ReplaceAll(finalCmd, "{"+k+"}", v)
		finalCmd = strings.ReplaceAll(finalCmd, "%"+k+"%", v)
	}

	needsSudo := isSudoCmd || req.CmdKey == "install_sudo" || req.CmdKey == "remove_sudo" || (req.CmdKey == "install_cmd" && rawMap["install_sudo"] != nil) || (req.CmdKey == "remove_cmd" && rawMap["remove_sudo"] != nil)
	var execCmd *exec.Cmd
	if needsSudo && os.Getuid() != 0 {
		log.Printf("[EXEC-SUDO] Plugin: %s, CmdKey: %s, Cmd: %s", req.Plugin, req.CmdKey, finalCmd)
		execCmd = exec.Command("sudo", "-n", "sh", "-c", finalCmd)
	} else {
		log.Printf("[EXEC] Plugin: %s, CmdKey: %s, Cmd: %s", req.Plugin, req.CmdKey, finalCmd)
		execCmd = exec.Command("sh", "-c", finalCmd)
	}

	outBytes, err := execCmd.CombinedOutput()
	outputStr := string(outBytes)

	if err != nil {
		jsonResponse(w, ExecResponse{
			Success: false,
			Output:  outputStr,
			Error:   err.Error(),
		})
		return
	}

	jsonResponse(w, ExecResponse{
		Success: true,
		Output:  outputStr,
	})
}

func handleExecPluginCmdStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req ExecRequest
	if err := json.Unmarshal(decryptedBody, &req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, req.Plugin); !matched {
		http.Error(w, "Invalid plugin ID", http.StatusBadRequest)
		return
	}

	if enabled, exists := appConfig.FeatureToggles[req.Plugin]; exists && !enabled {
		http.Error(w, fmt.Sprintf("Plugin '%s' is currently disabled", req.Plugin), http.StatusForbidden)
		return
	}

	isSudoCmd := strings.HasSuffix(req.CmdKey, "_sudo")
	isStandardCmd := strings.HasSuffix(req.CmdKey, "_cmd")

	if !isSudoCmd && !isStandardCmd {
		http.Error(w, "Only keys ending with '_cmd' or '_sudo' can be executed", http.StatusBadRequest)
		return
	}

	jsonPath := filepath.Join("html", req.Plugin, "plugin.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		http.Error(w, "Plugin manifest not found", http.StatusNotFound)
		return
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		http.Error(w, "Failed to parse plugin manifest", http.StatusInternalServerError)
		return
	}

	cmdTemplate := ""
	if val, ok := rawMap[req.CmdKey].(string); ok {
		cmdTemplate = val
	} else if cmds, ok := rawMap["commands"].(map[string]interface{}); ok {
		if val, ok := cmds[req.CmdKey].(string); ok {
			cmdTemplate = val
		}
	}

	if cmdTemplate == "" {
		if req.CmdKey == "install_cmd" || req.CmdKey == "install_sudo" {
			if val, ok := rawMap["install_sudo"].(string); ok {
				cmdTemplate = val
			} else if val, ok := rawMap["install_cmd"].(string); ok {
				cmdTemplate = val
			}
		} else if req.CmdKey == "remove_cmd" || req.CmdKey == "remove_sudo" {
			if val, ok := rawMap["remove_sudo"].(string); ok {
				cmdTemplate = val
			} else if val, ok := rawMap["remove_cmd"].(string); ok {
				cmdTemplate = val
			}
		}
	}

	if cmdTemplate == "" {
		http.Error(w, fmt.Sprintf("Command key %s not found in plugin", req.CmdKey), http.StatusNotFound)
		return
	}

	finalCmd := cmdTemplate
	for k, v := range req.Args {
		if len(v) > 0 && !safeVarReg.MatchString(v) {
			http.Error(w, fmt.Sprintf("Invalid or dangerous character in parameter %s", k), http.StatusBadRequest)
			return
		}
		finalCmd = strings.ReplaceAll(finalCmd, "{"+k+"}", v)
		finalCmd = strings.ReplaceAll(finalCmd, "%"+k+"%", v)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	needsSudo := isSudoCmd || req.CmdKey == "install_sudo" || req.CmdKey == "remove_sudo" || (req.CmdKey == "install_cmd" && rawMap["install_sudo"] != nil) || (req.CmdKey == "remove_cmd" && rawMap["remove_sudo"] != nil)
	var execCmd *exec.Cmd
	if needsSudo && os.Getuid() != 0 {
		log.Printf("[EXEC-STREAM-SUDO] Plugin: %s, CmdKey: %s, Cmd: %s", req.Plugin, req.CmdKey, finalCmd)
		execCmd = exec.Command("sudo", "-n", "sh", "-c", finalCmd)
	} else {
		log.Printf("[EXEC-STREAM] Plugin: %s, CmdKey: %s, Cmd: %s", req.Plugin, req.CmdKey, finalCmd)
		execCmd = exec.Command("sh", "-c", finalCmd)
	}

	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		_, _ = fmt.Fprintf(w, "Error creating stdout pipe: %v\n", err)
		return
	}
	stderrPipe, err := execCmd.StderrPipe()
	if err != nil {
		_, _ = fmt.Fprintf(w, "Error creating stderr pipe: %v\n", err)
		return
	}

	if err := execCmd.Start(); err != nil {
		_, _ = fmt.Fprintf(w, "Error starting command: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 512)
		for {
			n, readErr := stdoutPipe.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				flusher.Flush()
			}
			if readErr != nil {
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 512)
		for {
			n, readErr := stderrPipe.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				flusher.Flush()
			}
			if readErr != nil {
				break
			}
		}
	}()

	wg.Wait()
	_ = execCmd.Wait()
}

// Sync SMB, DNS, and DHCP plugin data directly to Debian service configs
func syncSystemConfigs(pluginID string, body []byte) {
	switch pluginID {
	case "smb":
		var smbData SMBData
		if err := json.Unmarshal(body, &smbData); err == nil {
			var sb strings.Builder
			sb.WriteString("# Generated by LinNAS\n\n")

			if smbData.HideHomes {
				sb.WriteString("[homes]\n")
				sb.WriteString("   comment = User Home Directories\n")
				sb.WriteString("   browseable = no\n")
				sb.WriteString("   available = no\n")
				sb.WriteString("   read only = yes\n\n")
			}

			var activeShares []SMBShare
			for _, share := range smbData.Shares {
				if !share.Enabled {
					continue
				}

				// Ensure directory exists for share path
				cleanPath := filepath.Clean(share.Path)
				if info, err := os.Stat(cleanPath); os.IsNotExist(err) || err != nil || !info.IsDir() {
					_ = os.MkdirAll(cleanPath, 0777)
				}

				activeShares = append(activeShares, share)

				sb.WriteString(fmt.Sprintf("[%s]\n", share.Name))
				sb.WriteString(fmt.Sprintf("   path = %s\n", share.Path))
				if share.Comment != "" {
					sb.WriteString(fmt.Sprintf("   comment = %s\n", share.Comment))
				}
				if share.ReadOnly {
					sb.WriteString("   read only = yes\n")
				} else {
					sb.WriteString("   read only = no\n")
				}
				if len(share.ValidUsers) > 0 {
					sb.WriteString(fmt.Sprintf("   valid users = %s\n", strings.Join(share.ValidUsers, " ")))
					sb.WriteString("   guest ok = no\n\n")
				} else {
					sb.WriteString("   guest ok = yes\n\n")
				}
			}
			_ = os.MkdirAll("/etc/samba/conf.d", 0755)
			confPath := "/etc/samba/conf.d/shares.conf"
			_ = os.WriteFile(confPath, []byte(sb.String()), 0644)

			// Ensure smb.conf includes shares.conf
			if mainConf, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
				if !strings.Contains(string(mainConf), "/etc/samba/conf.d/shares.conf") {
					newConf := string(mainConf) + "\n\n# Include LinNAS Shares\ninclude = /etc/samba/conf.d/shares.conf\n"
					_ = os.WriteFile("/etc/samba/smb.conf", []byte(newConf), 0644)
				}
			}
		}

	case "dns":
		var dnsData DNSData
		if err := json.Unmarshal(body, &dnsData); err == nil {
			var sb strings.Builder
			sb.WriteString("# Generated by LinNAS\n")
			if dnsData.PrimaryDNS != "" {
				sb.WriteString(fmt.Sprintf("server=%s\n", dnsData.PrimaryDNS))
			}
			if dnsData.SecondaryDNS != "" {
				sb.WriteString(fmt.Sprintf("server=%s\n", dnsData.SecondaryDNS))
			}
			if dnsData.BlockRules != "" {
				sb.WriteString("\n# AdBlock Rules\n")
				sb.WriteString(dnsData.BlockRules)
				sb.WriteString("\n")
			}
			_ = os.MkdirAll("/etc/dnsmasq.d", 0755)
			_ = os.WriteFile("/etc/dnsmasq.d/99-server-manager-dns.conf", []byte(sb.String()), 0644)
		}

	case "dhcp":
		var dhcpData DHCPData
		if err := json.Unmarshal(body, &dhcpData); err == nil {
			var sb strings.Builder
			sb.WriteString("# Generated by LinNAS\n")
			if dhcpData.Enabled && dhcpData.Interface != "" && dhcpData.StartIP != "" && dhcpData.EndIP != "" {
				sb.WriteString(fmt.Sprintf("interface=%s\n", dhcpData.Interface))
				sb.WriteString(fmt.Sprintf("dhcp-range=%s,%s,%s,%s\n", dhcpData.StartIP, dhcpData.EndIP, dhcpData.Netmask, dhcpData.LeaseTime))
				if dhcpData.Gateway != "" {
					sb.WriteString(fmt.Sprintf("dhcp-option=option:router,%s\n", dhcpData.Gateway))
				}
			}
			_ = os.MkdirAll("/etc/dnsmasq.d", 0755)
			_ = os.WriteFile("/etc/dnsmasq.d/99-server-manager-dhcp.conf", []byte(sb.String()), 0644)
		}

	case "cron":
		var cronPayload struct {
			Tasks []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Command   string `json:"command"`
				Args      string `json:"args"`
				Schedule  string `json:"schedule"`
				IsRoot    bool   `json:"is_root"`
				Enabled   bool   `json:"enabled"`
			} `json:"tasks"`
		}
		if err := json.Unmarshal(body, &cronPayload); err == nil {
			var sb strings.Builder
			sb.WriteString("# /etc/cron.d/linnas-cron\n")
			sb.WriteString("# Generated automatically by LinNAS Cron Tasks plugin\n")
			sb.WriteString("SHELL=/bin/bash\n")
			sb.WriteString("PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n")

			for _, t := range cronPayload.Tasks {
				if t.Command == "" || t.Schedule == "" {
					continue
				}
				user := "root"
				if !t.IsRoot {
					user = "linnas"
					// check current non-root user if available
					if u := os.Getenv("USER"); u != "" && u != "root" {
						user = u
					}
				}
				fullCmd := t.Command
				if t.Args != "" {
					fullCmd += " " + t.Args
				}

				if !t.Enabled {
					sb.WriteString(fmt.Sprintf("# DISABLED_LINNAS: %s %s %s\n", t.Schedule, user, fullCmd))
				} else {
					sb.WriteString(fmt.Sprintf("%s %s %s\n", t.Schedule, user, fullCmd))
				}
			}

			_ = os.MkdirAll("/etc/cron.d", 0755)
			if os.Getuid() != 0 {
				cmd := exec.Command("sudo", "-n", "tee", "/etc/cron.d/linnas-cron")
				cmd.Stdin = strings.NewReader(sb.String())
				_ = cmd.Run()
			} else {
				_ = os.WriteFile("/etc/cron.d/linnas-cron", []byte(sb.String()), 0644)
			}
		}
	}
}

func parseSystemSMBConf() SMBData {
	var smbData SMBData
	var shares []SMBShare

	confPaths := []string{"/etc/samba/conf.d/shares.conf", "/etc/samba/smb.conf"}
	seenShares := make(map[string]bool)

	for _, confPath := range confPaths {
		contentBytes, err := os.ReadFile(confPath)
		if err != nil || len(contentBytes) == 0 {
			continue
		}

		lines := strings.Split(string(contentBytes), "\n")
		var currentShare *SMBShare

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}

			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				sectionName := strings.TrimSpace(line[1 : len(line)-1])
				lowerSec := strings.ToLower(sectionName)
				if lowerSec == "global" {
					currentShare = nil
					continue
				}
				if lowerSec == "homes" {
					smbData.HideHomes = true
					currentShare = nil
					continue
				}

				if seenShares[sectionName] {
					currentShare = nil
					continue
				}

				seenShares[sectionName] = true
				shares = append(shares, SMBShare{
					Name:     sectionName,
					Path:     "",
					Enabled:  true,
					ReadOnly: false,
				})
				currentShare = &shares[len(shares)-1]
			} else if currentShare != nil && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				val := strings.TrimSpace(parts[1])

				switch key {
				case "path":
					currentShare.Path = val
				case "comment":
					currentShare.Comment = val
				case "read only":
					currentShare.ReadOnly = (strings.ToLower(val) == "yes" || strings.ToLower(val) == "true" || val == "1")
				case "valid users":
					currentShare.ValidUsers = strings.Fields(val)
				case "available", "browseable":
					if strings.ToLower(val) == "no" || strings.ToLower(val) == "false" || val == "0" {
						currentShare.Enabled = false
					}
				}
			}
		}
	}

	var validShares []SMBShare
	for _, s := range shares {
		if s.Path != "" {
			validShares = append(validShares, s)
		}
	}

	smbData.Shares = validShares
	return smbData
}

func getBinaryDir() string {
	if exePath, err := os.Executable(); err == nil {
		if resolved, rErr := filepath.EvalSymlinks(exePath); rErr == nil {
			exePath = resolved
		}
		return filepath.Dir(exePath)
	}
	cwd, _ := os.Getwd()
	return cwd
}

func handlePluginData(w http.ResponseWriter, r *http.Request) {
	pluginID := r.URL.Query().Get("plugin")
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, pluginID); !matched || pluginID == "" {
		http.Error(w, "Invalid or missing plugin parameter", http.StatusBadRequest)
		return
	}

	// Persist JSON files in the same folder where the binary is
	binDir := getBinaryDir()
	persistentPath := filepath.Join(binDir, pluginID+".json")
	htmlPath := filepath.Join("html", pluginID, "data.json")

	switch r.Method {
	case http.MethodGet:
		dataBytes, err := os.ReadFile(persistentPath)
		if err != nil || len(dataBytes) == 0 {
			// Check legacy data/ dir if exists
			dataBytes, err = os.ReadFile(filepath.Join("data", pluginID+".json"))
		}
		if err != nil || len(dataBytes) == 0 {
			dataBytes, err = os.ReadFile(htmlPath)
		}

		// Provide in-code defaults if no file exists
		if (err != nil || len(dataBytes) == 0) && pluginID == "ufw" {
			// Single default entry for LinNAS in the firewall as code in the binary
			defaultUfw := map[string]interface{}{
				"rules": map[string]interface{}{
					"linnas": map[string]interface{}{
						"name":     "LinNAS",
						"disabled": false,
						"rawCmd":   fmt.Sprintf("ufw allow %d/tcp", appConfig.Port),
					},
				},
			}
			if defBytes, defErr := json.MarshalIndent(defaultUfw, "", "  "); defErr == nil {
				dataBytes = defBytes
				_ = os.WriteFile(persistentPath, defBytes, 0644)
			}
		}

		if pluginID == "smb" {
			var smbTest SMBData
			if err != nil || len(dataBytes) == 0 || json.Unmarshal(dataBytes, &smbTest) != nil || len(smbTest.Shares) == 0 {
				recovered := parseSystemSMBConf()
				if len(recovered.Shares) > 0 {
					if recBytes, err2 := json.MarshalIndent(recovered, "", "  "); err2 == nil {
						_ = os.MkdirAll("data", 0755)
						_ = os.WriteFile(persistentPath, recBytes, 0644)
						_ = os.MkdirAll(filepath.Dir(htmlPath), 0755)
						_ = os.WriteFile(htmlPath, recBytes, 0644)
						syncSystemConfigs("smb", recBytes)
						w.Header().Set("Content-Type", "application/json")
						w.Write(recBytes)
						return
					}
				}
			}
		}

		if err != nil || len(dataBytes) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(dataBytes)

	case http.MethodPost, http.MethodPut:
		if pluginID == "cron" && os.Getuid() != 0 {
			http.Error(w, "Root privileges required for cron operations", http.StatusForbidden)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		decryptedBody, err := decryptPayload(body)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
			return
		}

		var js json.RawMessage
		if err := json.Unmarshal(decryptedBody, &js); err != nil {
			http.Error(w, "Invalid JSON data", http.StatusBadRequest)
			return
		}

		_ = os.WriteFile(persistentPath, decryptedBody, 0644)

		_ = os.MkdirAll(filepath.Dir(htmlPath), 0755)
		_ = os.WriteFile(htmlPath, decryptedBody, 0644)

		// Sync data directly to system config files (/etc/samba, /etc/dnsmasq.d)
		syncSystemConfigs(pluginID, decryptedBody)

		jsonResponse(w, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleConsoleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Command == "" {
		http.Error(w, "Invalid JSON or empty command", http.StatusBadRequest)
		return
	}

	// Session token for working directory tracking
	sessKey := "default"
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		sessKey = cookie.Value
	}

	consoleDirsMu.Lock()
	currentDir, exists := consoleDirs[sessKey]
	if !exists || currentDir == "" {
		currentDir, _ = os.Getwd()
		if currentDir == "" {
			currentDir = "/"
		}
		consoleDirs[sessKey] = currentDir
	}
	consoleDirsMu.Unlock()

	// Flusher interface for streaming chunked HTTP responses
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Append pwd query to track working directory updates (e.g. cd /etc)
	wrappedCmd := req.Command + "\n echo '___PWD_MARKER___'\n pwd"

	var cmd *exec.Cmd
	if os.Getuid() != 0 {
		cmd = exec.Command("sudo", "-n", "sh", "-c", wrappedCmd)
	} else {
		cmd = exec.Command("sh", "-c", wrappedCmd)
	}

	if _, err := os.Stat(currentDir); err == nil {
		cmd.Dir = currentDir
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		_, _ = fmt.Fprintf(w, "Error creating stdin pipe: %v\n", err)
		return
	}
	activeStdinPipesMu.Lock()
	activeStdinPipes[sessKey] = stdinPipe
	activeStdinPipesMu.Unlock()
	defer func() {
		activeStdinPipesMu.Lock()
		delete(activeStdinPipes, sessKey)
		activeStdinPipesMu.Unlock()
		_ = stdinPipe.Close()
	}()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = fmt.Fprintf(w, "Error creating stdout pipe: %v\n", err)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_, _ = fmt.Fprintf(w, "Error creating stderr pipe: %v\n", err)
		return
	}

	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(w, "Error starting command: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream stdout and capture updated working directory
	go func() {
		defer wg.Done()
		var stdoutBuf bytes.Buffer
		buf := make([]byte, 1024)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				stdoutBuf.Write(chunk)

				// Strip ___PWD_MARKER___ from live output
				chunkStr := string(chunk)
				if strings.Contains(chunkStr, "___PWD_MARKER___") {
					parts := strings.Split(chunkStr, "___PWD_MARKER___")
					if len(parts[0]) > 0 {
						_, _ = w.Write([]byte(parts[0]))
						flusher.Flush()
					}
				} else if !strings.Contains(stdoutBuf.String(), "___PWD_MARKER___") {
					_, _ = w.Write(chunk)
					flusher.Flush()
				}
			}
			if err != nil {
				break
			}
		}

		fullOut := stdoutBuf.String()
		if idx := strings.Index(fullOut, "___PWD_MARKER___"); idx != -1 {
			pwdSection := strings.TrimSpace(fullOut[idx+len("___PWD_MARKER___"):])
			pwdLines := strings.Split(pwdSection, "\n")
			if len(pwdLines) > 0 {
				newPwd := strings.TrimSpace(pwdLines[0])
				if newPwd != "" {
					consoleDirsMu.Lock()
					consoleDirs[sessKey] = newPwd
					consoleDirsMu.Unlock()
				}
			}
		}
	}()

	// Stream stderr
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				break
			}
		}
	}()

	wg.Wait()
	_ = cmd.Wait()
}

func handleFileWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		FilePath string `json:"filepath"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.FilePath == "" {
		http.Error(w, "Invalid JSON body or missing filepath", http.StatusBadRequest)
		return
	}

	cleanPath := filepath.Clean(req.FilePath)

	// If running as non-root and path needs root permissions, fallback to sudo tee
	if os.Getuid() != 0 {
		cmd := exec.Command("sudo", "-n", "tee", cleanPath)
		cmd.Stdin = strings.NewReader(req.Content)
		outBytes, err := cmd.CombinedOutput()
		if err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "output": string(outBytes)})
			return
		}
	} else {
		if err := os.WriteFile(cleanPath, []byte(req.Content), 0644); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
	}

	jsonResponse(w, map[string]interface{}{"success": true, "path": cleanPath})
}

func handleFsMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Path == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	cleanPath := filepath.Clean(req.Path)
	if err := os.MkdirAll(cleanPath, 0755); err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	jsonResponse(w, map[string]interface{}{"success": true, "path": cleanPath})
}

func handleFsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || len(req.Paths) == 0 {
		http.Error(w, "Invalid JSON body or empty paths", http.StatusBadRequest)
		return
	}

	var errors []string
	for _, p := range req.Paths {
		clean := filepath.Clean(p)
		if clean == "/" || clean == "." {
			errors = append(errors, "Cannot delete root directory")
			continue
		}
		if os.Getuid() != 0 {
			cmd := exec.Command("sudo", "-n", "rm", "-rf", clean)
			if out, err := cmd.CombinedOutput(); err != nil {
				if err2 := os.RemoveAll(clean); err2 != nil {
					errors = append(errors, fmt.Sprintf("Failed to delete %s: %v (%s)", clean, err2, string(out)))
				}
			}
		} else {
			if err := os.RemoveAll(clean); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to delete %s: %v", clean, err.Error()))
			}
		}
	}

	if len(errors) > 0 {
		jsonResponse(w, map[string]interface{}{"success": false, "error": strings.Join(errors, "; ")})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleFsRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}
	var req struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.OldPath == "" || req.NewPath == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	oldClean := filepath.Clean(req.OldPath)
	newClean := filepath.Clean(req.NewPath)

	if os.Getuid() != 0 {
		cmd := exec.Command("sudo", "-n", "mv", oldClean, newClean)
		if out, err := cmd.CombinedOutput(); err != nil {
			if err2 := os.Rename(oldClean, newClean); err2 != nil {
				jsonResponse(w, map[string]interface{}{"success": false, "error": fmt.Sprintf("%v (%s)", err2, string(out))})
				return
			}
		}
	} else {
		if err := os.Rename(oldClean, newClean); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleFsCopy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}
	var req struct {
		Sources     []string `json:"sources"`
		Destination string   `json:"destination"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || len(req.Sources) == 0 || req.Destination == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	destClean := filepath.Clean(req.Destination)
	var errors []string
	for _, src := range req.Sources {
		srcClean := filepath.Clean(src)
		target := filepath.Join(destClean, filepath.Base(srcClean))
		if srcClean == target {
			target = target + "_copy"
		}

		var cmd *exec.Cmd
		if os.Getuid() != 0 {
			cmd = exec.Command("sudo", "-n", "cp", "-r", srcClean, target)
		} else {
			cmd = exec.Command("cp", "-r", srcClean, target)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			errors = append(errors, fmt.Sprintf("Failed copying %s to %s: %v (%s)", srcClean, target, err, string(out)))
		}
	}

	if len(errors) > 0 {
		jsonResponse(w, map[string]interface{}{"success": false, "error": strings.Join(errors, "; ")})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleFsMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}
	var req struct {
		Sources     []string `json:"sources"`
		Destination string   `json:"destination"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || len(req.Sources) == 0 || req.Destination == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	destClean := filepath.Clean(req.Destination)
	var errors []string
	for _, src := range req.Sources {
		srcClean := filepath.Clean(src)
		target := filepath.Join(destClean, filepath.Base(srcClean))

		var cmd *exec.Cmd
		if os.Getuid() != 0 {
			cmd = exec.Command("sudo", "-n", "mv", srcClean, target)
		} else {
			cmd = exec.Command("mv", srcClean, target)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			errors = append(errors, fmt.Sprintf("Failed moving %s to %s: %v (%s)", srcClean, target, err, string(out)))
		}
	}

	if len(errors) > 0 {
		jsonResponse(w, map[string]interface{}{"success": false, "error": strings.Join(errors, "; ")})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleFsChmod(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Paths     []string `json:"paths"`
		ModeOctal string   `json:"mode_octal"`
		Recursive bool     `json:"recursive"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || len(req.Paths) == 0 || req.ModeOctal == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if matched, _ := regexp.MatchString(`^[0-7]{3,4}$`, req.ModeOctal); !matched {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "Invalid octal permission mode"})
		return
	}

	var errors []string
	for _, p := range req.Paths {
		clean := filepath.Clean(p)
		args := []string{}
		if req.Recursive {
			args = append(args, "-R")
		}
		args = append(args, req.ModeOctal, clean)

		var cmd *exec.Cmd
		if os.Getuid() != 0 {
			sudoArgs := append([]string{"-n", "chmod"}, args...)
			cmd = exec.Command("sudo", sudoArgs...)
		} else {
			cmd = exec.Command("chmod", args...)
		}

		if out, err := cmd.CombinedOutput(); err != nil {
			errors = append(errors, fmt.Sprintf("Failed chmod on %s: %v (%s)", clean, err, string(out)))
		}
	}

	if len(errors) > 0 {
		jsonResponse(w, map[string]interface{}{"success": false, "error": strings.Join(errors, "; ")})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleFsChown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Paths     []string `json:"paths"`
		Owner     string   `json:"owner"`
		Group     string   `json:"group"`
		Recursive bool     `json:"recursive"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || len(req.Paths) == 0 {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	ownerGroup := req.Owner
	if req.Group != "" {
		ownerGroup = fmt.Sprintf("%s:%s", req.Owner, req.Group)
	}

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-\.:]+$`, ownerGroup); !matched || ownerGroup == "" {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "Invalid owner or group specification"})
		return
	}

	var errors []string
	for _, p := range req.Paths {
		clean := filepath.Clean(p)
		args := []string{}
		if req.Recursive {
			args = append(args, "-R")
		}
		args = append(args, ownerGroup, clean)

		var cmd *exec.Cmd
		if os.Getuid() != 0 {
			sudoArgs := append([]string{"-n", "chown"}, args...)
			cmd = exec.Command("sudo", sudoArgs...)
		} else {
			cmd = exec.Command("chown", args...)
		}

		if out, err := cmd.CombinedOutput(); err != nil {
			errors = append(errors, fmt.Sprintf("Failed chown on %s: %v (%s)", clean, err, string(out)))
		}
	}

	if len(errors) > 0 {
		jsonResponse(w, map[string]interface{}{"success": false, "error": strings.Join(errors, "; ")})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": true})
}

func handleFsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Path       string `json:"path"`
		ContentB64 string `json:"content_b64"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Path == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	cleanPath := filepath.Clean(req.Path)
	data, err := base64.StdEncoding.DecodeString(req.ContentB64)
	if err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "Invalid base64 encoding"})
		return
	}

	if os.Getuid() != 0 {
		cmd := exec.Command("sudo", "-n", "tee", cleanPath)
		cmd.Stdin = bytes.NewReader(data)
		if out, err := cmd.CombinedOutput(); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": fmt.Sprintf("%v (%s)", err, string(out))})
			return
		}
	} else {
		if err := os.WriteFile(cleanPath, data, 0644); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
	}

	jsonResponse(w, map[string]interface{}{"success": true, "path": cleanPath})
}

func handleFsRaw(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "Missing path parameter", http.StatusBadRequest)
		return
	}
	cleanPath := filepath.Clean(filePath)

	file, err := os.Open(cleanPath)
	if err == nil {
		defer file.Close()
		stat, errStat := file.Stat()
		if errStat == nil && !stat.IsDir() {
			w.Header().Set("Cache-Control", "no-cache")
			ext := strings.ToLower(filepath.Ext(cleanPath))
			switch ext {
			case ".mp4":
				w.Header().Set("Content-Type", "video/mp4")
			case ".webm":
				w.Header().Set("Content-Type", "video/webm")
			case ".ogg", ".ogv":
				w.Header().Set("Content-Type", "video/ogg")
			case ".mkv":
				w.Header().Set("Content-Type", "video/x-matroska")
			case ".mov":
				w.Header().Set("Content-Type", "video/quicktime")
			case ".svg":
				w.Header().Set("Content-Type", "image/svg+xml")
			case ".webp":
				w.Header().Set("Content-Type", "image/webp")
			}
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), file)
			return
		}
	}

	// Fallback to cat / reading if os.Open fails
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.Getuid() != 0 {
			cmd := exec.Command("sudo", "-n", "cat", cleanPath)
			out, err2 := cmd.CombinedOutput()
			if err2 != nil {
				http.Error(w, "Failed to read file: "+err.Error(), http.StatusNotFound)
				return
			}
			data = out
		} else {
			http.Error(w, "Failed to read file: "+err.Error(), http.StatusNotFound)
			return
		}
	}

	contentType := http.DetectContentType(data)
	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case ".svg":
		contentType = "image/svg+xml"
	case ".webp":
		contentType = "image/webp"
	case ".mp4":
		contentType = "video/mp4"
	case ".webm":
		contentType = "video/webm"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

func handleFsBrowse(w http.ResponseWriter, r *http.Request) {
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}

	dirPath = filepath.Clean(dirPath)
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		jsonResponse(w, map[string]interface{}{"error": err.Error(), "path": dirPath, "items": []FileEntry{}})
		return
	}

	var items []FileEntry
	for _, entry := range entries {
		info, err := entry.Info()
		size := int64(0)
		permStr := "rw-r--r--"
		octalStr := "0644"
		if err == nil {
			size = info.Size()
			permStr = info.Mode().String()
			octalStr = fmt.Sprintf("%04o", info.Mode().Perm())
		}
		items = append(items, FileEntry{
			Name:        entry.Name(),
			Path:        filepath.Join(dirPath, entry.Name()),
			IsDir:       entry.IsDir(),
			Size:        size,
			Permissions: permStr,
			ModeOctal:   octalStr,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir // folders first (true < false is false, so true comes first)
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	parent := filepath.Dir(dirPath)

	// Query filesystem type of the directory
	fsType := "ext4"
	if out, err := exec.Command("stat", "-f", "-c", "%T", dirPath).Output(); err == nil {
		fsType = strings.TrimSpace(string(out))
	}

	jsonResponse(w, map[string]interface{}{
		"path":    dirPath,
		"parent":  parent,
		"fs_type": fsType,
		"items":   items,
	})
}

func handleDNSConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	rawInput := string(bodyBytes)
	lines := strings.Split(rawInput, "\n")
	var converted []string

	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			domain := line[2 : len(line)-1]
			if domainRegex.MatchString(domain) {
				converted = append(converted, fmt.Sprintf("address=/%s/0.0.0.0", domain))
			}
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := parts[1]
			if domainRegex.MatchString(domain) {
				converted = append(converted, fmt.Sprintf("address=/%s/0.0.0.0", domain))
				continue
			}
		}

		if domainRegex.MatchString(line) {
			converted = append(converted, fmt.Sprintf("address=/%s/0.0.0.0", line))
		}
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"count":   len(converted),
		"result":  strings.Join(converted, "\n"),
	})
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func logStartupEvent(msg string) {
	entry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	log.Print(entry)
	if isAutostartMode || appConfig.FeatureToggles["debug_startup"] != false {
		f, err := os.OpenFile("autostart_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			_, _ = f.WriteString(entry)
			_ = f.Close()
		}
	}
}

func restoreEmbeddedPlugins(forceOverwrite bool) error {
	logStartupEvent("Restoring default embedded html/ assets and plugin files...")
	err := fs.WalkDir(embeddedHTML, "html", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(path, 0755)
		}

		data, err := embeddedHTML.ReadFile(path)
		if err != nil {
			return err
		}

		if !forceOverwrite {
			// Don't overwrite existing user files if forceOverwrite is false
			if _, err := os.Stat(path); err == nil {
				return nil
			}
		}

		_ = os.MkdirAll(filepath.Dir(path), 0755)
		return os.WriteFile(path, data, 0644)
	})

	if err != nil {
		logStartupEvent(fmt.Sprintf("Error extracting embedded HTML: %v", err))
		return err
	}
	logStartupEvent("Successfully extracted default embedded html/ assets.")
	return nil
}

func extractEmbeddedHTML() {
	// If html/ exists and contains index.htm, assume disk assets are present
	if _, err := os.Stat(filepath.Join("html", "index.htm")); err == nil {
		return
	}
	_ = restoreEmbeddedPlugins(false)
}

func ensureWorkingDirectory() {
	cwd, _ := os.Getwd()
	// 1. Check if html directory exists in current working directory
	if _, err := os.Stat("html"); err == nil {
		logStartupEvent(fmt.Sprintf("Working directory verified: %s", cwd))
		return
	}

	// 2. Check directory of the running executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		if _, err := os.Stat(filepath.Join(execDir, "html")); err == nil {
			_ = os.Chdir(execDir)
			logStartupEvent(fmt.Sprintf("Switched working directory from %s to executable directory: %s", cwd, execDir))
			return
		}
	}
	logStartupEvent(fmt.Sprintf("No 'html/' directory found in %s; will extract embedded assets.", cwd))
}

func handleStartupIssues(w http.ResponseWriter, r *http.Request) {
	logBytes, err := os.ReadFile("autostart_debug.log")
	logStr := ""
	hasIssues := false
	if err == nil && len(logBytes) > 0 {
		logStr = string(logBytes)
		hasIssues = true
	}
	jsonResponse(w, map[string]interface{}{
		"has_issues":     hasIssues,
		"log":            logStr,
		"autostart_mode": isAutostartMode,
		"debug_enabled":  appConfig.FeatureToggles["debug_startup"] != false,
	})
}

func handleStartupClear(w http.ResponseWriter, r *http.Request) {
	_ = os.Remove("autostart_debug.log")
	jsonResponse(w, map[string]interface{}{"success": true})
}

func main() {
	var flagHelp, flagQuit, flagBg, flagAutostart bool
	flag.BoolVar(&flagHelp, "h", false, "Show help and usage information")
	flag.BoolVar(&flagQuit, "q", false, "Terminate running LinNAS background processes")
	flag.BoolVar(&flagBg, "b", false, "Run LinNAS in background mode")
	flag.BoolVar(&flagAutostart, "a", false, "Identify systemd autostart boot execution and log startup debug diagnostics")
	flag.Parse()

	if flagAutostart {
		isAutostartMode = true
	}

	ensureWorkingDirectory()
	extractEmbeddedHTML()

	if flagAutostart {
		logStartupEvent("=== LinNAS Systemd Autostart Boot Execution Started (-a) ===")
	}

	if flagHelp {
		fmt.Println("LinNAS - Lightweight Server Control Panel")
		fmt.Println("Usage: linnas [options]")
		fmt.Println("Options:")
		fmt.Println("  -h   Show this help message and exit")
		fmt.Println("  -q   Terminate any running LinNAS processes and exit")
		fmt.Println("  -b   Run LinNAS in background daemon mode")
		os.Exit(0)
	}

	if flagQuit {
		fmt.Println("Terminating running LinNAS processes...")
		_ = exec.Command("pkill", "-f", "linnas").Run()
		_ = exec.Command("pkill", "-f", "debian-server-manager").Run()
		fmt.Println("Done.")
		os.Exit(0)
	}

	if flagBg {
		if os.Getenv("LINNAS_BG") != "1" {
			executable, err := os.Executable()
			if err != nil {
				executable = os.Args[0]
			}
			var args []string
			for _, arg := range os.Args[1:] {
				if arg != "-b" {
					args = append(args, arg)
				}
			}
			cmd := exec.Command(executable, args...)
			cmd.Env = append(os.Environ(), "LINNAS_BG=1")
			if err := cmd.Start(); err != nil {
				log.Fatalf("Failed to start LinNAS in background: %v", err)
			}
			fmt.Printf("LinNAS started in background (PID %d)\n", cmd.Process.Pid)
			os.Exit(0)
		}
	}

	if os.Getuid() != 0 {
		fmt.Println("⚠️  Warning: LinNAS is running as a non-root user.")
		fmt.Println("   Administrative functionality (APT manager, systemd boot service, UFW firewall, drive mounts) will be limited or hidden.")
		fmt.Println("   To unlock all features, consider running LinNAS as root (e.g. `sudo ./linnas`).")
	}

	loadConfig()

	_ = os.MkdirAll("html", 0755)
	// Sync SMB config at startup if data exists or recover from system config
	binDir := getBinaryDir()
	var smbBytes []byte
	if b, err := os.ReadFile(filepath.Join(binDir, "smb.json")); err == nil && len(b) > 0 {
		smbBytes = b
	} else if b, err := os.ReadFile("data/smb.json"); err == nil && len(b) > 0 {
		smbBytes = b
	} else if b, err := os.ReadFile("html/smb/data.json"); err == nil && len(b) > 0 {
		smbBytes = b
	}

	var smbCheck SMBData
	if len(smbBytes) == 0 || json.Unmarshal(smbBytes, &smbCheck) != nil || len(smbCheck.Shares) == 0 {
		recovered := parseSystemSMBConf()
		if len(recovered.Shares) > 0 {
			if recBytes, err := json.MarshalIndent(recovered, "", "  "); err == nil {
				smbBytes = recBytes
				_ = os.WriteFile(filepath.Join(binDir, "smb.json"), recBytes, 0644)
				_ = os.MkdirAll("html/smb", 0755)
				_ = os.WriteFile("html/smb/data.json", recBytes, 0644)
			}
		}
	}

	if len(smbBytes) > 0 {
		syncSystemConfigs("smb", smbBytes)
	}

	loadCloudConfig()

	mux := http.NewServeMux()

	// API Endpoints protected by authMiddleware
	initRSAKeys()

	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/auth/status", handleAuthStatus)
	mux.HandleFunc("/api/crypto/pubkey", handleCryptoPubKey)
	mux.HandleFunc("/api/auth/password", authMiddleware(handlePasswordChange))
	// Public status execution helper for pre-login status view
	publicExecMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !isAuthorized(r) {
				// Allow read-only status queries pre-login
				if r.URL.Path == "/api/plugins" {
					next(w, r)
					return
				}
			}
			authMiddleware(next)(w, r)
		}
	}

	mux.HandleFunc("/api/plugins", publicExecMiddleware(handleListPlugins))
	mux.HandleFunc("/api/plugin/exec/stream", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		handleExecPluginCmdStream(w, r)
	})
	mux.HandleFunc("/api/plugin/exec", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(r) {
			// Allow read-only status queries when unauthenticated
			var req ExecRequest
			bodyBytes, readErr := io.ReadAll(r.Body)
			if readErr == nil {
				decBytes, _ := decryptPayload(bodyBytes)
				_ = json.Unmarshal(decBytes, &req)
				r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
				if req.Plugin == "status" && (req.CmdKey == "sys_info_cmd" || req.CmdKey == "disk_space_cmd" || req.CmdKey == "smart_health_sudo" || req.CmdKey == "service_status_cmd") {
					handleExecPluginCmd(w, r)
					return
				}
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		handleExecPluginCmd(w, r)
	})
	mux.HandleFunc("/api/plugin/data", authMiddleware(handlePluginData))
	mux.HandleFunc("/api/fs/raw", authMiddleware(handleFsRaw))
	mux.HandleFunc("/api/fs/browse", authMiddleware(handleFsBrowse))
	mux.HandleFunc("/api/fs/mkdir", authMiddleware(handleFsMkdir))
	mux.HandleFunc("/api/fs/delete", authMiddleware(handleFsDelete))
	mux.HandleFunc("/api/fs/rename", authMiddleware(handleFsRename))
	mux.HandleFunc("/api/fs/copy", authMiddleware(handleFsCopy))
	mux.HandleFunc("/api/fs/move", authMiddleware(handleFsMove))
	mux.HandleFunc("/api/fs/chmod", authMiddleware(handleFsChmod))
	mux.HandleFunc("/api/fs/chown", authMiddleware(handleFsChown))
	mux.HandleFunc("/api/fs/upload", authMiddleware(handleFsUpload))
	mux.HandleFunc("/api/file/write", authMiddleware(handleFileWrite))
	mux.HandleFunc("/api/startup/issues", authMiddleware(handleStartupIssues))
	mux.HandleFunc("/api/startup/clear", authMiddleware(handleStartupClear))
	mux.HandleFunc("/api/plugins/restore", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := restoreEmbeddedPlugins(true); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		jsonResponse(w, map[string]interface{}{"success": true, "message": "Successfully restored default plugins from embedded application binary."})
	}))
	mux.HandleFunc("/api/console/stream", authMiddleware(handleConsoleStream))
	mux.HandleFunc("/api/console/input", authMiddleware(handleConsoleInput))
		mux.HandleFunc("/api/sources/get", authMiddleware(handleSourcesGet))
	mux.HandleFunc("/api/sources/test", authMiddleware(handleSourcesTest))
	mux.HandleFunc("/api/sources/apply", authMiddleware(handleSourcesApply))
	mux.HandleFunc("/api/app/path", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		exePath, err := os.Executable()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
		jsonResponse(w, map[string]interface{}{"path": exePath})
	}))
	mux.HandleFunc("/api/cron/run", authMiddleware(handleCronRun))
	mux.HandleFunc("/api/cron/stop", authMiddleware(handleCronStop))
	mux.HandleFunc("/api/dns/convert", authMiddleware(handleDNSConvert))

	// Local Cloud endpoints
	mux.HandleFunc("/api/cloud/status", authMiddleware(handleCloudStatus))
	mux.HandleFunc("/api/cloud/config", authMiddleware(handleCloudConfig))
	mux.HandleFunc("/api/cloud/list", authMiddleware(handleCloudList))
	mux.HandleFunc("/api/cloud/save", authMiddleware(handleCloudSave))
	mux.HandleFunc("/api/cloud/load", authMiddleware(handleCloudLoad))
	mux.HandleFunc("/api/cloud/delete", authMiddleware(handleCloudDelete))
	mux.HandleFunc("/api/cloud/mkdir", authMiddleware(handleCloudMkdir))
	mux.HandleFunc("/api/cloud/smart", authMiddleware(handleCloudSmart))
	mux.HandleFunc("/api/cloud/smart/test_toggle", authMiddleware(handleCloudSmartTestToggle))
	mux.HandleFunc("/api/settings/get", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			"port":            appConfig.Port,
			"username":        appConfig.Username,
			"feature_toggles": appConfig.FeatureToggles,
		})
	}))
	mux.HandleFunc("/api/settings/toggle", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		decrypted, _ := decryptPayload(body)
		var req struct {
			Feature string `json:"feature"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.Unmarshal(decrypted, &req); err != nil || req.Feature == "" {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		if appConfig.FeatureToggles == nil {
			appConfig.FeatureToggles = make(map[string]bool)
		}
		appConfig.FeatureToggles[req.Feature] = req.Enabled
		_ = saveLinnasDataEx(appConfig.Username, appConfig.PasswordHash, appConfig.Port, appConfig.FeatureToggles)
		jsonResponse(w, map[string]interface{}{"success": true, "feature_toggles": appConfig.FeatureToggles})
	}))
	mux.HandleFunc("/api/settings/port", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		decrypted, _ := decryptPayload(body)
		var req struct {
			Port int `json:"port"`
		}
		if err := json.Unmarshal(decrypted, &req); err != nil || req.Port <= 1024 || req.Port > 65535 {
			jsonResponse(w, map[string]interface{}{"success": false, "error": "Invalid port number. Must be between 1025 and 65535."})
			return
		}

		oldPort := appConfig.Port
		newPort := req.Port

		// Allow new port in ufw first to prevent lockout
		if os.Getuid() == 0 {
			_ = exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", newPort)).Run()
		} else {
			_ = exec.Command("sudo", "-n", "ufw", "allow", fmt.Sprintf("%d/tcp", newPort)).Run()
		}

		_ = saveLinnasDataEx(appConfig.Username, appConfig.PasswordHash, newPort, appConfig.FeatureToggles)

		jsonResponse(w, map[string]interface{}{
			"success": true,
			"old_port": oldPort,
			"new_port": newPort,
			"message": fmt.Sprintf("Port changed from %d to %d. UFW rule added. Please restart server or connect via new port.", oldPort, newPort),
		})
	}))

	// Static HTML File server protected by authMiddleware
	fileServer := http.FileServer(http.Dir("html"))
	mux.Handle("/", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join("html", "index.htm"))
			return
		}
		fileServer.ServeHTTP(w, r)
	})))

	addr := fmt.Sprintf(":%d", appConfig.Port)
	log.Printf("Starting LinNAS on http://localhost%s (Running as Root: %v)", addr, os.Getuid() == 0)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}


func handleConsoleInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	sessKey := "default"
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		sessKey = cookie.Value
	}

	activeStdinPipesMu.Lock()
	pipe, exists := activeStdinPipes[sessKey]
	activeStdinPipesMu.Unlock()

	if !exists || pipe == nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "No running command to receive input"})
		return
	}

	data := []byte(req.Input + "\n")
	if _, err := pipe.Write(data); err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	jsonResponse(w, map[string]interface{}{"success": true})
}


func handleSourcesGet(w http.ResponseWriter, r *http.Request) {
	sourcesContent := ""
	sourcesFile := "/etc/apt/sources.list"
	if data, err := os.ReadFile(sourcesFile); err == nil {
		sourcesContent = string(data)
	} else if data, err := os.ReadFile("/etc/apt/sources.list.d/ubuntu.sources"); err == nil {
		sourcesFile = "/etc/apt/sources.list.d/ubuntu.sources"
		sourcesContent = string(data)
	} else if data, err := os.ReadFile("/etc/apt/sources.list.d/debian.sources"); err == nil {
		sourcesFile = "/etc/apt/sources.list.d/debian.sources"
		sourcesContent = string(data)
	}

	mirrors := []map[string]string{
		{"name": "Global Official (deb.debian.org)", "url": "http://deb.debian.org/debian", "country": "Global"},
		{"name": "Cloudflare CDN Mirror", "url": "https://mirrors.cloudflare.com/debian", "country": "Global"},
		{"name": "University of Waterloo (Ontario)", "url": "http://mirror.cs.uwaterloo.ca/debian", "country": "Canada"},
		{"name": "Simon Fraser University (Burnaby, BC)", "url": "http://mirror.its.sfu.ca/mirror/debian", "country": "Canada"},
		{"name": "Dalhousie University (Nova Scotia)", "url": "http://debian.mirror.rafal.ca/debian", "country": "Canada"},
		{"name": "CIX (Toronto, Ontario)", "url": "http://debian.mirror.iweb.ca/debian", "country": "Canada"},
		{"name": "Kernel.org Mirror", "url": "http://mirrors.kernel.org/debian", "country": "United States"},
		{"name": "MIT (Massachusetts)", "url": "http://mirrors.mit.edu/debian", "country": "United States"},
		{"name": "Princeton University (New Jersey)", "url": "http://mirror.math.princeton.edu/pub/debian", "country": "United States"},
		{"name": "LeaseWeb US Mirror", "url": "http://mirror.us.leaseweb.net/debian", "country": "United States"},
		{"name": "LeaseWeb NL Mirror", "url": "http://mirror.nl.leaseweb.net/debian", "country": "Netherlands"},
		{"name": "IRCAM Mirror (France)", "url": "http://mirrors.ircam.fr/pub/debian", "country": "France"},
		{"name": "FAU Erlangen (Germany)", "url": "http://ftp.fau.de/debian", "country": "Germany"},
		{"name": "University of Kent (UK)", "url": "http://www.mirrorservice.org/sites/ftp.debian.org/debian", "country": "United Kingdom"},
		{"name": "Yamagata University (Japan)", "url": "http://ftp.yz.yamagata-u.ac.jp/pub/linux/debian", "country": "Japan"},
		{"name": "AARNet (Australia)", "url": "http://mirror.aarnet.edu.au/pub/debian", "country": "Australia"},
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"active_file": sourcesFile,
		"content": sourcesContent,
		"mirrors": mirrors,
	})
}

func handleSourcesTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.URL == "" {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Benchmark HTTP HEAD / GET latency
	client := http.Client{
		Timeout: 4 * time.Second,
	}
	targetURL := strings.TrimRight(req.URL, "/") + "/project/trace/master"
	start := time.Now()
	resp, err := client.Get(targetURL)
	if err != nil {
		// Fallback to testing base URL
		start = time.Now()
		resp, err = client.Get(req.URL)
	}

	if err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "speed": "Timeout / Unreachable"})
		return
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	var speedRating string
	latencyMs := elapsed.Milliseconds()
	if latencyMs < 80 {
		speedRating = fmt.Sprintf("%d ms (Very Fast - Excellent)", latencyMs)
	} else if latencyMs < 200 {
		speedRating = fmt.Sprintf("%d ms (Fast - Good)", latencyMs)
	} else if latencyMs < 450 {
		speedRating = fmt.Sprintf("%d ms (Moderate)", latencyMs)
	} else {
		speedRating = fmt.Sprintf("%d ms (Slow)", latencyMs)
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"latency_ms": latencyMs,
		"speed": speedRating,
		"status": resp.StatusCode,
	})
}

func handleSourcesApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		MirrorURL string `json:"mirror_url"`
		Content   string `json:"content"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Target file
	sourcesFile := "/etc/apt/sources.list"
	if _, err := os.Stat("/etc/apt/sources.list.d/ubuntu.sources"); err == nil && !strings.Contains(req.MirrorURL, "debian") {
		sourcesFile = "/etc/apt/sources.list.d/ubuntu.sources"
	}

	// Backup original file
	backupFile := sourcesFile + ".bak." + time.Now().Format("20060102150405")
	if orig, err := os.ReadFile(sourcesFile); err == nil {
		_ = os.WriteFile(backupFile, orig, 0644)
	}

	newContent := req.Content
	if newContent == "" && req.MirrorURL != "" {
		m := strings.TrimRight(req.MirrorURL, "/")
		newContent = fmt.Sprintf(
			"deb %s bookworm main non-free-firmware contrib non-free\n" +
			"deb-src %s bookworm main non-free-firmware contrib non-free\n\n" +
			"deb %s bookworm-updates main non-free-firmware contrib non-free\n" +
			"deb-src %s bookworm-updates main non-free-firmware contrib non-free\n\n" +
			"deb http://security.debian.org/debian-security bookworm-security main non-free-firmware contrib non-free\n" +
			"deb-src http://security.debian.org/debian-security bookworm-security main non-free-firmware contrib non-free\n",
			m, m, m, m,
		)
	}

	if os.Getuid() != 0 {
		cmd := exec.Command("sudo", "-n", "tee", sourcesFile)
		cmd.Stdin = strings.NewReader(newContent)
		if out, err := cmd.CombinedOutput(); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": fmt.Sprintf("Failed to write %s: %v (%s)", sourcesFile, err, string(out))})
			return
		}
	} else {
		if err := os.WriteFile(sourcesFile, []byte(newContent), 0644); err != nil {
			jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully applied new mirror source to %s. Backup created at %s", sourcesFile, backupFile),
		"backup": backupFile,
	})
}

var (
	cronProcessesLock sync.Mutex
	cronProcesses     = make(map[string]*exec.Cmd)
)

func handleCronRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		ID      string `json:"id"`
		Command string `json:"command"`
		Args    string `json:"args"`
		IsRoot  bool   `json:"is_root"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Command == "" {
		http.Error(w, "Invalid request or missing command", http.StatusBadRequest)
		return
	}

	fullCmd := req.Command
	if req.Args != "" {
		fullCmd += " " + req.Args
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, canFlush := w.(http.Flusher)

	var cmd *exec.Cmd
	if req.IsRoot && os.Getuid() != 0 {
		cmd = exec.Command("sudo", "-n", "bash", "-c", fullCmd)
	} else {
		cmd = exec.Command("bash", "-c", fullCmd)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	taskId := req.ID
	if taskId == "" {
		taskId = fmt.Sprintf("cron_%d", time.Now().UnixNano())
	}

	cronProcessesLock.Lock()
	cronProcesses[taskId] = cmd
	cronProcessesLock.Unlock()

	defer func() {
		cronProcessesLock.Lock()
		delete(cronProcesses, taskId)
		cronProcessesLock.Unlock()
	}()

	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(w, "Failed to start command: %v\n", err)
		if canFlush {
			flusher.Flush()
		}
		return
	}

	multiReader := io.MultiReader(stdoutPipe, stderrPipe)
	buf := make([]byte, 1024)
	for {
		n, rErr := multiReader.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			if canFlush {
				flusher.Flush()
			}
		}
		if rErr != nil {
			break
		}
	}

	waitErr := cmd.Wait()
	if waitErr != nil {
		_, _ = fmt.Fprintf(w, "\n[Process exited with error: %v]\n", waitErr)
	} else {
		_, _ = fmt.Fprintf(w, "\n[Process completed successfully]\n")
	}
	if canFlush {
		flusher.Flush()
	}
}

func handleCronStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	decryptedBody, err := decryptPayload(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.ID == "" {
		http.Error(w, "Invalid request or missing ID", http.StatusBadRequest)
		return
	}

	cronProcessesLock.Lock()
	cmd, exists := cronProcesses[req.ID]
	cronProcessesLock.Unlock()

	if !exists || cmd == nil || cmd.Process == nil {
		jsonResponse(w, map[string]interface{}{"success": true, "message": "No active process found for task"})
		return
	}

	_ = cmd.Process.Kill()
	jsonResponse(w, map[string]interface{}{"success": true, "message": "Process terminated"})
}

// ---------------------------------------------------------
// Local Cloud Server Plugin Logic & Endpoints
// ---------------------------------------------------------

func getCloudConfigPath() string {
	return filepath.Join(getBinaryDir(), "cloud.json")
}

func loadCloudConfig() {
	cloudConfigMu.Lock()
	defer cloudConfigMu.Unlock()
	b, err := os.ReadFile(getCloudConfigPath())
	if err != nil || len(b) == 0 {
		// check legacy location
		b, err = os.ReadFile("data/cloud.json")
	}
	if err == nil && len(b) > 0 {
		var cfg CloudConfig
		if err := json.Unmarshal(b, &cfg); err == nil {
			cloudConfig = cfg
		}
	}
}

func saveCloudConfig(cfg CloudConfig) error {
	cloudConfigMu.Lock()
	defer cloudConfigMu.Unlock()
	cfg.UpdatedAt = time.Now().Format(time.RFC3339)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(getCloudConfigPath(), b, 0644); err != nil {
		return err
	}
	cloudConfig = cfg
	return nil
}

func getPrimaryIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
					return ip.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func getPrimaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	// Prefer non-loopback up interfaces with hardware address
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 && len(iface.HardwareAddr) > 0 {
			mac := strings.ToLower(strings.ReplaceAll(iface.HardwareAddr.String(), ":", ""))
			if mac != "" {
				return mac
			}
		}
	}
	// Fallback to any interface with MAC
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) > 0 {
			mac := strings.ToLower(strings.ReplaceAll(iface.HardwareAddr.String(), ":", ""))
			if mac != "" {
				return mac
			}
		}
	}
	return "000000000000"
}

func getVolumeUUID(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "unknown"
	}
	out, err := exec.Command("df", "-P", abs).CombinedOutput()
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return "unknown"
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 6 {
		return "unknown"
	}
	dev := fields[0]
	cmd := exec.Command("lsblk", "-no", "UUID", dev)
	uuidOut, err := cmd.Output()
	uuid := strings.TrimSpace(string(uuidOut))
	if err == nil && uuid != "" {
		return uuid
	}
	return dev
}

func recordCloudActivity() {
	cloudActivityMu.Lock()
	cloudLastActivity = time.Now()
	cloudActivityMu.Unlock()
}

func acquireCloudFileLock(relPath string) bool {
	clean := filepath.Clean(relPath)
	cloudFileLocksMu.Lock()
	defer cloudFileLocksMu.Unlock()
	if cloudFileLocks[clean] {
		return false
	}
	cloudFileLocks[clean] = true
	return true
}

func releaseCloudFileLock(relPath string) {
	clean := filepath.Clean(relPath)
	cloudFileLocksMu.Lock()
	defer cloudFileLocksMu.Unlock()
	delete(cloudFileLocks, clean)
}

func safeCloudPath(rootFolder, userRelPath string) (string, string, error) {
	trimmed := strings.TrimSpace(userRelPath)
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") || filepath.IsAbs(trimmed) {
		return "", "", fmt.Errorf("absolute path forbidden, relative path required: %s", userRelPath)
	}

	cleanRel := filepath.Clean(trimmed)
	cleanRel = strings.TrimPrefix(cleanRel, "/")
	cleanRel = strings.TrimPrefix(cleanRel, "\\")
	if cleanRel == "." || cleanRel == "" {
		cleanRel = ""
	}
	if strings.HasPrefix(cleanRel, "..") || strings.Contains(cleanRel, "/../") || strings.Contains(cleanRel, `\..\`) {
		return "", "", fmt.Errorf("path traversal forbidden: %s", userRelPath)
	}

	absRoot, err := filepath.Abs(rootFolder)
	if err != nil {
		return "", "", fmt.Errorf("invalid cloud root directory: %v", err)
	}

	target := filepath.Join(absRoot, cleanRel)
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("invalid path: %v", err)
	}

	if absTarget != absRoot && !strings.HasPrefix(absTarget, absRoot+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path traversal escape detected: %s", userRelPath)
	}

	// Forbid access to internal metadata
	if strings.HasPrefix(cleanRel, ".cloud_meta") || strings.Contains(cleanRel, "/.cloud_meta") || strings.Contains(cleanRel, `\.cloud_meta`) {
		return "", "", fmt.Errorf("access to internal metadata directory forbidden")
	}

	return absTarget, cleanRel, nil
}

func getCloudMetaFilePath(rootFolder, relSubdir string) string {
	mac := getPrimaryMAC()
	filename := fmt.Sprintf(".cloud-%s.json", mac)
	metaDir := filepath.Join(rootFolder, ".cloud_meta")
	if relSubdir != "" && relSubdir != "." {
		metaDir = filepath.Join(metaDir, relSubdir)
	}
	return filepath.Join(metaDir, filename)
}

func loadCloudDirMeta(rootFolder, relSubdir string) CloudDirMeta {
	metaFile := getCloudMetaFilePath(rootFolder, relSubdir)
	var meta CloudDirMeta
	meta.Directory = relSubdir
	meta.ServerMAC = getPrimaryMAC()
	meta.VolumeUUID = getVolumeUUID(rootFolder)
	meta.Files = make(map[string]CloudMetaFile)
	meta.Deleted = make(map[string]int64)
	meta.History = make([]CloudHistoryEntry, 0)

	b, err := os.ReadFile(metaFile)
	if err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &meta)
		if meta.Files == nil {
			meta.Files = make(map[string]CloudMetaFile)
		}
		if meta.Deleted == nil {
			meta.Deleted = make(map[string]int64)
		}
		if meta.History == nil {
			meta.History = make([]CloudHistoryEntry, 0)
		}
	}
	return meta
}

func saveCloudDirMeta(rootFolder, relSubdir string, meta CloudDirMeta) error {
	metaFile := getCloudMetaFilePath(rootFolder, relSubdir)
	_ = os.MkdirAll(filepath.Dir(metaFile), 0755)
	meta.LastScan = time.Now().Format(time.RFC3339)
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaFile, b, 0644)
}

func calculateFileSHA256(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sendCloudJSONResponse(w http.ResponseWriter, r *http.Request, aesKey []byte, data interface{}) {
	rawJSON, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(aesKey) > 0 {
		encResp, err := encryptResponseWithAES(aesKey, rawJSON)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(encResp)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rawJSON)
}

// HTTP Handlers for Local Cloud Server

func handleCloudStatus(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	cloudConfigMu.RLock()
	cfg := cloudConfig
	cloudConfigMu.RUnlock()

	cloudActivityMu.RLock()
	lastAct := cloudLastActivity
	cloudActivityMu.RUnlock()

	activeSecondsAgo := -1
	if !lastAct.IsZero() {
		activeSecondsAgo = int(time.Since(lastAct).Seconds())
	}

	currentUUID := ""
	folderExists := false
	if cfg.Folder != "" {
		if fi, err := os.Stat(cfg.Folder); err == nil && fi.IsDir() {
			folderExists = true
			currentUUID = getVolumeUUID(cfg.Folder)
		}
	}

	cloudFileLocksMu.Lock()
	activeLocksCount := len(cloudFileLocks)
	cloudFileLocksMu.Unlock()

	mac := getPrimaryMAC()

	primaryIP := getPrimaryIP()
	serverEndpoint := fmt.Sprintf("%s:%d", primaryIP, appConfig.Port)

	jsonResponse(w, map[string]interface{}{
		"success":            true,
		"enabled":            cfg.Enabled,
		"folder":             cfg.Folder,
		"folder_exists":      folderExists,
		"configured_uuid":    cfg.VolumeUUID,
		"current_uuid":       currentUUID,
		"uuid_matches":       cfg.VolumeUUID == "" || cfg.VolumeUUID == currentUUID,
		"server_mac":         mac,
		"server_ip":          primaryIP,
		"server_port":        appConfig.Port,
		"server_endpoint":    serverEndpoint,
		"active_file_locks":  activeLocksCount,
		"last_activity_sec":  activeSecondsAgo,
		"activity_flicker":   activeSecondsAgo >= 0 && activeSecondsAgo < 3,
	})
}

type SmartDiskInfo struct {
	Device        string `json:"device"`
	FirstPartName string `json:"first_part_name,omitempty"` // e.g. "sda1" or "vda1"
	Model         string `json:"model"`
	Capacity      string `json:"capacity"`
	Health        string `json:"health"` // "PASSED", "FAILED", "UNKNOWN"
	TempC         int    `json:"temp_c,omitempty"`
	RawInfo       string `json:"raw_info,omitempty"`
}

func handleCloudSmartTestToggle(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	cloudSmartTestMu.Lock()
	cloudSmartTestSimulated = !cloudSmartTestSimulated
	curState := cloudSmartTestSimulated
	cloudSmartTestMu.Unlock()

	jsonResponse(w, map[string]interface{}{
		"success":       true,
		"simulated":     curState,
		"message":       fmt.Sprintf("SMART test alert simulation set to %v", curState),
	})
}

func handleCloudSmart(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()

	cloudSmartTestMu.RLock()
	isTestSimulated := cloudSmartTestSimulated
	cloudSmartTestMu.RUnlock()

	out, err := exec.Command("lsblk", "-d", "-n", "-o", "NAME,TYPE,SIZE,MODEL").CombinedOutput()
	var disks []SmartDiskInfo
	overallHealthy := true

	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "disk" {
				dev := fields[0]
				size := ""
				if len(fields) >= 3 {
					size = fields[2]
				}
				model := ""
				if len(fields) >= 4 {
					model = strings.Join(fields[3:], " ")
				}

				// Look for first partition name
				firstPart := ""
				partOut, pErr := exec.Command("lsblk", "-n", "-l", "-o", "NAME,TYPE", "/dev/"+dev).CombinedOutput()
				if pErr == nil {
					pLines := strings.Split(strings.TrimSpace(string(partOut)), "\n")
					for _, pl := range pLines {
						pFields := strings.Fields(pl)
						if len(pFields) >= 2 && pFields[1] == "part" {
							firstPart = pFields[0]
							break
						}
					}
				}

				info := SmartDiskInfo{
					Device:        "/dev/" + dev,
					FirstPartName: firstPart,
					Capacity:      size,
					Model:         model,
					Health:        "UNKNOWN",
				}

				// Check SMART health via smartctl
				sCmd := exec.Command("smartctl", "-H", "/dev/"+dev)
				if os.Getuid() != 0 {
					sCmd = exec.Command("sudo", "-n", "smartctl", "-H", "/dev/"+dev)
				}
				sOut, sErr := sCmd.CombinedOutput()
				sStr := string(sOut)
				upperStr := strings.ToUpper(sStr)

				// Only flag FAILED if SMART self-assessment explicitly reports failure
				if strings.Contains(upperStr, "SELF-ASSESSMENT TEST RESULT: FAILED") ||
					strings.Contains(upperStr, "SMART HEALTH STATUS: FAILURE") ||
					strings.Contains(upperStr, "SMART OVERALL-HEALTH SELF-ASSESSMENT TEST RESULT: FAILED") {
					info.Health = "FAILED"
					overallHealthy = false
				} else if strings.Contains(upperStr, "SELF-ASSESSMENT TEST RESULT: PASSED") ||
					strings.Contains(upperStr, "SMART HEALTH STATUS: OK") ||
					strings.Contains(upperStr, "SMART HEALTH STATUS: PASSED") ||
					(sErr == nil && (strings.Contains(upperStr, "PASSED") || strings.Contains(upperStr, "OK"))) {
					info.Health = "PASSED"
				} else {
					// Missing smartmontools, device lacks SMART capability, or virtual disk
					info.Health = "UNKNOWN"
				}

				info.RawInfo = strings.TrimSpace(sStr)
				disks = append(disks, info)
			}
		}
	}

	// If test simulation is active, inject bad drives and trigger overall_healthy = false
	if isTestSimulated {
		overallHealthy = false
		disks = append([]SmartDiskInfo{
			{
				Device:        "/dev/sda",
				FirstPartName: "sda1",
				Model:         "Samsung 980 PRO (SIMULATED ERROR)",
				Capacity:      "1.0 TB",
				Health:        "FAILED",
				RawInfo:       "SMART overall-health self-assessment test result: FAILED (Test Mode Active)",
			},
			{
				Device:        "/dev/sdb",
				FirstPartName: "sdb1",
				Model:         "WDC WD40EFAX (SIMULATED ERROR)",
				Capacity:      "4.0 TB",
				Health:        "FAILED",
				RawInfo:       "SMART overall-health self-assessment test result: FAILED (Test Mode Active)",
			},
		}, disks...)
	}

	jsonResponse(w, map[string]interface{}{
		"success":         true,
		"overall_healthy": overallHealthy,
		"is_test":         isTestSimulated,
		"test_message":    "This is a test!",
		"disks":           disks,
		"timestamp":       time.Now().Unix(),
	})
}

func handleCloudConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	decryptedBody, aesKey, err := decryptPayloadWithKey(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Folder  *string `json:"folder"`
		Enabled *bool   `json:"enabled"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	cloudConfigMu.RLock()
	newCfg := cloudConfig
	cloudConfigMu.RUnlock()

	if req.Folder != nil {
		folderPath := strings.TrimSpace(*req.Folder)
		if folderPath != "" {
			absFolder, err := filepath.Abs(folderPath)
			if err != nil {
				jsonResponse(w, map[string]interface{}{"success": false, "error": "Invalid folder path"})
				return
			}
			fi, err := os.Stat(absFolder)
			if err != nil || !fi.IsDir() {
				jsonResponse(w, map[string]interface{}{"success": false, "error": "Folder does not exist or is not a directory"})
				return
			}
			newCfg.Folder = absFolder
			newCfg.VolumeUUID = getVolumeUUID(absFolder)
		}
	}

	if req.Enabled != nil {
		newCfg.Enabled = *req.Enabled
		// If starting, ensure folder is configured and exists
		if newCfg.Enabled {
			if newCfg.Folder == "" {
				jsonResponse(w, map[string]interface{}{"success": false, "error": "Cannot start cloud: no folder configured"})
				return
			}
			fi, err := os.Stat(newCfg.Folder)
			if err != nil || !fi.IsDir() {
				newCfg.Enabled = false
				_ = saveCloudConfig(newCfg)
				jsonResponse(w, map[string]interface{}{"success": false, "error": "Cannot start cloud: folder does not exist or drive unmounted"})
				return
			}
			// Verify volume UUID
			curUUID := getVolumeUUID(newCfg.Folder)
			if newCfg.VolumeUUID != "" && curUUID != "" && newCfg.VolumeUUID != curUUID {
				newCfg.Enabled = false
				_ = saveCloudConfig(newCfg)
				jsonResponse(w, map[string]interface{}{"success": false, "error": fmt.Sprintf("Volume UUID mismatch (%s vs %s). Drive may have changed.", curUUID, newCfg.VolumeUUID)})
				return
			}
			if newCfg.VolumeUUID == "" {
				newCfg.VolumeUUID = curUUID
			}
		}
	}

	if err := saveCloudConfig(newCfg); err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
		"success":     true,
		"enabled":     newCfg.Enabled,
		"folder":      newCfg.Folder,
		"volume_uuid": newCfg.VolumeUUID,
	})
}

// verifyCloudServiceActive checks if the cloud service is enabled, folder exists and UUID matches
func verifyCloudServiceActive() (string, error) {
	cloudConfigMu.RLock()
	cfg := cloudConfig
	cloudConfigMu.RUnlock()

	if !cfg.Enabled {
		return "", fmt.Errorf("cloud service is stopped")
	}
	if cfg.Folder == "" {
		return "", fmt.Errorf("cloud root folder not configured")
	}
	fi, err := os.Stat(cfg.Folder)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("cloud storage drive is offline or folder missing")
	}
	curUUID := getVolumeUUID(cfg.Folder)
	if cfg.VolumeUUID != "" && curUUID != "" && cfg.VolumeUUID != curUUID {
		return "", fmt.Errorf("storage volume UUID mismatch (configured: %s, found: %s)", cfg.VolumeUUID, curUUID)
	}
	return cfg.Folder, nil
}

func handleCloudList(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	rootFolder, err := verifyCloudServiceActive()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "cloud_stopped": true})
		return
	}

	relPath := r.URL.Query().Get("path")
	recursive := r.URL.Query().Get("recursive") == "true" || r.URL.Query().Get("all") == "true"

	targetDir, cleanRel, err := safeCloudPath(rootFolder, relPath)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	fi, err := os.Stat(targetDir)
	if err != nil || !fi.IsDir() {
		w.WriteHeader(http.StatusNotFound)
		jsonResponse(w, map[string]interface{}{"success": false, "error": "directory not found"})
		return
	}

	type CloudItem struct {
		Name    string `json:"name"`
		RelPath string `json:"rel_path"`
		IsDir   bool   `json:"is_dir"`
		Size    int64  `json:"size"`
		ModTime int64  `json:"mod_time"`
		SHA256  string `json:"sha256,omitempty"`
	}

	var items []CloudItem
	var deletedItems []CloudDeletedItem

	if recursive {
		// Collect active items
		err = filepath.Walk(targetDir, func(p string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			relFromRoot, _ := filepath.Rel(rootFolder, p)
			if relFromRoot == "." || relFromRoot == "" {
				return nil
			}
			// Skip internal metadata folder
			if strings.HasPrefix(relFromRoot, ".cloud_meta") || filepath.Base(p) == ".cloud_meta" {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(filepath.Base(p), ".cloud-") && strings.HasSuffix(filepath.Base(p), ".json") {
				return nil
			}

			item := CloudItem{
				Name:    info.Name(),
				RelPath: filepath.ToSlash(relFromRoot),
				IsDir:   info.IsDir(),
				Size:    info.Size(),
				ModTime: info.ModTime().Unix(),
			}
			items = append(items, item)
			return nil
		})

		// Scan .cloud_meta to collect deletion tombstones
		metaBase := filepath.Join(rootFolder, ".cloud_meta")
		if _, mErr := os.Stat(metaBase); mErr == nil {
			_ = filepath.Walk(metaBase, func(p string, info os.FileInfo, walkErr error) error {
				if walkErr != nil || info.IsDir() {
					return nil
				}
				if strings.HasPrefix(info.Name(), ".cloud-") && strings.HasSuffix(info.Name(), ".json") {
					metaRelDir, _ := filepath.Rel(metaBase, filepath.Dir(p))
					if metaRelDir == "." {
						metaRelDir = ""
					}
					metaData := loadCloudDirMeta(rootFolder, metaRelDir)
					for delName, delTime := range metaData.Deleted {
						delRel := delName
						if metaRelDir != "" {
							delRel = filepath.ToSlash(filepath.Join(metaRelDir, delName))
						}
						deletedItems = append(deletedItems, CloudDeletedItem{
							RelPath:   delRel,
							DeletedAt: delTime,
						})
					}
				}
				return nil
			})
		}
	} else {
		entries, readErr := os.ReadDir(targetDir)
		if readErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			jsonResponse(w, map[string]interface{}{"success": false, "error": readErr.Error()})
			return
		}

		dirMeta := loadCloudDirMeta(rootFolder, cleanRel)
		updatedMeta := false

		for _, e := range entries {
			name := e.Name()
			if name == ".cloud_meta" || (strings.HasPrefix(name, ".cloud-") && strings.HasSuffix(name, ".json")) {
				continue
			}
			itemPath := filepath.Join(targetDir, name)
			info, err := e.Info()
			if err != nil {
				continue
			}
			itemRel := filepath.ToSlash(filepath.Join(cleanRel, name))
			sha := ""
			if !info.IsDir() {
				if cached, ok := dirMeta.Files[name]; ok && cached.ModTime == info.ModTime().Unix() && cached.Size == info.Size() && cached.SHA256 != "" {
					sha = cached.SHA256
				} else {
					sha = calculateFileSHA256(itemPath)
					dirMeta.Files[name] = CloudMetaFile{
						Path:        itemRel,
						Size:        info.Size(),
						ModTime:     info.ModTime().Unix(),
						SHA256:      sha,
						LastUpdated: time.Now().Format(time.RFC3339),
					}
					updatedMeta = true
				}
			}

			items = append(items, CloudItem{
				Name:    name,
				RelPath: itemRel,
				IsDir:   info.IsDir(),
				Size:    info.Size(),
				ModTime: info.ModTime().Unix(),
				SHA256:  sha,
			})
		}
		if updatedMeta {
			_ = saveCloudDirMeta(rootFolder, cleanRel, dirMeta)
		}

		for delName, delTime := range dirMeta.Deleted {
			delRel := delName
			if cleanRel != "" {
				delRel = filepath.ToSlash(filepath.Join(cleanRel, delName))
			}
			deletedItems = append(deletedItems, CloudDeletedItem{
				RelPath:   delRel,
				DeletedAt: delTime,
			})
		}
	}

	jsonResponse(w, map[string]interface{}{
		"success":   true,
		"path":      cleanRel,
		"items":     items,
		"deleted":   deletedItems,
		"timestamp": time.Now().Unix(),
	})
}

func handleCloudSave(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	rootFolder, err := verifyCloudServiceActive()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "cloud_stopped": true})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	decryptedBody, aesKey, err := decryptPayloadWithKey(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Path        string `json:"path"`
		ContentB64  string `json:"content_b64"`
		ContentText string `json:"content_text"`
		ModTime     int64  `json:"mod_time"`
		Force       bool   `json:"force"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Path == "" {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": "invalid payload or missing path"})
		return
	}

	targetFile, cleanRel, err := safeCloudPath(rootFolder, req.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	// Acquire file lock
	if !acquireCloudFileLock(cleanRel) {
		w.WriteHeader(http.StatusConflict) // 409 Conflict / busy
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
			"success": false,
			"error":   "file is currently open or in use by another operation",
			"status":  "busy",
			"path":    cleanRel,
		})
		return
	}
	defer releaseCloudFileLock(cleanRel)

	// Decode incoming content
	var fileData []byte
	if req.ContentB64 != "" {
		b, err := base64.StdEncoding.DecodeString(req.ContentB64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": "invalid base64 content"})
			return
		}
		fileData = b
	} else {
		fileData = []byte(req.ContentText)
	}

	relDir := filepath.Dir(cleanRel)
	if relDir == "." {
		relDir = ""
	}
	baseName := filepath.Base(cleanRel)
	dirMeta := loadCloudDirMeta(rootFolder, relDir)

	// Check if file already exists
	existingInfo, err := os.Stat(targetFile)
	if err == nil && !existingInfo.IsDir() {
		existingModTime := existingInfo.ModTime().Unix()

		// Date comparison: if incoming file is older than server's file and not forced
		if req.ModTime > 0 && req.ModTime < existingModTime && !req.Force {
			// Save the attempted older upload to RecycleBin
			dateTag := time.Now().Format("2006-01-02_150405")
			olderBackupName := fmt.Sprintf("%s.rejected_older.%s", baseName, dateTag)
			recycleDir := filepath.Join(rootFolder, "RecycleBin", relDir)
			_ = os.MkdirAll(recycleDir, 0755)
			olderBackupPath := filepath.Join(recycleDir, olderBackupName)
			_ = os.WriteFile(olderBackupPath, fileData, 0644)

			// Record history in metadata
			dirMeta.History = append(dirMeta.History, CloudHistoryEntry{
				Action:     "conflict_reject",
				OrigPath:   cleanRel,
				BackupPath: filepath.ToSlash(filepath.Join("RecycleBin", relDir, olderBackupName)),
				Timestamp:  time.Now().Format(time.RFC3339),
				ModTime:    req.ModTime,
				Size:       int64(len(fileData)),
				Details:    fmt.Sprintf("Client attempted older upload (client: %d vs server: %d). Saved to RecycleBin.", req.ModTime, existingModTime),
			})
			_ = saveCloudDirMeta(rootFolder, relDir, dirMeta)

			// Read server's current (newer) file to return to client
			serverData, readErr := os.ReadFile(targetFile)
			serverB64 := ""
			if readErr == nil {
				serverB64 = base64.StdEncoding.EncodeToString(serverData)
			}

			w.WriteHeader(http.StatusConflict) // 409
			sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
				"success":           false,
				"status":            "conflict_older_version",
				"error":             "Server has a newer version of this file. Incoming older file backed up to RecycleBin.",
				"server_mod_time":   existingModTime,
				"client_mod_time":   req.ModTime,
				"server_size":       existingInfo.Size(),
				"server_sha256":     calculateFileSHA256(targetFile),
				"server_file_b64":   serverB64,
				"saved_recycle_bin": filepath.ToSlash(filepath.Join("RecycleBin", relDir, olderBackupName)),
			})
			return
		}

		// Overwrite case: Move existing version into RecycleBin
		dateTag := existingInfo.ModTime().Format("2006-01-02_150405")
		backupName := fmt.Sprintf("%s.%s", baseName, dateTag)
		recycleDir := filepath.Join(rootFolder, "RecycleBin", relDir)
		_ = os.MkdirAll(recycleDir, 0755)
		backupPath := filepath.Join(recycleDir, backupName)

		// Copy existing file to RecycleBin
		if existingData, readErr := os.ReadFile(targetFile); readErr == nil {
			_ = os.WriteFile(backupPath, existingData, 0644)
			dirMeta.History = append(dirMeta.History, CloudHistoryEntry{
				Action:     "overwrite",
				OrigPath:   cleanRel,
				BackupPath: filepath.ToSlash(filepath.Join("RecycleBin", relDir, backupName)),
				Timestamp:  time.Now().Format(time.RFC3339),
				ModTime:    existingModTime,
				Size:       existingInfo.Size(),
				Details:    "Overwritten by newer file save",
			})
		}
	}

	// Ensure parent directory exists
	_ = os.MkdirAll(filepath.Dir(targetFile), 0755)

	// Write new file
	if err := os.WriteFile(targetFile, fileData, 0644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": fmt.Sprintf("failed to write file: %v", err)})
		return
	}

	// Update mod time if specified
	if req.ModTime > 0 {
		mTime := time.Unix(req.ModTime, 0)
		_ = os.Chtimes(targetFile, mTime, mTime)
	}

	// Recalculate checksum and update dir metadata
	newSha := calculateFileSHA256(targetFile)
	newFi, _ := os.Stat(targetFile)
	modT := time.Now().Unix()
	size := int64(len(fileData))
	if newFi != nil {
		modT = newFi.ModTime().Unix()
		size = newFi.Size()
	}

	dirMeta.Files[baseName] = CloudMetaFile{
		Path:        cleanRel,
		Size:        size,
		ModTime:     modT,
		SHA256:      newSha,
		LastUpdated: time.Now().Format(time.RFC3339),
	}
	if dirMeta.Deleted != nil {
		delete(dirMeta.Deleted, baseName) // Clear deletion tombstone on re-save
	}
	_ = saveCloudDirMeta(rootFolder, relDir, dirMeta)

	sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
		"success":  true,
		"path":     cleanRel,
		"size":     size,
		"mod_time": modT,
		"sha256":   newSha,
	})
}

func handleCloudLoad(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	rootFolder, err := verifyCloudServiceActive()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "cloud_stopped": true})
		return
	}

	var relPath string
	var aesKey []byte

	if r.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(r.Body)
		decryptedBody, key, err := decryptPayloadWithKey(bodyBytes)
		if err == nil {
			aesKey = key
			var req struct {
				Path string `json:"path"`
			}
			_ = json.Unmarshal(decryptedBody, &req)
			relPath = req.Path
		}
	}

	if relPath == "" {
		relPath = r.URL.Query().Get("path")
	}

	targetFile, cleanRel, err := safeCloudPath(rootFolder, relPath)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	// Check if file is currently locked/being written
	cloudFileLocksMu.Lock()
	locked := cloudFileLocks[cleanRel]
	cloudFileLocksMu.Unlock()
	if locked {
		w.WriteHeader(http.StatusConflict) // 409
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
			"success": false,
			"status":  "busy",
			"error":   "file is currently open for writing by another operation",
		})
		return
	}

	fi, err := os.Stat(targetFile)
	if err != nil || fi.IsDir() {
		w.WriteHeader(http.StatusNotFound)
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": "file not found"})
		return
	}

	contentBytes, err := os.ReadFile(targetFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	sha := calculateFileSHA256(targetFile)

	respPayload := map[string]interface{}{
		"success":     true,
		"path":        cleanRel,
		"size":        fi.Size(),
		"mod_time":    fi.ModTime().Unix(),
		"sha256":      sha,
		"content_b64": base64.StdEncoding.EncodeToString(contentBytes),
	}

	sendCloudJSONResponse(w, r, aesKey, respPayload)
}

func handleCloudDelete(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	rootFolder, err := verifyCloudServiceActive()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "cloud_stopped": true})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	decryptedBody, aesKey, err := decryptPayloadWithKey(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Path == "" {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": "missing path"})
		return
	}

	targetFile, cleanRel, err := safeCloudPath(rootFolder, req.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	// Check file lock
	if !acquireCloudFileLock(cleanRel) {
		w.WriteHeader(http.StatusConflict)
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
			"success": false,
			"status":  "busy",
			"error":   "file is currently open or in use",
		})
		return
	}
	defer releaseCloudFileLock(cleanRel)

	fi, err := os.Stat(targetFile)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": "file not found"})
		return
	}

	relDir := filepath.Dir(cleanRel)
	if relDir == "." {
		relDir = ""
	}
	baseName := filepath.Base(cleanRel)
	dirMeta := loadCloudDirMeta(rootFolder, relDir)

	// Move file or directory to RecycleBin
	dateTag := time.Now().Format("2006-01-02_150405")
	backupName := fmt.Sprintf("%s.deleted.%s", baseName, dateTag)
	recycleDir := filepath.Join(rootFolder, "RecycleBin", relDir)
	_ = os.MkdirAll(recycleDir, 0755)
	backupPath := filepath.Join(recycleDir, backupName)

	if err := os.Rename(targetFile, backupPath); err != nil {
		// If rename fails (e.g. cross-device, or permissions), try copy and remove
		data, readErr := os.ReadFile(targetFile)
		if readErr == nil {
			_ = os.WriteFile(backupPath, data, 0644)
			_ = os.Remove(targetFile)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
	}

	// Update metadata, tombstone deleted map, and history
	delete(dirMeta.Files, baseName)
	if dirMeta.Deleted == nil {
		dirMeta.Deleted = make(map[string]int64)
	}
	nowUnix := time.Now().Unix()
	dirMeta.Deleted[baseName] = nowUnix
	dirMeta.History = append(dirMeta.History, CloudHistoryEntry{
		Action:     "delete",
		OrigPath:   cleanRel,
		BackupPath: filepath.ToSlash(filepath.Join("RecycleBin", relDir, backupName)),
		Timestamp:  time.Now().Format(time.RFC3339),
		ModTime:    fi.ModTime().Unix(),
		Size:       fi.Size(),
		Details:    "Deleted by client, moved to RecycleBin",
	})
	_ = saveCloudDirMeta(rootFolder, relDir, dirMeta)

	sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
		"success":     true,
		"path":        cleanRel,
		"recycle_bin": filepath.ToSlash(filepath.Join("RecycleBin", relDir, backupName)),
	})
}

func handleCloudMkdir(w http.ResponseWriter, r *http.Request) {
	recordCloudActivity()
	rootFolder, err := verifyCloudServiceActive()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error(), "cloud_stopped": true})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	decryptedBody, aesKey, err := decryptPayloadWithKey(bodyBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decryption_failed: %v"}`, err), http.StatusBadRequest)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(decryptedBody, &req); err != nil || req.Path == "" {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": "missing path"})
		return
	}

	targetDir, cleanRel, err := safeCloudPath(rootFolder, req.Path)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	sendCloudJSONResponse(w, r, aesKey, map[string]interface{}{
		"success": true,
		"path":    cleanRel,
	})
}
