package main

import (
	"bytes"
	"crypto/aes"
	"flag"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
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
	rsaPrivateKey *rsa.PrivateKey
	usedNonces    = make(map[string]time.Time)
	noncesMu      sync.Mutex
	// Prohibit shell metacharacters $, `, |, &, ;, <, >, (, ), \, *, ?, newlines \r \n
	safeVarReg    = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/\:\ \@\!\#\%\^\=\+\{\}\[\]\~\t]+$`)
)

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

func decryptPayload(body []byte) ([]byte, error) {
	var encPayload EncryptedPayload
	if err := json.Unmarshal(body, &encPayload); err != nil || encPayload.EncryptedKey == "" {
		// Return unencrypted raw body if payload isn't encrypted
		return body, nil
	}

	if err := checkNonceAndTimestamp(encPayload.Nonce, encPayload.Timestamp); err != nil {
		return nil, err
	}

	keyBytes, err := base64.StdEncoding.DecodeString(encPayload.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encrypted_key")
	}

	// Decrypt AES key with RSA private key
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, keyBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key with RSA: %v", err)
	}

	dataBytes, err := base64.StdEncoding.DecodeString(encPayload.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encrypted_data")
	}

	if len(dataBytes) < 12 {
		return nil, fmt.Errorf("encrypted_data payload too short for AES-GCM nonce")
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
	if len(dataBytes) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	aesNonce, ciphertext := dataBytes[:nonceSize], dataBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, aesNonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES-GCM data: %v", err)
	}

	return plaintext, nil
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
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(decryptedBody, &creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	providedHash := hashPassword(creds.Password)
	if creds.Username == appConfig.Username && (providedHash == appConfig.PasswordHash || creds.Password == appConfig.Password) {
		token := generateToken()
		sessionsMu.Lock()
		sessions[token] = time.Now().Add(24 * time.Hour)
		sessionsMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(24 * time.Hour),
		})
		jsonResponse(w, map[string]interface{}{"success": true})
	} else {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
	}
}

func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
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

			for _, share := range smbData.Shares {
				if share.Enabled {
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
	}
}

func handlePluginData(w http.ResponseWriter, r *http.Request) {
	pluginID := r.URL.Query().Get("plugin")
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, pluginID); !matched || pluginID == "" {
		http.Error(w, "Invalid or missing plugin parameter", http.StatusBadRequest)
		return
	}

	dataPath := filepath.Join("html", pluginID, "data.json")

	switch r.Method {
	case http.MethodGet:
		if _, err := os.Stat(dataPath); os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
			return
		}
		http.ServeFile(w, r, dataPath)

	case http.MethodPost, http.MethodPut:
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

		_ = os.MkdirAll(filepath.Dir(dataPath), 0755)
		if err := os.WriteFile(dataPath, decryptedBody, 0644); err != nil {
			http.Error(w, "Failed to write data file", http.StatusInternalServerError)
			return
		}

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
		if err == nil {
			size = info.Size()
		}
		items = append(items, FileEntry{
			Name:  entry.Name(),
			Path:  filepath.Join(dirPath, entry.Name()),
			IsDir: entry.IsDir(),
			Size:  size,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir // folders first (true < false is false, so true comes first)
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	parent := filepath.Dir(dirPath)
	jsonResponse(w, map[string]interface{}{
		"path":   dirPath,
		"parent": parent,
		"items":  items,
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
	logStartupEvent(fmt.Sprintf("WARNING: Could not find 'html/' directory in %s", cwd))
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
	mux.HandleFunc("/api/fs/upload", authMiddleware(handleFsUpload))
	mux.HandleFunc("/api/file/write", authMiddleware(handleFileWrite))
	mux.HandleFunc("/api/startup/issues", authMiddleware(handleStartupIssues))
	mux.HandleFunc("/api/startup/clear", authMiddleware(handleStartupClear))
	mux.HandleFunc("/api/console/stream", authMiddleware(handleConsoleStream))
	mux.HandleFunc("/api/dns/convert", authMiddleware(handleDNSConvert))
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
