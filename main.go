package main

import (
	"crypto/rand"
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
	"strings"
	"sync"
	"time"
)

type Config struct {
	Port        int    `json:"port"`
	AuthEnabled bool   `json:"auth_enabled"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

type PluginManifest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Default     bool              `json:"default"`
	AptPackage  string            `json:"apt_package,omitempty"`
	CheckCmd    string            `json:"check_cmd,omitempty"`
	Commands    map[string]string `json:"commands,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Installed   bool              `json:"installed"`
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

var (
	appConfig   Config
	sessions    = make(map[string]time.Time)
	sessionsMu  sync.RWMutex
	safeVarReg  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/\:\ \@]+$`)
)

func loadConfig() {
	appConfig = Config{
		Port:        8080,
		AuthEnabled: true,
		Username:    "admin",
		Password:    "adminpassword",
	}

	data, err := os.ReadFile("config.json")
	if err == nil {
		_ = json.Unmarshal(data, &appConfig)
	}
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
		// Serve static files and public auth endpoints
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

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if creds.Username == appConfig.Username && creds.Password == appConfig.Password {
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
		// Fallback check with which
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

		// Check installation status
		if manifest.Default {
			manifest.Installed = true
		} else {
			manifest.Installed = checkPackageInstalled(manifest.CheckCmd, manifest.AptPackage)
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

	var req ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Security validation: plugin id must be safe alphanumeric
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, req.Plugin); !matched {
		jsonResponse(w, ExecResponse{Success: false, Error: "Invalid plugin ID"})
		return
	}

	// Security validation: cmd_key MUST end with "_cmd"
	if !strings.HasSuffix(req.CmdKey, "_cmd") {
		jsonResponse(w, ExecResponse{Success: false, Error: "Only keys ending with '_cmd' can be executed"})
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

	// Look up command string in root JSON or inside "commands" map
	cmdTemplate := ""
	if val, ok := rawMap[req.CmdKey].(string); ok {
		cmdTemplate = val
	} else if cmds, ok := rawMap["commands"].(map[string]interface{}); ok {
		if val, ok := cmds[req.CmdKey].(string); ok {
			cmdTemplate = val
		}
	}

	if cmdTemplate == "" {
		jsonResponse(w, ExecResponse{Success: false, Error: fmt.Sprintf("Command key %s not found in plugin", req.CmdKey)})
		return
	}

	// Substitute variables safely
	finalCmd := cmdTemplate
	for k, v := range req.Args {
		// Verify argument value doesn't contain shell injection characters
		if !safeVarReg.MatchString(v) && len(v) > 0 {
			jsonResponse(w, ExecResponse{Success: false, Error: fmt.Sprintf("Invalid characters in parameter %s", k)})
			return
		}
		finalCmd = strings.ReplaceAll(finalCmd, "{"+k+"}", v)
		finalCmd = strings.ReplaceAll(finalCmd, "%"+k+"%", v)
	}

	log.Printf("[EXEC] Plugin: %s, CmdKey: %s, Cmd: %s", req.Plugin, req.CmdKey, finalCmd)

	cmd := exec.Command("sh", "-c", finalCmd)
	outBytes, err := cmd.CombinedOutput()
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
		// Validate JSON
		var js json.RawMessage
		if err := json.Unmarshal(body, &js); err != nil {
			http.Error(w, "Invalid JSON data", http.StatusBadRequest)
			return
		}

		_ = os.MkdirAll(filepath.Dir(dataPath), 0755)
		if err := os.WriteFile(dataPath, body, 0644); err != nil {
			http.Error(w, "Failed to write data file", http.StatusInternalServerError)
			return
		}
		jsonResponse(w, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
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

		// AdBlock format: ||domain.com^
		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			domain := line[2 : len(line)-1]
			if domainRegex.MatchString(domain) {
				converted = append(converted, fmt.Sprintf("address=/%s/0.0.0.0", domain))
			}
			continue
		}

		// Hosts format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := parts[1]
			if domainRegex.MatchString(domain) {
				converted = append(converted, fmt.Sprintf("address=/%s/0.0.0.0", domain))
				continue
			}
		}

		// Single raw domain: domain.com
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

func main() {
	loadConfig()

	// Ensure html directory exists
	_ = os.MkdirAll("html", 0755)

	mux := http.NewServeMux()

	// API Endpoints
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/auth/status", handleAuthStatus)
	mux.HandleFunc("/api/plugins", handleListPlugins)
	mux.HandleFunc("/api/plugin/exec", handleExecPluginCmd)
	mux.HandleFunc("/api/plugin/data", handlePluginData)
	mux.HandleFunc("/api/dns/convert", handleDNSConvert)

	// Static HTML File server
	fileServer := http.FileServer(http.Dir("html"))
	mux.Handle("/", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve index.htm if root
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join("html", "index.htm"))
			return
		}
		fileServer.ServeHTTP(w, r)
	})))

	addr := fmt.Sprintf(":%d", appConfig.Port)
	log.Printf("Starting Debian Server Manager on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
