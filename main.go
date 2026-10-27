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
	InstallCmd  string            `json:"install_cmd,omitempty"`
	RemoveCmd   string            `json:"remove_cmd,omitempty"`
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
	Shares []SMBShare `json:"shares"`
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
	appConfig  Config
	sessions   = make(map[string]time.Time)
	sessionsMu sync.RWMutex
	// Prohibit shell metacharacters $, `, |, &, ;, <, >, (, ), \, *, ?, newlines \r \n
	safeVarReg = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/\:\ \@\!\#\%\^\=\+\{\}\[\]\~\t]+$`)
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

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, req.Plugin); !matched {
		jsonResponse(w, ExecResponse{Success: false, Error: "Invalid plugin ID"})
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

// Sync SMB, DNS, and DHCP plugin data directly to Debian service configs
func syncSystemConfigs(pluginID string, body []byte) {
	switch pluginID {
	case "smb":
		var smbData SMBData
		if err := json.Unmarshal(body, &smbData); err == nil {
			var sb strings.Builder
			sb.WriteString("# Generated by Debian Server Manager\n\n")
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
					newConf := string(mainConf) + "\n\n# Include Debian Server Manager Shares\ninclude = /etc/samba/conf.d/shares.conf\n"
					_ = os.WriteFile("/etc/samba/smb.conf", []byte(newConf), 0644)
				}
			}
		}

	case "dns":
		var dnsData DNSData
		if err := json.Unmarshal(body, &dnsData); err == nil {
			var sb strings.Builder
			sb.WriteString("# Generated by Debian Server Manager\n")
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
			sb.WriteString("# Generated by Debian Server Manager\n")
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

		// Sync data directly to system config files (/etc/samba, /etc/dnsmasq.d)
		syncSystemConfigs(pluginID, body)

		jsonResponse(w, map[string]interface{}{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleFileWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FilePath string `json:"filepath"`
		Content  string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FilePath == "" {
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

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	cleanPath := filepath.Clean(req.Path)
	err := os.MkdirAll(cleanPath, 0755)
	if err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	jsonResponse(w, map[string]interface{}{"success": true, "path": cleanPath})
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

func main() {
	loadConfig()

	_ = os.MkdirAll("html", 0755)

	mux := http.NewServeMux()

	// API Endpoints protected by authMiddleware
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/auth/status", handleAuthStatus)
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
	mux.HandleFunc("/api/plugin/exec", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(r) {
			// Allow read-only status queries when unauthenticated
			var req ExecRequest
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil {
				_ = json.Unmarshal(bodyBytes, &req)
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
	mux.HandleFunc("/api/fs/browse", authMiddleware(handleFsBrowse))
	mux.HandleFunc("/api/fs/mkdir", authMiddleware(handleFsMkdir))
	mux.HandleFunc("/api/file/write", authMiddleware(handleFileWrite))
	mux.HandleFunc("/api/dns/convert", authMiddleware(handleDNSConvert))

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
	log.Printf("Starting Debian Server Manager on http://localhost%s (Running as Root: %v)", addr, os.Getuid() == 0)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
