package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type ClientConfig struct {
	ServerEndpoint  string          `json:"server_endpoint"`  // e.g. "192.168.1.50:8080"
	Username        string          `json:"username"`
	PasswordHash    string          `json:"password_hash"`
	LocalSyncDir    string          `json:"local_sync_dir"`
	SyncEnabled     bool            `json:"sync_enabled"`
	SyncIntervalSec int             `json:"sync_interval_sec"` // Default 30s
	ThrottleKBps    int             `json:"throttle_kbps"`     // 0 = unlimited, otherwise speed cap
	IdleOnly        bool            `json:"idle_only"`         // Only upload/sync when idle
	IdleWaitMinutes int             `json:"idle_wait_minutes"` // e.g. 5 minutes
	SelectedFolders map[string]bool `json:"selected_folders"`  // checked folders (relative paths)
}

var (
	configMu sync.RWMutex
	appCfg   ClientConfig
)

func getDefaultConfig() ClientConfig {
	home, _ := os.UserHomeDir()
	defaultLocalDir := filepath.Join(home, "LinNAS-Cloud")
	return ClientConfig{
		ServerEndpoint:  "127.0.0.1:8080",
		Username:        "admin",
		LocalSyncDir:    defaultLocalDir,
		SyncEnabled:     true,
		SyncIntervalSec: 30,
		ThrottleKBps:    500, // Leisurely default ~500 KB/s
		IdleOnly:        false,
		IdleWaitMinutes: 3,
		SelectedFolders: make(map[string]bool),
	}
}

func getConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	appDir := filepath.Join(configDir, "LinNASClient")
	_ = os.MkdirAll(appDir, 0755)
	return filepath.Join(appDir, "config.json")
}

func LoadConfig() ClientConfig {
	configMu.Lock()
	defer configMu.Unlock()

	appCfg = getDefaultConfig()
	data, err := os.ReadFile(getConfigPath())
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &appCfg)
		if appCfg.SelectedFolders == nil {
			appCfg.SelectedFolders = make(map[string]bool)
		}
		if appCfg.SyncIntervalSec <= 0 {
			appCfg.SyncIntervalSec = 30
		}
	}
	return appCfg
}

func SaveConfig(cfg ClientConfig) error {
	configMu.Lock()
	defer configMu.Unlock()

	appCfg = cfg
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getConfigPath(), data, 0644)
}

func HashPassword(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

// IsFolderSelected checks whether a folder (or any parent) is selected for sync.
// If no folders are checked, root is synced.
func IsFolderSelected(relPath string, selected map[string]bool) bool {
	if len(selected) == 0 {
		return true // default sync all if none specified
	}

	clean := filepath.Clean(filepath.ToSlash(relPath))
	if clean == "." || clean == "" {
		return true
	}

	// Check if the path or any prefix is selected
	parts := strings.Split(clean, "/")
	curr := ""
	for _, part := range parts {
		if curr == "" {
			curr = part
		} else {
			curr = curr + "/" + part
		}
		if selected[curr] {
			return true
		}
	}

	return false
}
