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
	ServerEndpoint  string          `json:"server_endpoint"`         // e.g. "192.168.1.50:8080"
	Username        string          `json:"username"`
	PasswordHash    string          `json:"password_hash"`            // SHA-256 hash (never store plaintext password)
	SessionToken    string          `json:"session_token,omitempty"` // Long-lived auth session token
	LocalSyncDir    string          `json:"local_sync_dir"`
	SyncEnabled     bool            `json:"sync_enabled"`
	SyncMode        string          `json:"sync_mode"`                // "On a timer" or "When idle for"
	SyncIntervalSec int             `json:"sync_interval_sec"`        // 120 (2 mins) to 18000 (5 hours)
	ThrottleKBps    int             `json:"throttle_kbps"`            // 0 = unlimited, otherwise speed cap
	IdleOnly        bool            `json:"idle_only"`                // Only upload/sync when idle
	SelectedFolders map[string]bool `json:"selected_folders"`         // checked folders (relative paths)
	LogToFile       bool            `json:"log_to_file"`              // Defaults to false (off)
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
		SyncMode:        "On a timer",
		SyncIntervalSec: 300, // Default 5 mins
		ThrottleKBps:    500, // Leisurely default ~500 KB/s
		IdleOnly:        false,
		SelectedFolders: make(map[string]bool),
		LogToFile:       false,
	}
}

func getConfigPath() string {
	// Saved data should be saved in the folder where the binary is
	exePath, err := os.Executable()
	if err == nil {
		resolved, rErr := filepath.EvalSymlinks(exePath)
		if rErr == nil {
			exePath = resolved
		}
		binDir := filepath.Dir(exePath)
		return filepath.Join(binDir, "config.json")
	}
	return "config.json"
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
		if appCfg.SyncMode == "" {
			if appCfg.IdleOnly {
				appCfg.SyncMode = "When idle for"
			} else {
				appCfg.SyncMode = "On a timer"
			}
		}
		if appCfg.SyncIntervalSec < 120 {
			appCfg.SyncIntervalSec = 300 // default 5 mins
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
