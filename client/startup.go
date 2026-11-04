package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SetRunOnStartup configures the application to launch on user login
func SetRunOnStartup(enabled bool) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err == nil {
		exePath = resolved
	}

	if runtime.GOOS == "windows" {
		// Set or remove Run key in HKCU
		keyPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
		appName := "LinNASCloudClient"
		if enabled {
			cmd := exec.Command("reg", "add", keyPath, "/v", appName, "/t", "REG_SZ", "/d", fmt.Sprintf("\"%s\"", exePath), "/f")
			prepareHiddenCommand(cmd)
			return cmd.Run()
		} else {
			cmd := exec.Command("reg", "delete", keyPath, "/v", appName, "/f")
			prepareHiddenCommand(cmd)
			_ = cmd.Run()
			return nil
		}
	} else if runtime.GOOS == "linux" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		autostartDir := filepath.Join(homeDir, ".config", "autostart")
		desktopFile := filepath.Join(autostartDir, "linnas-client.desktop")

		if enabled {
			if err := os.MkdirAll(autostartDir, 0755); err != nil {
				return err
			}
			content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Version=1.0
Name=LinNAS Local Cloud Client
Comment=LinNAS Desktop Synchronization & SMART Diagnostics Client
Exec="%s"
Terminal=false
Categories=Network;FileTransfer;
StartupNotify=false
`, exePath)
			return os.WriteFile(desktopFile, []byte(content), 0644)
		} else {
			if _, err := os.Stat(desktopFile); err == nil {
				return os.Remove(desktopFile)
			}
			return nil
		}
	}
	return nil
}

// IsRunOnStartupEnabled checks whether autostart is currently enabled
func IsRunOnStartupEnabled() bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "LinNASCloudClient")
		prepareHiddenCommand(cmd)
		out, err := cmd.Output()
		return err == nil && strings.Contains(string(out), "LinNASCloudClient")
	} else if runtime.GOOS == "linux" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		desktopFile := filepath.Join(homeDir, ".config", "autostart", "linnas-client.desktop")
		_, err = os.Stat(desktopFile)
		return err == nil
	}
	return false
}
