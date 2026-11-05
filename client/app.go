package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type CombinedSmartData struct {
	OverallHealthy bool                  `json:"overall_healthy"`
	IsTest         bool                  `json:"is_test"`
	ServerDisks    []SmartDiskInfo       `json:"server_disks"`
	LocalDisks     []SmartDiskInfo       `json:"local_disks"`
	ClientGroups   []ClientGroupInfo     `json:"client_groups"`
	Error          string                `json:"error,omitempty"`
}

type ClientGroupInfo struct {
	IP       string          `json:"ip"`
	Client   string          `json:"client"`
	Disks    []SmartDiskInfo `json:"disks"`
}

type App struct {
	ctx           context.Context
	cfg           ClientConfig
	engine        *SyncEngine
	reconnectMgr  *ReconnectManager
	mu            sync.Mutex
	alertActive   bool
	lastFailingDrives string
}

func NewApp() *App {
	cfg := LoadConfig()
	engine, err := NewSyncEngine(cfg)
	if err != nil {
		fmt.Printf("Error creating sync engine: %v\n", err)
	}

	app := &App{
		cfg:    cfg,
		engine: engine,
	}

	app.reconnectMgr = NewReconnectManager(
		func() {
			// Trigger re-authentication and catch-up check
			go app.handlePostReconnect()
		},
		func(status string) {
			app.engine.SetStatus(status)
			if app.ctx != nil {
				wailsRuntime.EventsEmit(app.ctx, "status-update", status)
				wailsRuntime.EventsEmit(app.ctx, "connection-state", false)
			}
		},
	)

	return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Wire engine callbacks
	a.engine.onStatus = func(status string) {
		wailsRuntime.EventsEmit(a.ctx, "status-update", status)
		// If status indicates connected or up to date, emit connected true
		if strings.Contains(status, "Connected") || strings.Contains(status, "Up to Date") {
			wailsRuntime.EventsEmit(a.ctx, "connection-state", true)
		} else if strings.Contains(status, "Disconnected") || strings.Contains(status, "Offline") || strings.Contains(status, "Failed") {
			wailsRuntime.EventsEmit(a.ctx, "connection-state", false)
		}
	}

	a.engine.onSmartAlert = func(alertMsg string, isTest bool) {
		a.triggerSmartAlert(alertMsg, isTest)
	}

	// Start background workers
	go a.startBackgroundWorker()
}

func (a *App) handlePostReconnect() {
	a.engine.SetStatus("Re-authenticating...")
	if err := a.engine.EnsureAuthenticated(""); err != nil {
		a.reconnectMgr.MarkDisconnected("re-auth failed: " + err.Error())
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "connection-state", false)
		}
		return
	}
	a.engine.SetStatus("Connected")
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "connection-state", true)
	}

	// Trigger SMART check immediately
	go a.CheckSMARTStatus()

	// If timer sync fired and failed while down, perform sync catchup now (unless idle-only mode prevents it)
	if a.reconnectMgr.HasMissedTimerSync() {
		a.reconnectMgr.ClearMissedTimerSync()
		if a.cfg.SyncEnabled && !a.cfg.IdleOnly {
			a.engine.SetStatus("Running catchup sync...")
			_ = a.engine.PerformSync("")
		}
	}
}

func (a *App) triggerSmartAlert(alertMsg string, isTest bool) {
	if a.engine.IsSmartAlertMuted() {
		return
	}

	// Fullscreen app detection: Defer popup until user exits fullscreen
	go func() {
		for {
			if !IsFullscreenAppActive() {
				break
			}
			time.Sleep(5 * time.Second)
		}

		if a.engine.IsSmartAlertMuted() {
			return
		}

		if a.ctx != nil {
			// Unhide and show window
			wailsRuntime.WindowShow(a.ctx)
			wailsRuntime.WindowUnminimise(a.ctx)
			// Emit alert event to frontend to activate SMART tab and show top warning banner
			wailsRuntime.EventsEmit(a.ctx, "smart-alert", map[string]interface{}{
				"message": alertMsg,
				"is_test": isTest,
			})
		}
	}()
}

// GetConfig returns the current configuration
func (a *App) GetConfig() ClientConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// SaveConfig updates and persists config
func (a *App) SaveConfig(newCfg ClientConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Preserve password hash if not changing
	if newCfg.PasswordHash == "" && a.cfg.PasswordHash != "" {
		newCfg.PasswordHash = a.cfg.PasswordHash
	}

	if err := SaveConfig(newCfg); err != nil {
		return err
	}
	a.cfg = newCfg
	a.engine.UpdateConfig(newCfg)
	return nil
}

// SetPassword updates user password
func (a *App) SetPassword(plainPwd string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg.PasswordHash = HashPassword(plainPwd)
	a.cfg.SessionToken = ""
	if err := SaveConfig(a.cfg); err != nil {
		return err
	}
	a.engine.UpdateConfig(a.cfg)
	return nil
}

// PickDirectory opens native directory picker
func (a *App) PickDirectory() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("context not initialized")
	}
	return wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select Local Synchronization Folder",
	})
}

// PerformSync runs an on-demand sync
func (a *App) PerformSync() error {
	a.engine.SetStatus("Manual sync initiated...")
	err := a.engine.PerformSync("")
	if err != nil {
		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "timeout") {
			a.reconnectMgr.MarkDisconnected(err.Error())
			if a.ctx != nil {
				wailsRuntime.EventsEmit(a.ctx, "connection-state", false)
			}
		}
		a.engine.SetStatus("Sync Error: " + err.Error())
		return err
	}
	a.reconnectMgr.MarkConnected()
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "connection-state", true)
	}
	return nil
}

// FetchServerFolders returns server folder listing
func (a *App) FetchServerFolders() ([]ServerItem, error) {
	err := a.engine.EnsureAuthenticated("")
	if err != nil {
		if strings.Contains(err.Error(), "network") || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "timeout") {
			a.reconnectMgr.MarkDisconnected("connection failed")
			if a.ctx != nil {
				wailsRuntime.EventsEmit(a.ctx, "connection-state", false)
			}
		}
		return nil, err
	}
	items, err := a.engine.FetchServerFolderTree()
	if err != nil {
		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "timeout") {
			a.reconnectMgr.MarkDisconnected(err.Error())
			if a.ctx != nil {
				wailsRuntime.EventsEmit(a.ctx, "connection-state", false)
			}
		}
		return nil, err
	}
	a.reconnectMgr.MarkConnected()
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "connection-state", true)
	}
	return items, nil
}

// CheckSMARTStatus gathers server, local, and client drives in proper section order
func (a *App) CheckSMARTStatus() CombinedSmartData {
	result := CombinedSmartData{}

	// 1. Local SMART drives
	localHealthy, localDisks, _ := CheckLocalSMARTHealth()
	result.LocalDisks = localDisks

	// 2. Server & Remote Client drives
	_ = a.engine.EnsureAuthenticated("")
	healthy, isTest, serverDisks, clientReports, err := a.engine.CheckSMARTDriveHealth()
	result.ServerDisks = serverDisks
	result.IsTest = isTest
	result.OverallHealthy = healthy && localHealthy

	if err != nil {
		result.Error = err.Error()
		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "timeout") {
			a.reconnectMgr.MarkDisconnected(err.Error())
			if a.ctx != nil {
				wailsRuntime.EventsEmit(a.ctx, "connection-state", false)
			}
		}
	} else {
		a.reconnectMgr.MarkConnected()
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "connection-state", true)
		}
	}

	// 3. Other IP client groups
	groupMap := make(map[string]*ClientGroupInfo)
	for _, cr := range clientReports {
		clientIP := "Unknown IP"
		if strings.Contains(cr.Client, "(") {
			s := strings.LastIndex(cr.Client, "(")
			e := strings.LastIndex(cr.Client, ")")
			if s != -1 && e != -1 && e > s {
				clientIP = cr.Client[s+1 : e]
			}
		}
		grp, exists := groupMap[clientIP]
		if !exists {
			grp = &ClientGroupInfo{
				IP:     clientIP,
				Client: cr.Client,
				Disks:  []SmartDiskInfo{},
			}
			groupMap[clientIP] = grp
		}
		for _, d := range cr.Failing {
			if d.IP == "" {
				d.IP = clientIP
			}
			grp.Disks = append(grp.Disks, d)
		}
	}

	for _, g := range groupMap {
		result.ClientGroups = append(result.ClientGroups, *g)
	}

	return result
}

// MuteSmartAlerts mutes alert popups for 12 hours
func (a *App) MuteSmartAlerts() {
	a.engine.MuteSmartAlerts(12 * time.Hour)
}

// GetStartupOnBoot returns whether run on startup is enabled
func (a *App) GetStartupOnBoot() bool {
	return IsRunOnStartupEnabled()
}

// SetStartupOnBoot enables or disables run on startup
func (a *App) SetStartupOnBoot(enabled bool) error {
	return SetRunOnStartup(enabled)
}

// GetStatus returns the current status message
func (a *App) GetStatus() string {
	return a.engine.GetStatus()
}

// IsConnected returns whether the client is currently connected to LinNAS
func (a *App) IsConnected() bool {
	return !a.reconnectMgr.IsDisconnected() && a.engine.isLoggedIn
}

// TriggerRefresh performs updates based on the configured "On refresh update" target
func (a *App) TriggerRefresh(manualTarget string) {
	target := manualTarget
	if target == "" {
		target = a.cfg.RefreshTarget
	}
	target = strings.ToLower(target)

	shouldCloud := target == "cloud only" || target == "cloud and smart" || target == ""
	shouldSmart := target == "smart only" || target == "cloud and smart" || target == ""

	if shouldCloud {
		go func() {
			_, _ = a.FetchServerFolders()
		}()
	}

	if shouldSmart {
		go func() {
			_ = a.CheckSMARTStatus()
		}()
	}
}

// Background scheduler worker
func (a *App) startBackgroundWorker() {
	time.Sleep(2 * time.Second)

	_ = a.engine.EnsureAuthenticated("")
	go a.CheckSMARTStatus()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastSyncPass time.Time

	for {
		select {
		case <-ticker.C:
			// Check reconnection retry
			if a.reconnectMgr.IsDisconnected() && a.reconnectMgr.ShouldAttemptRetry() {
				a.engine.SetStatus("Reconnecting to LinNAS server...")
				err := a.engine.EnsureAuthenticated("")
				if err == nil {
					a.reconnectMgr.MarkConnected()
				} else {
					a.reconnectMgr.MarkDisconnected("server still unreachable")
				}
			}

			// Periodic sync & SMART health check
			now := time.Now()
			intervalSec := a.cfg.SyncIntervalSec
			if intervalSec < 120 {
				intervalSec = 120
			}

			if now.Sub(lastSyncPass) >= time.Duration(intervalSec)*time.Second {
				lastSyncPass = now

				// Respect SyncMode: disabled vs timer vs on idle
				isSyncDisabled := a.cfg.SyncMode == "disabled" || !a.cfg.SyncEnabled
				if !isSyncDisabled {
					if a.reconnectMgr.IsDisconnected() {
						a.reconnectMgr.RecordMissedTimerSync()
					} else {
						if a.cfg.SyncMode != "on idle" && !a.cfg.IdleOnly {
							go func() {
								_ = a.engine.PerformSync("")
							}()
						}
					}
				}
				go a.CheckSMARTStatus()
			}
		case <-a.engine.stopChan:
			return
		}
	}
}
