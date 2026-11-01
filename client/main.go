package main

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.NewWithID("com.linnas.cloudclient")
	w := a.NewWindow("LinNAS Local Cloud")
	w.Resize(fyne.NewSize(720, 580))
	w.SetFixedSize(true) // Prevent window from expanding and stretching off screen

	cfg := LoadConfig()
	engine, err := NewSyncEngine(cfg)
	if err != nil {
		fmt.Println("Error initializing sync engine:", err)
	}

	// Concise Status indicator badge (strictly truncated to prevent expanding the window)
	statusLabel := widget.NewLabel("Status: " + engine.GetStatus())
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	// High contrast, scrollable, selectable, copy-pasteable Activity & Error Log Area
	logEntry := widget.NewMultiLineEntry()
	logEntry.Wrapping = fyne.TextWrapWord
	logEntry.SetPlaceHolder("Log entries and sync errors will appear here...")
	// Keep enabled for maximum contrast (white on dark background) while intercepting edits
	logEntry.OnChanged = func(s string) {
		// Prevent accidental user editing while preserving copy-paste selection
	}

	appendLog := func(msg string) {
		fyne.Do(func() {
			timestamp := time.Now().Format("15:04:05")
			current := logEntry.Text
			newEntry := fmt.Sprintf("[%s] %s\n", timestamp, msg)
			if len(current) > 20000 {
				current = current[len(current)-15000:]
			}
			logEntry.SetText(current + newEntry)
			logEntry.CursorRow = strings.Count(logEntry.Text, "\n")
		})
	}

	clearLogBtn := widget.NewButtonWithIcon("Clear Log", theme.DeleteIcon(), func() {
		logEntry.SetText("")
	})

	engine.onStatus = func(msg string) {
		fyne.Do(func() {
			shortMsg := msg
			if len(shortMsg) > 35 {
				shortMsg = shortMsg[:32] + "..."
			}
			statusLabel.SetText("Status: " + shortMsg)
		})
		appendLog(msg)
	}

	// SMART alert notification
	engine.onSmartAlert = func(alert string) {
		fyne.Do(func() {
			a.SendNotification(fyne.NewNotification("LinNAS Drive Warning", alert))
		})
	}

	// ==========================================
	// TAB 1: Server Connection & Sync Settings
	// ==========================================
	endpointEntry := widget.NewEntry()
	endpointEntry.SetPlaceHolder("192.168.1.50:8080")
	endpointEntry.SetText(cfg.ServerEndpoint)

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("admin")
	userEntry.SetText(cfg.Username)

	pwdEntry := widget.NewPasswordEntry()
	if cfg.PasswordHash != "" || cfg.SessionToken != "" {
		pwdEntry.SetPlaceHolder("•••••••• (Credentials Saved)")
	} else {
		pwdEntry.SetPlaceHolder("Enter password to connect")
	}

	pauseCheck := widget.NewCheck("Enable Background Syncing", func(checked bool) {
		cfg.SyncEnabled = checked
	})
	pauseCheck.SetChecked(cfg.SyncEnabled)

	freqSlider := widget.NewSlider(5, 300)
	freqSlider.SetValue(float64(cfg.SyncIntervalSec))
	freqLabel := widget.NewLabel(fmt.Sprintf("%d seconds", cfg.SyncIntervalSec))
	freqSlider.OnChanged = func(val float64) {
		secs := int(val)
		freqLabel.SetText(fmt.Sprintf("%d seconds", secs))
		cfg.SyncIntervalSec = secs
	}

	idleCheck := widget.NewCheck("Only perform backup/uploads when computer is idle", func(checked bool) {
		cfg.IdleOnly = checked
	})
	idleCheck.SetChecked(cfg.IdleOnly)

	saveConnBtn := widget.NewButtonWithIcon("Save Connection & Preferences", theme.DocumentSaveIcon(), func() {
		cfg.ServerEndpoint = strings.TrimSpace(endpointEntry.Text)
		cfg.Username = strings.TrimSpace(userEntry.Text)
		if strings.TrimSpace(pwdEntry.Text) != "" {
			// Hash password immediately so plaintext password is never written to disk
			cfg.PasswordHash = HashPassword(pwdEntry.Text)
			cfg.SessionToken = "" // Invalidate old session token for new password
			pwdEntry.SetText("")
			pwdEntry.SetPlaceHolder("•••••••• (Credentials Saved)")
		}
		cfg.SyncEnabled = pauseCheck.Checked
		cfg.IdleOnly = idleCheck.Checked
		cfg.SyncIntervalSec = int(freqSlider.Value)

		if err := SaveConfig(cfg); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to save connection: %w", err), w)
			return
		}
		engine.UpdateConfig(cfg)
		dialog.ShowInformation("Saved", "Connection settings and sync preferences have been saved securely.", w)
	})

	connTabContent := container.NewVBox(
		widget.NewLabelWithStyle("LinNAS Server Connection", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("Server Endpoint (IP:Port)", endpointEntry),
			widget.NewFormItem("Username", userEntry),
			widget.NewFormItem("Password", pwdEntry),
		),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Sync Frequency & Performance", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, widget.NewLabel("Background check interval:"), freqLabel, freqSlider),
		pauseCheck,
		idleCheck,
		widget.NewSeparator(),
		saveConnBtn,
	)
	connScroll := container.NewVScroll(connTabContent)

	// ==========================================
	// TAB 2: Folders & Selective Sync
	// ==========================================
	localDirEntry := widget.NewEntry()
	localDirEntry.SetText(cfg.LocalSyncDir)

	browseLocalBtn := widget.NewButtonWithIcon("Browse...", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err == nil && lu != nil {
				localDirEntry.SetText(lu.Path())
				cfg.LocalSyncDir = lu.Path()
			}
		}, w)
	})
	localFolderRow := container.NewBorder(nil, nil, nil, browseLocalBtn, localDirEntry)

	treeBox := container.NewVBox()
	treeScroll := container.NewVScroll(treeBox)
	treeScroll.SetMinSize(fyne.NewSize(660, 220))

	refreshTree := func() {
		fyne.Do(func() {
			treeBox.Objects = nil
			treeBox.Add(widget.NewLabel("Fetching server folders..."))
			treeBox.Refresh()
		})

		pwd := pwdEntry.Text
		go func() {
			_ = engine.EnsureAuthenticated(pwd)
			dirs, err := engine.FetchServerFolderTree()

			fyne.Do(func() {
				treeBox.Objects = nil

				if err != nil {
					treeBox.Add(widget.NewLabel("Could not load server folders: " + err.Error()))
					treeBox.Refresh()
					return
				}

				if len(dirs) == 0 {
					rootCheck := widget.NewCheck("📁 / (Root Cloud Folder - Sync Everything)", func(b bool) {
						cfg.SelectedFolders = make(map[string]bool)
					})
					rootCheck.SetChecked(len(cfg.SelectedFolders) == 0)
					treeBox.Add(rootCheck)
				} else {
					rootCheck := widget.NewCheck("📁 / (Root Cloud Folder)", func(b bool) {
						if b {
							cfg.SelectedFolders = make(map[string]bool)
						}
					})
					rootCheck.SetChecked(len(cfg.SelectedFolders) == 0)
					treeBox.Add(rootCheck)

					for _, d := range dirs {
						dirRel := d.RelPath
						chk := widget.NewCheck("📁 "+dirRel, func(checked bool) {
							if cfg.SelectedFolders == nil {
								cfg.SelectedFolders = make(map[string]bool)
							}
							cfg.SelectedFolders[dirRel] = checked
							if checked {
								parts := strings.Split(dirRel, "/")
								curr := ""
								for _, p := range parts {
									if curr == "" {
										curr = p
									} else {
										curr = curr + "/" + p
									}
									cfg.SelectedFolders[curr] = true
								}
							}
						})
						chk.SetChecked(cfg.SelectedFolders[dirRel])
						treeBox.Add(chk)
					}
				}
				treeBox.Refresh()
			})
		}()
	}

	refreshTreeBtn := widget.NewButtonWithIcon("Refresh Folders", theme.ViewRefreshIcon(), refreshTree)

	saveFoldersBtn := widget.NewButtonWithIcon("Save Folder Settings", theme.DocumentSaveIcon(), func() {
		cfg.LocalSyncDir = strings.TrimSpace(localDirEntry.Text)
		if err := SaveConfig(cfg); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to save folder configuration: %w", err), w)
			return
		}
		engine.UpdateConfig(cfg)
		dialog.ShowInformation("Folders Saved", "Local sync folder and selective sync preferences saved.", w)
	})

	foldersTabContent := container.NewVBox(
		widget.NewLabelWithStyle("Local Synchronization Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		localFolderRow,
		widget.NewSeparator(),
		container.NewHBox(
			widget.NewLabelWithStyle("Server Selective Sync", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			refreshTreeBtn,
		),
		widget.NewLabel("Check the folders on the server you wish to sync to your local PC:"),
		treeScroll,
		widget.NewSeparator(),
		saveFoldersBtn,
	)
	foldersScroll := container.NewVScroll(foldersTabContent)

	// Actions: Sync Now
	syncNowBtn := widget.NewButtonWithIcon("Sync Now", theme.MediaPlayIcon(), func() {
		pwd := pwdEntry.Text
		go func() {
			engine.SetStatus("Manual sync initiated...")
			err := engine.PerformSync(pwd)
			if err != nil {
				engine.SetStatus("Sync Error: " + err.Error())
			}
		}()
	})

	syncNowBrowseBtn := widget.NewButtonWithIcon("Sync Folder Now...", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err == nil && lu != nil {
				pwd := pwdEntry.Text
				go func() {
					engine.SetStatus("Syncing specific folder: " + lu.Path())
					_ = engine.PerformSync(pwd)
				}()
			}
		}, w)
	})

	// ==========================================
	// TAB 3: SMART Drive Monitoring
	// ==========================================
	smartBox := container.NewVBox()
	smartScroll := container.NewVScroll(smartBox)
	smartScroll.SetMinSize(fyne.NewSize(660, 360))

	refreshSmart := func() {
		fyne.Do(func() {
			smartBox.Objects = nil
			smartBox.Add(widget.NewLabel("Checking server drive SMART status..."))
			smartBox.Refresh()
		})

		pwd := pwdEntry.Text
		go func() {
			_ = engine.EnsureAuthenticated(pwd)
			healthy, disks, err := engine.CheckSMARTDriveHealth()

			fyne.Do(func() {
				smartBox.Objects = nil

				if err != nil {
					smartBox.Add(widget.NewLabel("Could not fetch SMART status: " + err.Error()))
					smartBox.Refresh()
					return
				}

				banner := canvas.NewText("", color.White)
				if healthy {
					banner.Text = "✅ Storage Drives Healthy / No SMART Failures"
					banner.Color = color.RGBA{R: 50, G: 200, B: 50, A: 255}
				} else {
					banner.Text = "⚠️ WARNING: SMART Hardware Failures Detected on Server!"
					banner.Color = color.RGBA{R: 255, G: 50, B: 50, A: 255}
				}
				banner.TextStyle = fyne.TextStyle{Bold: true}
				smartBox.Add(banner)

				if len(disks) == 0 {
					smartBox.Add(widget.NewLabel("No physical storage disks detected or SMART unavailable."))
				}

				for _, d := range disks {
					healthBadge := d.Health
					if healthBadge == "UNKNOWN" {
						healthBadge = "UNKNOWN (No SMART errors)"
					}
					cardText := fmt.Sprintf("Device: %s\nModel: %s\nCapacity: %s\nStatus: %s", d.Device, d.Model, d.Capacity, healthBadge)
					card := widget.NewCard(d.Device, healthBadge, widget.NewLabel(cardText))
					smartBox.Add(card)
				}
				smartBox.Refresh()
			})
		}()
	}

	refreshSmartBtn := widget.NewButtonWithIcon("Refresh SMART Data", theme.ViewRefreshIcon(), refreshSmart)
	smartTab := container.NewBorder(
		container.NewHBox(
			widget.NewLabelWithStyle("Server SMART Drive Health", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			refreshSmartBtn,
		),
		nil, nil, nil,
		smartScroll,
	)

	// ==========================================
	// TAB 4: Activity & Error Logs
	// ==========================================
	logHeader := container.NewHBox(
		widget.NewLabelWithStyle("Activity & Error Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		clearLogBtn,
	)
	// Dark contrast background container for log area
	logTab := container.NewBorder(logHeader, nil, nil, nil, logEntry)

	// Main Layout Tabs
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Connection", theme.SettingsIcon(), connScroll),
		container.NewTabItemWithIcon("Folders & Sync", theme.FolderIcon(), foldersScroll),
		container.NewTabItemWithIcon("SMART Health", theme.WarningIcon(), smartTab),
		container.NewTabItemWithIcon("Logs & Errors", theme.DocumentIcon(), logTab),
	)

	bottomBar := container.NewBorder(
		nil, nil,
		statusLabel,
		container.NewHBox(syncNowBrowseBtn, syncNowBtn),
	)
	mainContent := container.NewBorder(nil, bottomBar, nil, nil, tabs)
	w.SetContent(mainContent)

	// System Tray Integration
	if desk, ok := a.(desktop.App); ok {
		menu := fyne.NewMenu("LinNAS Cloud",
			fyne.NewMenuItem("Open Client", func() {
				w.Show()
			}),
			fyne.NewMenuItem("Sync Now", func() {
				var pwd string
				fyne.DoAndWait(func() {
					pwd = pwdEntry.Text
				})
				go func() { _ = engine.PerformSync(pwd) }()
			}),
			fyne.NewMenuItem("Toggle Pause", func() {
				cfg.SyncEnabled = !cfg.SyncEnabled
				fyne.Do(func() {
					pauseCheck.SetChecked(cfg.SyncEnabled)
				})
				_ = SaveConfig(cfg)
				engine.UpdateConfig(cfg)
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit", func() {
				a.Quit()
			}),
		)
		desk.SetSystemTrayMenu(menu)
		desk.SetSystemTrayIcon(theme.StorageIcon())

		// Intercept close to minimize to tray
		w.SetCloseIntercept(func() {
			w.Hide()
		})
	}

	// Periodic Background Lazy Sync Worker
	go func() {
		time.Sleep(3 * time.Second)
		refreshTree()
		refreshSmart()

		for {
			interval := cfg.SyncIntervalSec
			if interval < 5 {
				interval = 5
			}
			time.Sleep(time.Duration(interval) * time.Second)

			if cfg.SyncEnabled {
				var pwd string
				fyne.DoAndWait(func() {
					pwd = pwdEntry.Text
				})
				_ = engine.PerformSync(pwd)
			}
		}
	}()

	w.ShowAndRun()
}
