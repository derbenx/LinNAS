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

func formatInterval(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%d secs", seconds)
	}
	mins := seconds / 60
	hours := mins / 60
	remainMins := mins % 60
	if hours > 0 {
		if remainMins == 0 {
			if hours == 1 {
				return "1 hour"
			}
			return fmt.Sprintf("%d hours", hours)
		}
		return fmt.Sprintf("%d hr %d min", hours, remainMins)
	}
	return fmt.Sprintf("%d mins", mins)
}

func main() {
	a := app.NewWithID("com.linnas.cloudclient")
	w := a.NewWindow("LinNAS Local Cloud")

	// Fit on a single monitor: default to 740x540, center on screen, allow user resize
	initW := float32(740)
	initH := float32(540)
	w.Resize(fyne.NewSize(initW, initH))
	w.CenterOnScreen()

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

	appendLog := func(msg string) {
		fyne.Do(func() {
			timestamp := time.Now().Format("15:04:05")
			current := logEntry.Text
			newEntry := fmt.Sprintf("[%s] %s\n", timestamp, msg)

			// Memory / log rotation: keep last 12,000 characters to prevent excessive growth
			if len(current) > 15000 {
				lines := strings.Split(current, "\n")
				if len(lines) > 100 {
					current = strings.Join(lines[len(lines)-100:], "\n")
				}
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

	pauseCheck := widget.NewCheck("Enable automatic syncing", func(checked bool) {
		cfg.SyncEnabled = checked
	})
	pauseCheck.SetChecked(cfg.SyncEnabled)

	// Sync mode dropdown: "On a timer" or "When idle for"
	modeSelect := widget.NewSelect([]string{"On a timer", "When idle for"}, func(selected string) {
		cfg.SyncMode = selected
		cfg.IdleOnly = (selected == "When idle for")
	})
	if cfg.SyncMode == "" {
		cfg.SyncMode = "On a timer"
	}
	modeSelect.SetSelected(cfg.SyncMode)

	// Interval Slider: 2 minutes (120s) to 5 hours (18000s)
	if cfg.SyncIntervalSec < 120 {
		cfg.SyncIntervalSec = 300 // default 5 mins
	}
	freqSlider := widget.NewSlider(120, 18000)
	freqSlider.SetValue(float64(cfg.SyncIntervalSec))
	freqLabel := widget.NewLabel(formatInterval(cfg.SyncIntervalSec))
	freqLabel.TextStyle = fyne.TextStyle{Bold: true}

	freqSlider.OnChanged = func(val float64) {
		secs := int(val)
		// Round to nearest 30 seconds for clean intervals
		secs = (secs / 30) * 30
		if secs < 120 {
			secs = 120
		}
		freqLabel.SetText(formatInterval(secs))
		cfg.SyncIntervalSec = secs
	}

	syncNowBtn := widget.NewButtonWithIcon("Sync Files Now", theme.MediaPlayIcon(), func() {
		pwd := pwdEntry.Text
		go func() {
			engine.SetStatus("Manual sync initiated...")
			err := engine.PerformSync(pwd)
			if err != nil {
				engine.SetStatus("Sync Error: " + err.Error())
			}
		}()
	})

	saveConnBtn := widget.NewButtonWithIcon("Save Connection & Preferences", theme.DocumentSaveIcon(), func() {
		cfg.ServerEndpoint = strings.TrimSpace(endpointEntry.Text)
		cfg.Username = strings.TrimSpace(userEntry.Text)
		if strings.TrimSpace(pwdEntry.Text) != "" {
			cfg.PasswordHash = HashPassword(pwdEntry.Text)
			cfg.SessionToken = ""
			pwdEntry.SetText("")
			pwdEntry.SetPlaceHolder("•••••••• (Credentials Saved)")
		}
		cfg.SyncEnabled = pauseCheck.Checked
		cfg.SyncMode = modeSelect.Selected
		cfg.IdleOnly = (modeSelect.Selected == "When idle for")
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
		widget.NewLabelWithStyle("Automatic Sync Scheduling", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		pauseCheck,
		container.NewHBox(widget.NewLabel("Sync mode:"), modeSelect),
		container.NewBorder(nil, nil, widget.NewLabel("Interval / Wait:"), freqLabel, freqSlider),
		widget.NewSeparator(),
		container.NewHBox(saveConnBtn, syncNowBtn),
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
	// TAB 3: SMART Drive Monitoring (Glanceable Tiles, No Scrollbar)
	// ==========================================
	smartTilesContainer := container.NewGridWithColumns(2)

	refreshSmart := func() {
		fyne.Do(func() {
			smartTilesContainer.Objects = nil
			smartTilesContainer.Add(widget.NewLabel("Checking server drive SMART status..."))
			smartTilesContainer.Refresh()
		})

		pwd := pwdEntry.Text
		go func() {
			_ = engine.EnsureAuthenticated(pwd)
			_, disks, err := engine.CheckSMARTDriveHealth()

			fyne.Do(func() {
				smartTilesContainer.Objects = nil

				if err != nil {
					smartTilesContainer.Add(widget.NewLabel("Could not fetch SMART status: " + err.Error()))
					smartTilesContainer.Refresh()
					return
				}

				if len(disks) == 0 {
					smartTilesContainer.Add(widget.NewLabel("No physical storage disks detected or SMART unavailable."))
				}

				for _, d := range disks {
					// Title with drive name and first partition name
					titleName := d.Device
					if d.FirstPartName != "" {
						titleName = fmt.Sprintf("%s (%s)", d.Device, d.FirstPartName)
					}

					// Health text with bold colors: green for PASSED, red for FAILED
					statusColorText := canvas.NewText("", color.White)
					statusColorText.TextStyle = fyne.TextStyle{Bold: true}

					isFail := (d.Health == "FAILED")
					isPassed := (d.Health == "PASSED")

					if isFail {
						statusColorText.Text = "Status: ❌ FAILED"
						statusColorText.Color = color.RGBA{R: 255, G: 60, B: 60, A: 255}
					} else if isPassed {
						statusColorText.Text = "Status: ✅ PASSED"
						statusColorText.Color = color.RGBA{R: 50, G: 205, B: 50, A: 255}
					} else {
						statusColorText.Text = "Status: ℹ️ UNKNOWN (OK)"
						statusColorText.Color = color.RGBA{R: 120, G: 180, B: 255, A: 255}
					}

					detailsText := fmt.Sprintf("Model: %s\nSize: %s", d.Model, d.Capacity)
					tileContent := container.NewVBox(
						statusColorText,
						widget.NewLabel(detailsText),
					)

					card := widget.NewCard(titleName, "", tileContent)
					smartTilesContainer.Add(card)
				}
				smartTilesContainer.Refresh()
			})
		}()
	}

	refreshSmartBtn := widget.NewButtonWithIcon("Refresh SMART Data", theme.ViewRefreshIcon(), refreshSmart)
	smartHeader := container.NewHBox(
		widget.NewLabelWithStyle("Server Storage SMART Diagnostics", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		refreshSmartBtn,
	)
	// Border container with NO scrollbar to fit everything at a glance
	smartTab := container.NewBorder(smartHeader, nil, nil, nil, smartTilesContainer)

	// ==========================================
	// TAB 4: Activity & Error Logs
	// ==========================================
	logHeader := container.NewHBox(
		widget.NewLabelWithStyle("Activity & Error Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		clearLogBtn,
	)
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
			if interval < 120 {
				interval = 120
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
