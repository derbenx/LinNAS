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

func createCompactSmartTile(d SmartDiskInfo) fyne.CanvasObject {
	// Clean device name (e.g. "sda" instead of "/dev/sda" or "(sda1)")
	devName := strings.TrimPrefix(d.Device, "/dev/")
	headerText := devName
	if d.PartLabel != "" && d.PartLabel != devName {
		headerText = fmt.Sprintf("%s [%s]", devName, d.PartLabel)
	}
	if len(headerText) > 18 {
		headerText = headerText[:16] + ".."
	}

	nameLabel := canvas.NewText(headerText, color.White)
	nameLabel.TextStyle = fyne.TextStyle{Bold: true}
	nameLabel.TextSize = 11

	modelText := d.Model
	if len(modelText) > 18 {
		modelText = modelText[:16] + ".."
	}
	modelLabel := canvas.NewText(modelText, color.RGBA{R: 190, G: 190, B: 190, A: 255})
	modelLabel.TextSize = 9

	statusColorText := canvas.NewText("", color.White)
	statusColorText.TextStyle = fyne.TextStyle{Bold: true}
	statusColorText.TextSize = 10

	isFail := (d.Health == "FAILED")
	isPassed := (d.Health == "PASSED")

	if isFail {
		statusColorText.Text = "❌ FAIL"
		statusColorText.Color = color.RGBA{R: 255, G: 60, B: 60, A: 255}
	} else if isPassed {
		statusColorText.Text = "✅ PASS"
		statusColorText.Color = color.RGBA{R: 50, G: 205, B: 50, A: 255}
	} else {
		statusColorText.Text = "ℹ️ OK"
		statusColorText.Color = color.RGBA{R: 120, G: 180, B: 255, A: 255}
	}

	capText := d.Capacity
	if d.TempC > 0 {
		capText = fmt.Sprintf("%s 🌡️ %d°C", d.Capacity, d.TempC)
	}
	capLabel := canvas.NewText(capText, color.RGBA{R: 180, G: 180, B: 180, A: 255})
	capLabel.TextSize = 9

	tileBox := container.NewVBox(
		nameLabel,
		modelLabel,
		statusColorText,
		capLabel,
	)

	return widget.NewCard("", "", container.NewPadded(tileBox))
}

func main() {
	a := app.NewWithID("com.linnas.cloudclient")
	w := a.NewWindow("LinNAS Local Cloud")

	initW := float32(760)
	initH := float32(560)
	w.Resize(fyne.NewSize(initW, initH))
	w.CenterOnScreen()

	cfg := LoadConfig()
	engine, err := NewSyncEngine(cfg)
	if err != nil {
		fmt.Println("Error initializing sync engine:", err)
	}

	// Status indicator badge
	statusLabel := widget.NewLabel("Status: " + engine.GetStatus())
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	engine.onStatus = func(msg string) {
		fyne.Do(func() {
			shortMsg := msg
			if len(shortMsg) > 35 {
				shortMsg = shortMsg[:32] + "..."
			}
			statusLabel.SetText("Status: " + shortMsg)
		})
	}

	smartAlertActive := false

	// SMART alert notification: persistent toaster window in corner that stays open until muted/acknowledged
	engine.onSmartAlert = func(alert string, isTest bool) {
		fyne.Do(func() {
			if smartAlertActive || engine.IsSmartAlertMuted() {
				return // Do not spawn duplicate alert if one is already open or muted
			}
			smartAlertActive = true

			toastW := float32(520)
			toastH := float32(280)
			alertWin := a.NewWindow("⚠️ SMART Hardware Alert")
			alertWin.Resize(fyne.NewSize(toastW, toastH))
			alertWin.SetFixedSize(true)

			titleText := canvas.NewText("", color.White)
			titleText.TextStyle = fyne.TextStyle{Bold: true}
			titleText.TextSize = 14

			subLabel := widget.NewLabel("")
			subLabel.Wrapping = fyne.TextWrapWord

			if isTest {
				titleText.Text = "⚠️ THIS IS A TEST! Simulated SMART Drive Failure"
				titleText.Color = color.RGBA{R: 255, G: 220, B: 0, A: 255}
				subLabel.SetText("Test mode active: Simulated hardware failures detected:")
			} else {
				titleText.Text = "❌ CRITICAL DRIVE FAILURE DETECTED"
				titleText.Color = color.RGBA{R: 255, G: 60, B: 60, A: 255}
				subLabel.SetText("Attention required: The following drives failed SMART:")
			}

			// Scrollable, selectable, word-wrapped text area so text never forces window expansion
			msgEntry := widget.NewMultiLineEntry()
			msgEntry.Wrapping = fyne.TextWrapWord
			msgEntry.SetText(alert)

			muteBtn := widget.NewButtonWithIcon("Mute SMART Alerts (12h)", theme.VolumeMuteIcon(), func() {
				engine.MuteSmartAlerts(12 * time.Hour)
				smartAlertActive = false
				alertWin.Close()
			})

			alertWin.SetContent(container.NewBorder(
				container.NewVBox(titleText, subLabel, widget.NewSeparator()),
				container.NewVBox(widget.NewSeparator(), muteBtn),
				nil, nil,
				msgEntry,
			))

			alertWin.SetOnClosed(func() {
				smartAlertActive = false
			})

			// Position toast at bottom-right corner of screen
			positionWindowBottomRight(alertWin, int(toastW), int(toastH))
			alertWin.Show()
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

	logToFileCheck := widget.NewCheck("Log activity to file (debug.log, max 1MB)", func(checked bool) {
		cfg.LogToFile = checked
	})
	logToFileCheck.SetChecked(cfg.LogToFile)

	modeSelect := widget.NewSelect([]string{"On a timer", "When idle for"}, func(selected string) {
		cfg.SyncMode = selected
		cfg.IdleOnly = (selected == "When idle for")
	})
	if cfg.SyncMode == "" {
		cfg.SyncMode = "On a timer"
	}
	modeSelect.SetSelected(cfg.SyncMode)

	if cfg.SyncIntervalSec < 120 {
		cfg.SyncIntervalSec = 300
	}
	freqSlider := widget.NewSlider(120, 18000)
	freqSlider.SetValue(float64(cfg.SyncIntervalSec))
	freqLabel := widget.NewLabel(formatInterval(cfg.SyncIntervalSec))
	freqLabel.TextStyle = fyne.TextStyle{Bold: true}

	freqSlider.OnChanged = func(val float64) {
		secs := int(val)
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
		cfg.LogToFile = logToFileCheck.Checked
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
		widget.NewLabelWithStyle("Diagnostics & Logging", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		logToFileCheck,
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
	treeScroll := container.NewScroll(treeBox)
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
					errShort := err.Error()
					if len(errShort) > 35 {
						errShort = errShort[:32] + "..."
					}
					treeBox.Add(widget.NewLabel("Could not load folders: " + errShort))
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

	// ==========================================
	// TAB 3: Server SMART (Square tiles, 4-5 across default width)
	// ==========================================
	serverSmartBannerBox := container.NewVBox()
	smartTilesContainer := container.NewGridWrap(fyne.NewSize(135, 88))
	serverSmartScroll := container.NewScroll(container.NewVBox(
		serverSmartBannerBox,
		smartTilesContainer,
	))

	refreshSmart := func() {
		fyne.Do(func() {
			serverSmartBannerBox.Objects = nil
			smartTilesContainer.Objects = nil
			smartTilesContainer.Add(widget.NewLabel("Checking server drive SMART status..."))
			smartTilesContainer.Refresh()
		})

		pwd := pwdEntry.Text
		go func() {
			_ = engine.EnsureAuthenticated(pwd)
			healthy, isTest, disks, clientReports, err := engine.CheckSMARTDriveHealth()

			fyne.Do(func() {
				serverSmartBannerBox.Objects = nil
				smartTilesContainer.Objects = nil

				if err != nil {
					errShort := err.Error()
					if len(errShort) > 35 {
						errShort = errShort[:32] + "..."
					}
					smartTilesContainer.Add(widget.NewLabel("SMART status error: " + errShort))
					smartTilesContainer.Refresh()
					return
				}

				if isTest {
					testBanner := canvas.NewText("⚠️ THIS IS A TEST! (Simulated Bad Drives Alert)", color.RGBA{R: 255, G: 215, B: 0, A: 255})
					testBanner.TextStyle = fyne.TextStyle{Bold: true}
					serverSmartBannerBox.Add(testBanner)
					serverSmartBannerBox.Add(widget.NewSeparator())
				} else if !healthy {
					failBanner := canvas.NewText("❌ WARNING: Critical SMART Hardware Failure!", color.RGBA{R: 255, G: 60, B: 60, A: 255})
					failBanner.TextStyle = fyne.TextStyle{Bold: true}
					serverSmartBannerBox.Add(failBanner)
					serverSmartBannerBox.Add(widget.NewSeparator())
				}

				for _, cr := range clientReports {
					for _, fd := range cr.Failing {
						fd.Model = fmt.Sprintf("Client %s (%s)", cr.Client, fd.Model)
						smartTilesContainer.Add(createCompactSmartTile(fd))
					}
				}

				if len(disks) == 0 {
					smartTilesContainer.Add(widget.NewLabel("No server storage disks detected."))
				}

				for _, d := range disks {
					smartTilesContainer.Add(createCompactSmartTile(d))
				}
				serverSmartBannerBox.Refresh()
				smartTilesContainer.Refresh()
			})
		}()
	}

	refreshSmartBtn := widget.NewButtonWithIcon("Refresh SMART Data", theme.ViewRefreshIcon(), refreshSmart)
	smartHeader := container.NewHBox(
		widget.NewLabelWithStyle("Server Storage SMART Diagnostics", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		refreshSmartBtn,
	)
	smartTab := container.NewBorder(smartHeader, nil, nil, nil, serverSmartScroll)

	// ==========================================
	// TAB 4: Local SMART (Square tiles, 4-5 across default width)
	// ==========================================
	localSmartBannerBox := container.NewVBox()
	localSmartTilesContainer := container.NewGridWrap(fyne.NewSize(135, 88))
	localSmartScroll := container.NewScroll(container.NewVBox(
		localSmartBannerBox,
		localSmartTilesContainer,
	))

	refreshLocalSmart := func() {
		fyne.Do(func() {
			localSmartBannerBox.Objects = nil
			localSmartTilesContainer.Objects = nil
			localSmartTilesContainer.Add(widget.NewLabel("Checking local drive health..."))
			localSmartTilesContainer.Refresh()
		})

		go func() {
			localHealthy, localDisks, _ := CheckLocalSMARTHealth()

			fyne.Do(func() {
				localSmartBannerBox.Objects = nil
				localSmartTilesContainer.Objects = nil

				if !localHealthy {
					failBanner := canvas.NewText("❌ Local Drive Failure Detected!", color.RGBA{R: 255, G: 60, B: 60, A: 255})
					failBanner.TextStyle = fyne.TextStyle{Bold: true}
					localSmartBannerBox.Add(failBanner)
					localSmartBannerBox.Add(widget.NewSeparator())
				} else {
					okBanner := canvas.NewText("✅ All Local Disks Healthy", color.RGBA{R: 50, G: 205, B: 50, A: 255})
					okBanner.TextStyle = fyne.TextStyle{Bold: true}
					localSmartBannerBox.Add(okBanner)
					localSmartBannerBox.Add(widget.NewSeparator())
				}

				for _, ld := range localDisks {
					localSmartTilesContainer.Add(createCompactSmartTile(ld))
				}
				localSmartBannerBox.Refresh()
				localSmartTilesContainer.Refresh()
			})
		}()
	}

	refreshLocalSmartBtn := widget.NewButtonWithIcon("Refresh Local Disks", theme.ViewRefreshIcon(), refreshLocalSmart)
	localSmartHeader := container.NewHBox(
		widget.NewLabelWithStyle("Local PC Storage Health", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		refreshLocalSmartBtn,
	)
	localSmartTab := container.NewBorder(localSmartHeader, nil, nil, nil, localSmartScroll)

	// Main Layout Tabs
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Connection", theme.SettingsIcon(), connScroll),
		container.NewTabItemWithIcon("Folders & Sync", theme.FolderIcon(), foldersScroll),
		container.NewTabItemWithIcon("Server SMART", theme.WarningIcon(), smartTab),
		container.NewTabItemWithIcon("Local SMART", theme.ComputerIcon(), localSmartTab),
	)

	bottomBar := container.NewBorder(
		nil, nil,
		statusLabel,
		nil,
	)
	mainContent := container.NewBorder(nil, bottomBar, nil, nil, tabs)
	w.SetContent(mainContent)

	// System Tray Integration with right-click menu items for Local SMART and Server SMART
	if desk, ok := a.(desktop.App); ok {
		menu := fyne.NewMenu("LinNAS Cloud",
			fyne.NewMenuItem("Open Client", func() {
				w.Show()
			}),
			fyne.NewMenuItem("View Local SMART Health", func() {
				w.Show()
				tabs.SelectIndex(3) // Switch to Local SMART
				refreshLocalSmart()
			}),
			fyne.NewMenuItem("View Server SMART Health", func() {
				w.Show()
				tabs.SelectIndex(2) // Switch to Server SMART
				refreshSmart()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Sync Now", func() {
				var pwd string
				fyne.DoAndWait(func() {
					defer func() { _ = recover() }()
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

		w.SetCloseIntercept(func() {
			w.Hide()
		})
	}

	// Periodic Background Lazy Sync Worker
	go func() {
		time.Sleep(3 * time.Second)
		// Guard against background refreshes pushing window width if Fyne recalculates
		currSize := w.Canvas().Size()
		if currSize.Width < initW || currSize.Height < initH {
			w.Resize(fyne.NewSize(initW, initH))
		}

		refreshTree()
		refreshSmart()
		refreshLocalSmart()

		for {
			interval := cfg.SyncIntervalSec
			if interval < 120 {
				interval = 120
			}
			time.Sleep(time.Duration(interval) * time.Second)

			if cfg.SyncEnabled {
				var pwd string
				fyne.DoAndWait(func() {
					defer func() { _ = recover() }()
					pwd = pwdEntry.Text
				})
				_ = engine.PerformSync(pwd)
			}
			refreshSmart()
			refreshLocalSmart()
		}
	}()

	w.ShowAndRun()
}
