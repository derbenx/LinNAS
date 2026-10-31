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
	w.Resize(fyne.NewSize(680, 520))

	cfg := LoadConfig()
	engine, err := NewSyncEngine(cfg)
	if err != nil {
		fmt.Println("Error initializing sync engine:", err)
	}

	// Status label
	statusLabel := widget.NewLabel("Status: " + engine.GetStatus())
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}
	engine.onStatus = func(msg string) {
		statusLabel.SetText("Status: " + msg)
	}

	// SMART alert notification
	engine.onSmartAlert = func(alert string) {
		a.SendNotification(fyne.NewNotification("LinNAS Drive Warning", alert))
	}

	// 1. Connection & Credentials Tab
	endpointEntry := widget.NewEntry()
	endpointEntry.SetPlaceHolder("192.168.1.50:8080")
	endpointEntry.SetText(cfg.ServerEndpoint)

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("admin")
	userEntry.SetText(cfg.Username)

	pwdEntry := widget.NewPasswordEntry()
	pwdEntry.SetPlaceHolder("Enter password (or leave blank if saved)")

	pauseCheck := widget.NewCheck("Enable Automatic Syncing", func(checked bool) {
		cfg.SyncEnabled = checked
		_ = SaveConfig(cfg)
		engine.UpdateConfig(cfg)
		if checked {
			engine.SetStatus("Sync Enabled")
		} else {
			engine.SetStatus("Sync Paused")
		}
	})
	pauseCheck.SetChecked(cfg.SyncEnabled)

	connSaveBtn := widget.NewButtonWithIcon("Save Connection", theme.DocumentSaveIcon(), func() {
		cfg.ServerEndpoint = strings.TrimSpace(endpointEntry.Text)
		cfg.Username = strings.TrimSpace(userEntry.Text)
		if pwdEntry.Text != "" {
			cfg.PasswordHash = HashPassword(pwdEntry.Text)
		}
		_ = SaveConfig(cfg)
		engine.UpdateConfig(cfg)
		dialog.ShowInformation("Saved", "Connection settings saved.", w)
	})

	connForm := widget.NewForm(
		widget.NewFormItem("Server Endpoint (IP:Port)", endpointEntry),
		widget.NewFormItem("Username", userEntry),
		widget.NewFormItem("Password", pwdEntry),
	)

	connTab := container.NewVBox(
		widget.NewLabelWithStyle("LinNAS Server Connection", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		connForm,
		pauseCheck,
		connSaveBtn,
	)

	// 2. Local & Server Folders (Selective Sync Tree)
	localDirEntry := widget.NewEntry()
	localDirEntry.SetText(cfg.LocalSyncDir)

	browseLocalBtn := widget.NewButtonWithIcon("Browse...", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err == nil && lu != nil {
				localDirEntry.SetText(lu.Path())
				cfg.LocalSyncDir = lu.Path()
				_ = SaveConfig(cfg)
				engine.UpdateConfig(cfg)
			}
		}, w)
	})

	localFolderRow := container.NewBorder(nil, nil, nil, browseLocalBtn, localDirEntry)

	// Folder Tree Checkbox Container
	treeBox := container.NewVBox()
	treeScroll := container.NewVScroll(treeBox)
	treeScroll.SetMinSize(fyne.NewSize(600, 200))

	refreshTree := func() {
		treeBox.Objects = nil
		treeBox.Add(widget.NewLabel("Fetching server folders..."))
		treeBox.Refresh()

		go func() {
			_ = engine.EnsureAuthenticated(pwdEntry.Text)
			dirs, err := engine.FetchServerFolderTree()
			treeBox.Objects = nil

			if err != nil {
				treeBox.Add(widget.NewLabel("Could not load server folders: " + err.Error()))
				treeBox.Refresh()
				return
			}

			if len(dirs) == 0 {
				rootCheck := widget.NewCheck("📁 / (Root Cloud Folder - Sync Everything)", func(b bool) {
					cfg.SelectedFolders = make(map[string]bool)
					_ = SaveConfig(cfg)
					engine.UpdateConfig(cfg)
				})
				rootCheck.SetChecked(len(cfg.SelectedFolders) == 0)
				treeBox.Add(rootCheck)
			} else {
				// Add root checkbox
				rootCheck := widget.NewCheck("📁 / (Root Cloud Folder)", func(b bool) {
					if b {
						cfg.SelectedFolders = make(map[string]bool)
					}
					_ = SaveConfig(cfg)
					engine.UpdateConfig(cfg)
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
						// Upward trace: check all parents
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
						_ = SaveConfig(cfg)
						engine.UpdateConfig(cfg)
					})
					chk.SetChecked(cfg.SelectedFolders[dirRel])
					treeBox.Add(chk)
				}
			}
			treeBox.Refresh()
		}()
	}

	refreshTreeBtn := widget.NewButtonWithIcon("Refresh Server Folders", theme.ViewRefreshIcon(), refreshTree)

	foldersTab := container.NewVBox(
		widget.NewLabelWithStyle("Local Sync Folder", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		localFolderRow,
		widget.NewSeparator(),
		container.NewHBox(
			widget.NewLabelWithStyle("Server Selective Sync", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			refreshTreeBtn,
		),
		widget.NewLabel("Check which folders you want synced locally to this machine:"),
		treeScroll,
	)

	// 3. Lazy Sync Settings Tab
	freqSlider := widget.NewSlider(5, 300)
	freqSlider.SetValue(float64(cfg.SyncIntervalSec))
	freqLabel := widget.NewLabel(fmt.Sprintf("%d seconds", cfg.SyncIntervalSec))
	freqSlider.OnChanged = func(val float64) {
		secs := int(val)
		freqLabel.SetText(fmt.Sprintf("%d seconds", secs))
		cfg.SyncIntervalSec = secs
		_ = SaveConfig(cfg)
		engine.UpdateConfig(cfg)
	}

	idleCheck := widget.NewCheck("Only perform backup/uploads when computer is idle", func(checked bool) {
		cfg.IdleOnly = checked
		_ = SaveConfig(cfg)
		engine.UpdateConfig(cfg)
	})
	idleCheck.SetChecked(cfg.IdleOnly)

	syncNowBtn := widget.NewButtonWithIcon("Sync Now", theme.MediaPlayIcon(), func() {
		go func() {
			engine.SetStatus("Manual sync initiated...")
			err := engine.PerformSync(pwdEntry.Text)
			if err != nil {
				engine.SetStatus("Sync Error: " + err.Error())
			}
		}()
	})

	syncNowBrowseBtn := widget.NewButtonWithIcon("Sync Folder Now...", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err == nil && lu != nil {
				go func() {
					engine.SetStatus("Syncing specific folder: " + lu.Path())
					_ = engine.PerformSync(pwdEntry.Text)
				}()
			}
		}, w)
	})

	settingsTab := container.NewVBox(
		widget.NewLabelWithStyle("Sync Frequency & Performance", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Background check interval:"),
		container.NewBorder(nil, nil, nil, freqLabel, freqSlider),
		widget.NewSeparator(),
		idleCheck,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Manual Actions", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewHBox(syncNowBtn, syncNowBrowseBtn),
	)

	// 4. SMART Drive Monitoring Tab
	smartBox := container.NewVBox()
	smartScroll := container.NewVScroll(smartBox)
	smartScroll.SetMinSize(fyne.NewSize(600, 200))

	refreshSmart := func() {
		smartBox.Objects = nil
		smartBox.Add(widget.NewLabel("Checking server drive SMART status..."))
		smartBox.Refresh()

		go func() {
			_ = engine.EnsureAuthenticated(pwdEntry.Text)
			healthy, disks, err := engine.CheckSMARTDriveHealth()
			smartBox.Objects = nil

			if err != nil {
				smartBox.Add(widget.NewLabel("Could not fetch SMART status: " + err.Error()))
				smartBox.Refresh()
				return
			}

			banner := canvas.NewText("", color.White)
			if healthy {
				banner.Text = "✅ All Storage Drives Healthy (SMART PASSED)"
				banner.Color = color.RGBA{R: 50, G: 200, B: 50, A: 255}
			} else {
				banner.Text = "⚠️ WARNING: SMART Hardware Failures Detected on Server!"
				banner.Color = color.RGBA{R: 255, G: 50, B: 50, A: 255}
			}
			banner.TextStyle = fyne.TextStyle{Bold: true}
			smartBox.Add(banner)

			for _, d := range disks {
				cardText := fmt.Sprintf("Drive: %s (%s, %s)\nHealth: %s", d.Device, d.Model, d.Capacity, d.Health)
				card := widget.NewCard(d.Device, d.Health, widget.NewLabel(cardText))
				smartBox.Add(card)
			}
			smartBox.Refresh()
		}()
	}

	refreshSmartBtn := widget.NewButtonWithIcon("Refresh SMART Data", theme.ViewRefreshIcon(), refreshSmart)
	smartTab := container.NewVBox(
		container.NewHBox(
			widget.NewLabelWithStyle("Server SMART Drive Health", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			refreshSmartBtn,
		),
		smartScroll,
	)

	// Main Layout
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Connection", theme.ComputerIcon(), connTab),
		container.NewTabItemWithIcon("Folders", theme.FolderIcon(), foldersTab),
		container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), settingsTab),
		container.NewTabItemWithIcon("SMART Health", theme.WarningIcon(), smartTab),
	)

	bottomBar := container.NewBorder(nil, nil, statusLabel, syncNowBtn)
	mainContent := container.NewBorder(nil, bottomBar, nil, nil, tabs)
	w.SetContent(mainContent)

	// System Tray Integration
	if desk, ok := a.(desktop.App); ok {
		menu := fyne.NewMenu("LinNAS Cloud",
			fyne.NewMenuItem("Open Client", func() {
				w.Show()
			}),
			fyne.NewMenuItem("Sync Now", func() {
				go func() { _ = engine.PerformSync(pwdEntry.Text) }()
			}),
			fyne.NewMenuItem("Toggle Pause", func() {
				cfg.SyncEnabled = !cfg.SyncEnabled
				pauseCheck.SetChecked(cfg.SyncEnabled)
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
				_ = engine.PerformSync(pwdEntry.Text)
			}
		}
	}()

	w.ShowAndRun()
}
