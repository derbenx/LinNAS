package main

import (
	"context"
	"embed"
	"fmt"

	"fyne.io/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend
var assets embed.FS

func main() {
	app := NewApp()

	// Initialize system tray menu in background
	go systray.Run(func() {
		systray.SetIcon(defaultTrayIcon)
		systray.SetTitle("LinNAS Cloud")
		systray.SetTooltip("LinNAS Local Cloud Client")

		mOpen := systray.AddMenuItem("Open Client", "Show LinNAS Client Window")
		mSMART := systray.AddMenuItem("View SMART Health", "Show SMART Diagnostics Tab")
		systray.AddSeparator()
		mSyncNow := systray.AddMenuItem("Sync Now", "Trigger immediate file sync")
		mToggleSync := systray.AddMenuItemCheckbox("Automatic Syncing", "Enable or disable automatic sync", app.cfg.SyncEnabled)
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit", "Exit LinNAS Cloud Client")

		for {
			select {
			case <-mOpen.ClickedCh:
				if app.ctx != nil {
					wailsRuntime.WindowShow(app.ctx)
					wailsRuntime.WindowUnminimise(app.ctx)
				}
			case <-mSMART.ClickedCh:
				if app.ctx != nil {
					wailsRuntime.WindowShow(app.ctx)
					wailsRuntime.WindowUnminimise(app.ctx)
					wailsRuntime.EventsEmit(app.ctx, "navigate-tab", "smart")
				}
			case <-mSyncNow.ClickedCh:
				go func() {
					_ = app.PerformSync()
				}()
			case <-mToggleSync.ClickedCh:
				app.mu.Lock()
				app.cfg.SyncEnabled = !app.cfg.SyncEnabled
				_ = SaveConfig(app.cfg)
				app.engine.UpdateConfig(app.cfg)
				enabled := app.cfg.SyncEnabled
				app.mu.Unlock()
				if enabled {
					mToggleSync.Check()
				} else {
					mToggleSync.Uncheck()
				}
				if app.ctx != nil {
					wailsRuntime.EventsEmit(app.ctx, "sync-toggle", enabled)
				}
			case <-mQuit.ClickedCh:
				systray.Quit()
				if app.ctx != nil {
					wailsRuntime.Quit(app.ctx)
				}
				return
			}
		}
	}, func() {})

	err := wails.Run(&options.App{
		Title:             "LinNAS Local Cloud",
		Width:             780,
		Height:            580,
		MinWidth:          700,
		MinHeight:         500,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 13, G: 17, B: 23, A: 255},
		OnStartup:        app.startup,
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			// Hide to tray when 'X' is pressed instead of exiting process
			wailsRuntime.WindowHide(ctx)
			return true
		},
		Bind: []interface{}{
			app,
		},
		HideWindowOnClose: true,
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:   false,
			DisableWindowIcon:     false,
		},
		Linux: &linux.Options{
			WindowIsTranslucent: false,
		},
	})

	if err != nil {
		fmt.Printf("Error running application: %v\n", err)
	}
}
