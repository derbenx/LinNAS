//go:build windows

package main

import (
	"syscall"
	"time"
	"unsafe"

	"fyne.io/fyne/v2"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procFindWindowW      = user32.NewProc("FindWindowW")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
)

const (
	smCxScreen   = 0
	smCyScreen   = 1
	smCxWorkarea = 1000 // fallback
	swpNoZOrder  = 0x0004
	swpNoActivate = 0x0010
	swpShowWindow = 0x0040
)

// positionWindowBottomRight positions a window at the bottom-right corner of the screen on Windows
func positionWindowBottomRight(w fyne.Window, winWidth, winHeight int) {
	title := w.Title()
	go func() {
		// Wait brief moment for the window handle to be created by the OS
		time.Sleep(100 * time.Millisecond)

		titlePtr, err := syscall.UTF16PtrFromString(title)
		if err != nil {
			return
		}

		hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
		if hwnd == 0 {
			// Retry once if window took slightly longer to map
			time.Sleep(200 * time.Millisecond)
			hwnd, _, _ = procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
		}

		if hwnd != 0 {
			screenWidth, _, _ := procGetSystemMetrics.Call(uintptr(smCxScreen))
			screenHeight, _, _ := procGetSystemMetrics.Call(uintptr(smCyScreen))

			if screenWidth > 0 && screenHeight > 0 {
				posX := int(screenWidth) - winWidth - 30
				posY := int(screenHeight) - winHeight - 60
				if posX < 0 {
					posX = 0
				}
				if posY < 0 {
					posY = 0
				}
				procSetWindowPos.Call(
					hwnd,
					0,
					uintptr(posX),
					uintptr(posY),
					uintptr(winWidth),
					uintptr(winHeight),
					uintptr(swpNoZOrder|swpShowWindow),
				)
			}
		}
	}()
}
