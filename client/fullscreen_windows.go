//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	user32Win               = syscall.NewLazyDLL("user32.dll")
	procGetForegroundWindow = user32Win.NewProc("GetForegroundWindow")
	procGetWindowRect       = user32Win.NewProc("GetWindowRect")
	procGetSystemMetrics    = user32Win.NewProc("GetSystemMetrics")
)

type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

const (
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
)

// IsFullscreenAppActive checks whether the foreground window on Windows occupies the full screen
func IsFullscreenAppActive() bool {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return false
	}

	var rect RECT
	ret, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rect)))
	if ret == 0 {
		return false
	}

	scrW, _, _ := procGetSystemMetrics.Call(uintptr(SM_CXSCREEN))
	scrH, _, _ := procGetSystemMetrics.Call(uintptr(SM_CYSCREEN))

	w := rect.Right - rect.Left
	h := rect.Bottom - rect.Top

	return w >= int32(scrW) && h >= int32(scrH) && rect.Left <= 0 && rect.Top <= 0
}
