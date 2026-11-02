//go:build !windows

package main

import (
	"fyne.io/fyne/v2"
)

// positionWindowBottomRight is a no-op on non-Windows platforms
func positionWindowBottomRight(w fyne.Window, winWidth, winHeight int) {
	// Standard window placement
}
