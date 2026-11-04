//go:build !windows

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// IsFullscreenAppActive checks whether the currently focused window is fullscreen on Linux/X11
func IsFullscreenAppActive() bool {
	// Attempt check via xdotool and xprop if available
	out, err := exec.Command("xdotool", "getactivewindow").Output()
	if err != nil {
		return false
	}
	winID := strings.TrimSpace(string(out))
	if winID == "" {
		return false
	}

	// Check _NET_WM_STATE for _NET_WM_STATE_FULLSCREEN
	stateOut, err := exec.Command("xprop", "-id", winID, "_NET_WM_STATE").Output()
	if err == nil && strings.Contains(string(stateOut), "_NET_WM_STATE_FULLSCREEN") {
		return true
	}

	// Secondary check: Compare active window geometry with screen resolution
	geoOut, err := exec.Command("xdotool", "getwindowgeometry", winID).Output()
	if err == nil {
		lines := strings.Split(string(geoOut), "\n")
		var winW, winH int
		for _, l := range lines {
			if strings.Contains(l, "Geometry:") {
				parts := strings.Fields(l)
				if len(parts) >= 2 {
					dims := strings.Split(parts[1], "x")
					if len(dims) == 2 {
						winW, _ = strconv.Atoi(dims[0])
						winH, _ = strconv.Atoi(dims[1])
					}
				}
			}
		}

		dispOut, dErr := exec.Command("xdpyinfo").Output()
		if dErr == nil && winW > 0 && winH > 0 {
			for _, dl := range strings.Split(string(dispOut), "\n") {
				if strings.Contains(dl, "dimensions:") {
					dParts := strings.Fields(dl)
					if len(dParts) >= 2 {
						dims := strings.Split(dParts[1], "x")
						if len(dims) == 2 {
							scrW, _ := strconv.Atoi(dims[0])
							scrH, _ := strconv.Atoi(dims[1])
							if winW >= scrW && winH >= scrH {
								return true
							}
						}
					}
				}
			}
		}
	}

	return false
}
