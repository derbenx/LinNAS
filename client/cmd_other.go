//go:build !windows

package main

import "os/exec"

func prepareHiddenCommand(cmd *exec.Cmd) {
	// No-op on non-Windows platforms
}
