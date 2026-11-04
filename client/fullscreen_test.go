package main

import (
	"testing"
)

func TestFullscreenAppActive(t *testing.T) {
	// Call IsFullscreenAppActive without panic in headless/test environments
	_ = IsFullscreenAppActive()
}
