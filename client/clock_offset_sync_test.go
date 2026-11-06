package main

import (
	"testing"
)

func TestClockOffsetEvaluation(t *testing.T) {
	nowClient := int64(1800)
	serverTime := int64(2000)
	offset := ComputeClockOffset(serverTime, nowClient)
	if offset != 200 {
		t.Fatalf("expected offset 200, got %d", offset)
	}

	// Scenario 1: Server file modified at server time 1950.
	// Client file was modified at client time 1780.
	// Client normalized = 1780 + 200 = 1980.
	// Since 1980 > 1950, client file is NEWER!
	clientMod := int64(1780)
	serverMod := int64(1950)
	normalizedClientMod := NormalizeClientModTime(clientMod, offset)
	if normalizedClientMod <= serverMod {
		t.Fatalf("expected normalized client mod (1980) to be newer than server file (1950)")
	}

	// Scenario 2: Server file modified at server time 1990.
	// Client file was modified at client time 1700 (normalized = 1900).
	// Since 1990 > 1900, server file is NEWER!
	clientMod2 := int64(1700)
	normalizedClientMod2 := NormalizeClientModTime(clientMod2, offset)
	if serverMod <= normalizedClientMod2 {
		t.Fatalf("expected server file (1990) to be newer than client file (1900)")
	}
}
