package main

import (
	"testing"
)

func TestClockOffsetCalculation(t *testing.T) {
	serverTime := int64(1000)
	clientTime := int64(900)
	offset := ComputeClockOffset(serverTime, clientTime)
	if offset != 100 {
		t.Fatalf("expected offset 100, got %d", offset)
	}

	clientFileMod := int64(950)
	normalizedClientMod := NormalizeClientModTime(clientFileMod, offset)
	if normalizedClientMod != 1050 {
		t.Fatalf("expected 1050, got %d", normalizedClientMod)
	}

	serverFileMod := int64(1020)
	if normalizedClientMod <= serverFileMod {
		t.Fatalf("expected client to be newer")
	}

	localComparableServerMod := LocalComparableServerModTime(serverFileMod, offset)
	if localComparableServerMod != 920 {
		t.Fatalf("expected 920, got %d", localComparableServerMod)
	}
	if clientFileMod <= localComparableServerMod {
		t.Fatalf("expected client file mod (950) > local comparable server mod (920)")
	}
}
