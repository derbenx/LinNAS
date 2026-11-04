package main

import (
	"testing"
	"time"
)

func TestReconnectManagerBackoffIntervals(t *testing.T) {
	mgr := NewReconnectManager(nil, nil)

	// Under 30 minutes: 1-2 mins (90 seconds)
	d1 := mgr.CalculateBackoff(5 * time.Minute)
	if d1 < 60*time.Second || d1 > 120*time.Second {
		t.Fatalf("Expected 1-2 mins backoff under 30 mins, got: %v", d1)
	}

	// Between 30 mins and 60 mins: 5 mins
	d2 := mgr.CalculateBackoff(45 * time.Minute)
	if d2 != 5*time.Minute {
		t.Fatalf("Expected 5 min backoff after 30 mins, got: %v", d2)
	}

	// Over 60 mins: 15 mins
	d3 := mgr.CalculateBackoff(75 * time.Minute)
	if d3 != 15*time.Minute {
		t.Fatalf("Expected 15 min backoff after 1 hour, got: %v", d3)
	}
}

func TestReconnectManagerMissedTimerSyncTracking(t *testing.T) {
	reconnectedCalled := false
	mgr := NewReconnectManager(func() {
		reconnectedCalled = true
	}, nil)

	// Initially not disconnected
	if mgr.IsDisconnected() {
		t.Fatal("Should not be disconnected initially")
	}

	// Mark disconnected
	mgr.MarkDisconnected("network timeout")
	if !mgr.IsDisconnected() {
		t.Fatal("Expected disconnected state")
	}

	// Missed timer sync occurs while disconnected
	mgr.RecordMissedTimerSync()
	if !mgr.HasMissedTimerSync() {
		t.Fatal("Expected missedTimerSync to be true")
	}

	// Mark connected triggers onReconnect
	mgr.MarkConnected()
	if mgr.IsDisconnected() {
		t.Fatal("Expected connected state")
	}
	if !reconnectedCalled {
		t.Fatal("Expected onReconnect callback to fire")
	}
}
