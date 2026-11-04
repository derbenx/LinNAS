package main

import (
	"fmt"
	"sync"
	"time"
)

type ReconnectManager struct {
	mu                sync.Mutex
	isDisconnected    bool
	disconnectTime    time.Time
	retryCount        int
	nextRetryTime     time.Time
	missedTimerSync   bool
	onReconnect       func()
	onStatusChange    func(status string)
}

func NewReconnectManager(onReconnect func(), onStatusChange func(string)) *ReconnectManager {
	return &ReconnectManager{
		onReconnect:    onReconnect,
		onStatusChange: onStatusChange,
	}
}

// CalculateBackoff returns retry delay based on duration disconnected:
// 1-2 mins initially, after 30 mins wait 5 mins, after 1 hour wait 15 mins.
func (r *ReconnectManager) CalculateBackoff(disconnectedDuration time.Duration) time.Duration {
	if disconnectedDuration < 30*time.Minute {
		return 90 * time.Second // 1.5 mins
	} else if disconnectedDuration < 60*time.Minute {
		return 5 * time.Minute
	}
	return 15 * time.Minute
}

func (r *ReconnectManager) MarkDisconnected(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if !r.isDisconnected {
		r.isDisconnected = true
		r.disconnectTime = now
		r.retryCount = 0
	}

	backoff := r.CalculateBackoff(now.Sub(r.disconnectTime))
	r.nextRetryTime = now.Add(backoff)
	r.retryCount++

	if r.onStatusChange != nil {
		r.onStatusChange(fmt.Sprintf("Disconnected (%s). Retrying in %v...", reason, backoff.Round(time.Second)))
	}
}

func (r *ReconnectManager) MarkConnected() {
	r.mu.Lock()
	wasDisconnected := r.isDisconnected
	hadMissedSync := r.missedTimerSync
	r.isDisconnected = false
	r.retryCount = 0
	r.missedTimerSync = false
	r.mu.Unlock()

	if wasDisconnected {
		if r.onStatusChange != nil {
			r.onStatusChange("Connected & Re-authenticated")
		}
		if r.onReconnect != nil {
			r.onReconnect()
		}
	}
	_ = hadMissedSync
}

func (r *ReconnectManager) IsDisconnected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.isDisconnected
}

func (r *ReconnectManager) ShouldAttemptRetry() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.isDisconnected {
		return false
	}
	return time.Now().After(r.nextRetryTime)
}

func (r *ReconnectManager) RecordMissedTimerSync() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isDisconnected {
		r.missedTimerSync = true
	}
}

func (r *ReconnectManager) HasMissedTimerSync() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.missedTimerSync
}

func (r *ReconnectManager) ClearMissedTimerSync() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.missedTimerSync = false
}
