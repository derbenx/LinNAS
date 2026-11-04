package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSmartAlertOnlyOnServerExplicitError(t *testing.T) {
	var alertTriggered bool
	var alertReceivedMsg string
	var alertIsTest bool

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer server.Close()

	cfg := ClientConfig{
		ServerEndpoint: server.Listener.Addr().String(),
	}
	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to init sync engine: %v", err)
	}
	engine.crypto.serverURL = server.URL
	engine.onSmartAlert = func(msg string, isTest bool) {
		alertTriggered = true
		alertReceivedMsg = msg
		alertIsTest = isTest
	}

	resetAlert := func() {
		alertTriggered = false
		alertReceivedMsg = ""
		alertIsTest = false
	}

	// Case 1: Server healthy (success: true, overall_healthy: true, no client failures) -> NO ALERT
	resetAlert()
	handler = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"overall_healthy": true,
			"is_test":         false,
			"disks":           []SmartDiskInfo{{Device: "/dev/sda", Health: "PASSED"}},
			"client_reports":  []ClientFailureReport{},
		})
	}
	engine.CheckSMARTDriveHealth()
	if alertTriggered {
		t.Fatal("Alert triggered when server and clients were healthy!")
	}

	// Case 2: Server returns 500 error / network issue (and local is healthy) -> NO ALERT (ignore network problems)
	resetAlert()
	handler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
	engine.CheckSMARTDriveHealth()
	if alertTriggered {
		t.Fatal("Alert triggered on HTTP 500 when local healthy!")
	}

	// Case 3: Server returns bad/malformed data (and local is healthy) -> NO ALERT (ignore bad data)
	resetAlert()
	handler = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{this is not valid json}"))
	}
	engine.CheckSMARTDriveHealth()
	if alertTriggered {
		t.Fatal("Alert triggered on bad JSON data!")
	}

	// Case 4: Server specifically says there is a server disk failure (overall_healthy: false) -> MUST ALERT
	resetAlert()
	handler = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"overall_healthy": false,
			"is_test":         false,
			"disks": []SmartDiskInfo{
				{
					Device: "/dev/sda",
					Model:  "Samsung 980 PRO",
					Health: "FAILED",
				},
			},
			"client_reports": []ClientFailureReport{},
		})
	}
	engine.CheckSMARTDriveHealth()
	if !alertTriggered || !strings.Contains(alertReceivedMsg, "Samsung 980 PRO") {
		t.Fatalf("Alert NOT triggered on server disk failure: msg=%s", alertReceivedMsg)
	}

	// Case 5: Server reports remote client computer drive failures -> MUST ALERT
	resetAlert()
	handler = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"overall_healthy": false,
			"is_test":         false,
			"disks":           []SmartDiskInfo{{Device: "/dev/sda", Health: "PASSED"}},
			"client_reports": []ClientFailureReport{
				{
					Client: "OfficePC (192.168.1.120)",
					Failing: []SmartDiskInfo{
						{
							Device:   "/dev/nvme0n1",
							Model:    "Crucial P5 Plus 1TB",
							Health:   "FAILED",
							HostName: "OfficePC",
						},
					},
				},
			},
		})
	}
	engine.CheckSMARTDriveHealth()
	if !alertTriggered || !strings.Contains(alertReceivedMsg, "Crucial P5 Plus 1TB") {
		t.Fatalf("Alert NOT triggered on remote client failure reported by server: msg=%s", alertReceivedMsg)
	}

	// Case 6: Server specifically says is_test: true -> MUST ALERT
	resetAlert()
	handler = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":         true,
			"overall_healthy": false,
			"is_test":         true,
			"disks":           []SmartDiskInfo{},
			"client_reports":  []ClientFailureReport{},
		})
	}
	engine.CheckSMARTDriveHealth()
	if !alertTriggered || !alertIsTest {
		t.Fatal("Alert NOT triggered when server specifically reported is_test: true!")
	}
}
