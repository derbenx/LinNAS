package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestClientAutoReconnectOnServerRestart(t *testing.T) {
	var sessionsMu sync.RWMutex
	sessions := make(map[string]bool)

	serverPassHash := HashPassword("testpass123")
	serverUser := "admin"

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(derBytes)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/crypto/pubkey" {
			json.NewEncoder(w).Encode(map[string]string{"public_key": pubB64})
			return
		}

		if r.URL.Path == "/api/login" {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				EncryptedKey  string `json:"encrypted_key"`
				EncryptedData string `json:"encrypted_data"`
			}
			_ = json.Unmarshal(body, &payload)

			var creds struct {
				Username     string `json:"username"`
				PasswordHash string `json:"password_hash"`
				SessionToken string `json:"session_token"`
			}

			if payload.EncryptedKey != "" {
				encKeyBytes, _ := base64.StdEncoding.DecodeString(payload.EncryptedKey)
				aesKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, encKeyBytes, nil)
				combinedBytes, _ := base64.StdEncoding.DecodeString(payload.EncryptedData)

				block, _ := aes.NewCipher(aesKey)
				gcm, _ := cipher.NewGCM(block)
				nonceSize := gcm.NonceSize()
				if len(combinedBytes) >= nonceSize {
					nonce := combinedBytes[:nonceSize]
					cipherData := combinedBytes[nonceSize:]
					plaintext, _ := gcm.Open(nil, nonce, cipherData, nil)
					_ = json.Unmarshal(plaintext, &creds)
				}
			}

			sessionsMu.RLock()
			validToken := creds.SessionToken != "" && sessions[creds.SessionToken]
			sessionsMu.RUnlock()

			if validToken {
				w.Write([]byte(fmt.Sprintf(`{"success":true,"session_token":"%s"}`, creds.SessionToken)))
				return
			}

			if creds.Username == serverUser && creds.PasswordHash == serverPassHash {
				tok := fmt.Sprintf("token_%d", time.Now().UnixNano())
				sessionsMu.Lock()
				sessions[tok] = true
				sessionsMu.Unlock()
				w.Write([]byte(fmt.Sprintf(`{"success":true,"session_token":"%s"}`, tok)))
				return
			}

			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid credentials"}`))
			return
		}

		if r.URL.Path == "/api/cloud/list" {
			c, err := r.Cookie("session_token")
			sessionsMu.RLock()
			valid := err == nil && sessions[c.Value]
			sessionsMu.RUnlock()
			if !valid {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			w.Write([]byte(`{"success":true,"items":[]}`))
			return
		}
	}))
	defer ts.Close()

	cfg := ClientConfig{
		ServerEndpoint: ts.Listener.Addr().String(),
		Username:       serverUser,
		PasswordHash:   serverPassHash,
		SessionToken:   "stale_dead_token_from_previous_server_run",
	}

	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to init sync engine: %v", err)
	}
	engine.crypto.serverURL = ts.URL
	engine.crypto.pubKey = &rsaPriv.PublicKey

	// Attempt to authenticate: engine will initially send stale_dead_token, get 401,
	// and automatically discard it and re-authenticate using PasswordHash
	if err := engine.EnsureAuthenticated(""); err != nil {
		t.Fatalf("EnsureAuthenticated failed to auto-reconnect after stale token: %v", err)
	}

	if engine.cfg.SessionToken == "stale_dead_token_from_previous_server_run" || engine.cfg.SessionToken == "" {
		t.Fatalf("Expected new session token generated, got: %s", engine.cfg.SessionToken)
	}

	// Now simulate a server restart by wiping sessions in memory
	sessionsMu.Lock()
	sessions = make(map[string]bool)
	sessionsMu.Unlock()

	// Engine invalidates session on 401 and recovers on next cycle
	engine.InvalidateSession()
	if err := engine.EnsureAuthenticated(""); err != nil {
		t.Fatalf("EnsureAuthenticated failed to re-authenticate after server wipe: %v", err)
	}
}

func TestCheckSMARTDriveHealthAutoReauthorizesOnServerReboot401(t *testing.T) {
	var sessionsMu sync.RWMutex
	sessions := make(map[string]bool)

	serverPassHash := HashPassword("testpass123")
	serverUser := "admin"

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(derBytes)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/crypto/pubkey" {
			json.NewEncoder(w).Encode(map[string]string{"public_key": pubB64})
			return
		}

		if r.URL.Path == "/api/login" {
			tok := fmt.Sprintf("token_%d", time.Now().UnixNano())
			sessionsMu.Lock()
			sessions[tok] = true
			sessionsMu.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name:  "session_token",
				Value: tok,
				Path:  "/",
			})
			w.Write([]byte(fmt.Sprintf(`{"success":true,"session_token":"%s"}`, tok)))
			return
		}

		if r.URL.Path == "/api/cloud/smart" {
			c, err := r.Cookie("session_token")
			sessionsMu.RLock()
			valid := err == nil && sessions[c.Value]
			sessionsMu.RUnlock()
			if !valid {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			w.Write([]byte(`{"success":true,"overall_healthy":true,"is_test":false,"disks":[{"device":"sda","health":"PASSED"}]}`))
			return
		}
	}))
	defer ts.Close()

	cfg := ClientConfig{
		ServerEndpoint: ts.Listener.Addr().String(),
		Username:       serverUser,
		PasswordHash:   serverPassHash,
	}

	engine, err := NewSyncEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to init sync engine: %v", err)
	}
	engine.crypto.serverURL = ts.URL
	engine.crypto.pubKey = &rsaPriv.PublicKey

	// Initial authentication
	if err := engine.EnsureAuthenticated(""); err != nil {
		t.Fatalf("Initial EnsureAuthenticated failed: %v", err)
	}

	// Initial call succeeds
	healthy, _, disks, _, err := engine.CheckSMARTDriveHealth()
	if err != nil || !healthy || len(disks) == 0 {
		t.Fatalf("Initial CheckSMARTDriveHealth failed: %v", err)
	}

	// Server restarts and wipes in-memory sessions!
	sessionsMu.Lock()
	sessions = make(map[string]bool)
	sessionsMu.Unlock()

	// Calling CheckSMARTDriveHealth directly encounters 401, but auto-reauthorizes and succeeds
	healthy, _, disks, _, err = engine.CheckSMARTDriveHealth()
	if err != nil {
		t.Fatalf("Expected auto-reauthorization on 401 during CheckSMARTDriveHealth, got err: %v", err)
	}
	if !healthy || len(disks) == 0 {
		t.Fatalf("Expected healthy SMART disks after auto-reauthorization, got disks: %+v", disks)
	}
}
