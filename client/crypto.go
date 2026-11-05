package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type EncryptedPayload struct {
	EncryptedKey  string `json:"encrypted_key"`
	EncryptedData string `json:"encrypted_data"`
	Nonce         string `json:"nonce"`
	Timestamp     int64  `json:"timestamp"`
}

type ClientCrypto struct {
	serverURL string
	pubKey    *rsa.PublicKey
	mu        sync.RWMutex
}

func NewClientCrypto(serverURL string) *ClientCrypto {
	cleanURL := strings.TrimRight(serverURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}
	return &ClientCrypto{
		serverURL: cleanURL,
	}
}

func (c *ClientCrypto) InvalidatePublicKey() {
	c.mu.Lock()
	c.pubKey = nil
	c.mu.Unlock()
}

func (c *ClientCrypto) FetchServerPublicKey() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.serverURL + "/api/crypto/pubkey")
	if err != nil {
		return fmt.Errorf("failed to reach server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server responded with status %d", resp.StatusCode)
	}

	var data struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	derBytes, err := base64.StdEncoding.DecodeString(data.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid base64 public key: %w", err)
	}

	parsedKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return fmt.Errorf("invalid PKIX public key: %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("server public key is not RSA")
	}

	c.pubKey = rsaKey
	return nil
}

func (c *ClientCrypto) EncryptPayload(payload interface{}) ([]byte, []byte, error) {
	c.mu.RLock()
	pub := c.pubKey
	c.mu.RUnlock()

	if pub == nil {
		if err := c.FetchServerPublicKey(); err != nil {
			return nil, nil, err
		}
		c.mu.RLock()
		pub = c.pubKey
		c.mu.RUnlock()
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	// Generate 256-bit AES key
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, nil, err
	}

	// Encrypt AES key with RSA-OAEP
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA encryption failed: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, jsonBytes, nil)
	combined := append(nonce, ciphertext...)

	rnd := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, rnd)

	encEnvelope := EncryptedPayload{
		EncryptedKey:  base64.StdEncoding.EncodeToString(encKey),
		EncryptedData: base64.StdEncoding.EncodeToString(combined),
		Nonce:         fmt.Sprintf("cli-%d-%s", time.Now().UnixNano(), hex.EncodeToString(rnd)),
		Timestamp:     time.Now().Unix(),
	}

	bodyBytes, err := json.Marshal(encEnvelope)
	return bodyBytes, aesKey, err
}

func (c *ClientCrypto) DecryptResponse(aesKey []byte, respBody []byte) ([]byte, error) {
	if len(aesKey) == 0 {
		return respBody, nil
	}

	var env struct {
		Encrypted     bool   `json:"encrypted"`
		EncryptedData string `json:"encrypted_data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil || !env.Encrypted || env.EncryptedData == "" {
		return respBody, nil
	}

	dataBytes, err := base64.StdEncoding.DecodeString(env.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encrypted_data: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(dataBytes) < nonceSize {
		return nil, fmt.Errorf("data too short for nonce")
	}

	nonce := dataBytes[:nonceSize]
	ciphertext := dataBytes[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
