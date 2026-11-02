package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDLNAServerLifecycleAndEndpoints(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dlna_test_media")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a dummy audio file in tempDir
	dummyMP3 := filepath.Join(tempDir, "song.mp3")
	if err := os.WriteFile(dummyMP3, []byte("ID3dummy_audio_bytes_for_testing"), 0644); err != nil {
		t.Fatalf("Failed to write dummy mp3: %v", err)
	}

	appConfig.AuthEnabled = false
	loadDLNAConfig()

	// 1. Test /api/dlna/status endpoint
	req := httptest.NewRequest(http.MethodGet, "/api/dlna/status", nil)
	w := httptest.NewRecorder()
	handleDLNAStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}
	var statusResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("Invalid JSON from status: %v", err)
	}
	if statusResp["success"] != true {
		t.Errorf("Expected success true, got %v", statusResp)
	}

	// 2. Test /api/dlna/config endpoint
	cfgPayload := map[string]interface{}{
		"server_backend": "builtin",
		"media_folder":   tempDir,
		"friendly_name":  "Test AudioCast Server",
		"port":           8299,
		"stream_mode":    "direct_http",
	}
	b, _ := json.Marshal(cfgPayload)
	reqCfg := httptest.NewRequest(http.MethodPost, "/api/dlna/config", bytes.NewReader(b))
	wCfg := httptest.NewRecorder()
	handleDLNAConfig(wCfg, reqCfg)

	if wCfg.Code != http.StatusOK {
		t.Fatalf("Expected status 200 on config, got %d", wCfg.Code)
	}

	// 3. Test /api/dlna/toggle endpoint (Start Server)
	togglePayload := map[string]interface{}{"enabled": true}
	bTog, _ := json.Marshal(togglePayload)
	reqTog := httptest.NewRequest(http.MethodPost, "/api/dlna/toggle", bytes.NewReader(bTog))
	wTog := httptest.NewRecorder()
	handleDLNAToggle(wTog, reqTog)

	if wTog.Code != http.StatusOK {
		t.Fatalf("Expected status 200 on toggle, got %d", wTog.Code)
	}

	// Verify Built-in Go server is running and responds to UPnP / DLNA queries
	client := http.Client{}
	descResp, err := client.Get("http://127.0.0.1:8299/description.xml")
	if err != nil {
		t.Fatalf("Failed to fetch description.xml from built-in DLNA server: %v", err)
	}
	defer descResp.Body.Close()
	if descResp.StatusCode != http.StatusOK {
		t.Errorf("Expected description.xml 200 OK, got %d", descResp.StatusCode)
	}

	// Verify ContentDir.xml
	scpdResp, err := client.Get("http://127.0.0.1:8299/ContentDir.xml")
	if err != nil || scpdResp.StatusCode != http.StatusOK {
		t.Errorf("Failed to fetch ContentDir.xml: %v", err)
	}
	if scpdResp != nil {
		scpdResp.Body.Close()
	}

	// Verify ContentDirectory SOAP Browse Action
	browseEnvelope := `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
      <ObjectID>0</ObjectID>
      <BrowseFlag>BrowseDirectChildren</BrowseFlag>
      <Filter>*</Filter>
      <StartingIndex>0</StartingIndex>
      <RequestedCount>50</RequestedCount>
      <SortCriteria></SortCriteria>
    </u:Browse>
  </s:Body>
</s:Envelope>`
	browseReq, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8299/ContentDirectory/control", strings.NewReader(browseEnvelope))
	browseReq.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:ContentDirectory:1#Browse"`)
	browseReq.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	browseResp, err := client.Do(browseReq)
	if err != nil || browseResp.StatusCode != http.StatusOK {
		t.Fatalf("Failed SOAP Browse action: %v", err)
	}
	defer browseResp.Body.Close()

	// Verify Direct HTTP Media Stream Range Request
	mediaResp, err := client.Get("http://127.0.0.1:8299/media/song.mp3")
	if err != nil || mediaResp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to stream media: %v", err)
	}
	defer mediaResp.Body.Close()
	if mediaResp.Header.Get("contentFeatures.dlna.org") == "" {
		t.Errorf("Expected contentFeatures.dlna.org header in DLNA media stream")
	}

	// 4. Test Discovered Renderers Endpoint
	reqRdr := httptest.NewRequest(http.MethodGet, "/api/dlna/renderers", nil)
	wRdr := httptest.NewRecorder()
	handleDLNARenderers(wRdr, reqRdr)
	if wRdr.Code != http.StatusOK {
		t.Errorf("Expected renderers 200, got %d", wRdr.Code)
	}

	// 5. Test Casting Mock Device
	discoveredRenderersMu.Lock()
	discoveredRenderers["mock_audiocast_1"] = DiscoveredRenderer{
		ID:             "mock_audiocast_1",
		FriendlyName:   "AudioCast Living Room",
		AVTransportURL: "http://127.0.0.1:8299/mock_av_transport",
		IP:             "192.168.1.150",
	}
	discoveredRenderersMu.Unlock()

	castPayload := map[string]interface{}{
		"renderer_id": "mock_audiocast_1",
		"action":      "play",
		"file_path":   dummyMP3,
		"stream_mode": "direct_http",
	}
	bCast, _ := json.Marshal(castPayload)
	reqCast := httptest.NewRequest(http.MethodPost, "/api/dlna/cast", bytes.NewReader(bCast))
	wCast := httptest.NewRecorder()
	handleDLNACast(wCast, reqCast)

	// Will return 200 or connection error depending on mock endpoint, verifying parameter and routing handling
	if wCast.Code != http.StatusOK {
		t.Errorf("Expected cast handler to execute and return 200, got %d", wCast.Code)
	}

	// Clean up: Stop DLNA server
	toggleStop := map[string]interface{}{"enabled": false}
	bStop, _ := json.Marshal(toggleStop)
	reqStop := httptest.NewRequest(http.MethodPost, "/api/dlna/toggle", bytes.NewReader(bStop))
	wStop := httptest.NewRecorder()
	handleDLNAToggle(wStop, reqStop)
	_ = stopBuiltinDLNAServer()
}
