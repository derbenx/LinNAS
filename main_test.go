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

func TestDNSConvertEndpoint(t *testing.T) {
	input := `
# Sample Blocklist
0.0.0.0 ad.doubleclick.net
127.0.0.1 tracking.example.org
||badsite.com^
raw-malware.info
`
	req := httptest.NewRequest(http.MethodPost, "/api/dns/convert", strings.NewReader(input))
	w := httptest.NewRecorder()

	handleDNSConvert(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", res.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !data["success"].(bool) {
		t.Fatalf("Expected success true")
	}

	resultStr, ok := data["result"].(string)
	if !ok {
		t.Fatalf("Result is not a string")
	}

	expectedMatches := []string{
		"address=/ad.doubleclick.net/0.0.0.0",
		"address=/tracking.example.org/0.0.0.0",
		"address=/badsite.com/0.0.0.0",
		"address=/raw-malware.info/0.0.0.0",
	}

	for _, match := range expectedMatches {
		if !strings.Contains(resultStr, match) {
			t.Errorf("Expected result to contain %q, but output was:\n%s", match, resultStr)
		}
	}
}

func TestCommandKeyValidationAndSudoTags(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	_ = os.MkdirAll("html/testplugin", 0755)
	manifest := map[string]interface{}{
		"id":          "testplugin",
		"name":        "Test Plugin",
		"default":     true,
		"test_cmd":    "echo standard {name}",
		"test_sudo":   "echo sudo_elevated {name}",
		"test_root":   "echo root_elevated {name}",
		"not_allowed": "veracrypt",
	}
	bytesData, _ := json.Marshal(manifest)
	_ = os.WriteFile("html/testplugin/plugin.json", bytesData, 0644)

	// Test standard _cmd key
	reqBody, _ := json.Marshal(ExecRequest{
		Plugin: "testplugin",
		CmdKey: "test_cmd",
		Args:   map[string]string{"name": "world"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/plugin/exec", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	handleExecPluginCmd(w, req)

	var resp ExecResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if !resp.Success {
		t.Fatalf("Expected execution success, got error: %s", resp.Error)
	}
	if !strings.Contains(resp.Output, "standard world") {
		t.Fatalf("Expected output 'standard world', got %s", resp.Output)
	}

	// Test privileged _sudo key
	reqBodySudo, _ := json.Marshal(ExecRequest{
		Plugin: "testplugin",
		CmdKey: "test_sudo",
		Args:   map[string]string{"name": "admin"},
	})
	reqSudo := httptest.NewRequest(http.MethodPost, "/api/plugin/exec", bytes.NewReader(reqBodySudo))
	wSudo := httptest.NewRecorder()

	handleExecPluginCmd(wSudo, reqSudo)

	var respSudo ExecResponse
	_ = json.NewDecoder(wSudo.Body).Decode(&respSudo)
	if respSudo.Error != "" && !strings.Contains(respSudo.Error, "exit status") {
		t.Fatalf("Unexpected key validation error for _sudo key: %s", respSudo.Error)
	}

	// Test invalid key tag
	reqBodyInvalid, _ := json.Marshal(ExecRequest{
		Plugin: "testplugin",
		CmdKey: "not_allowed",
		Args:   map[string]string{},
	})
	reqInvalid := httptest.NewRequest(http.MethodPost, "/api/plugin/exec", bytes.NewReader(reqBodyInvalid))
	wInvalid := httptest.NewRecorder()

	handleExecPluginCmd(wInvalid, reqInvalid)

	var respInvalid ExecResponse
	_ = json.NewDecoder(wInvalid.Body).Decode(&respInvalid)
	if respInvalid.Success {
		t.Fatalf("Expected non-_cmd/_sudo/_root execution to fail")
	}
}

func TestPluginDataStorage(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	_ = os.MkdirAll("html/smb", 0755)

	payload := `{"shares":[{"name":"test","path":"/tmp"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/plugin/data?plugin=smb", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handlePluginData(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", w.Result().StatusCode)
	}

	dataPath := filepath.Join("html", "smb", "data.json")
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		t.Fatalf("data.json was not created")
	}

	reqGet := httptest.NewRequest(http.MethodGet, "/api/plugin/data?plugin=smb", nil)
	wGet := httptest.NewRecorder()

	handlePluginData(wGet, reqGet)

	if !strings.Contains(wGet.Body.String(), `"name":"test"`) {
		t.Fatalf("Expected GET data to return saved payload, got: %s", wGet.Body.String())
	}
}
