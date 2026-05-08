package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHTTPHandler_HandleAnalysis_InvalidParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHTTPHandler(nil, nil)

	router := gin.New()
	router.POST("/analyze", handler.HandleAnalysis)

	jsonBody, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest(http.MethodPost, "/analyze", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHTTPHandler_HandleSyntaxCheck_MissingParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHTTPHandler(nil, nil)

	router := gin.New()
	router.POST("/syntax-check", handler.HandleSyntaxCheck)

	jsonBody, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest(http.MethodPost, "/syntax-check", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHTTPHandler_HandleListAndGetScripts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	root := t.TempDir()
	writeTestScript(t, root, "script.zeek", `const SCRIPT_ID = "SCRIPT_ONE";`)
	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	handler := NewHTTPHandler(&Service{scriptRegistry: registry}, nil)

	router := gin.New()
	router.GET("/scripts", handler.HandleListScripts)
	router.GET("/scripts/:scriptID", handler.HandleGetScript)

	req, _ := http.NewRequest(http.MethodGet, "/scripts?enabledOnly=true&name=one", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var listResp struct {
		Code int `json:"code"`
		Data struct {
			Scripts []ScriptInfo `json:"scripts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list response failed: %v", err)
	}
	if len(listResp.Data.Scripts) != 1 || listResp.Data.Scripts[0].ScriptID != "SCRIPT_ONE" {
		t.Fatalf("unexpected list response: %+v", listResp)
	}

	req, _ = http.NewRequest(http.MethodGet, "/scripts/SCRIPT_ONE", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHTTPHandler_HandleGetScript_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry, err := newScriptRegistry(t.TempDir())
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	handler := NewHTTPHandler(&Service{scriptRegistry: registry}, nil)
	router := gin.New()
	router.GET("/scripts/:scriptID", handler.HandleGetScript)

	req, _ := http.NewRequest(http.MethodGet, "/scripts/NOPE", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestHTTPHandler_ResolveSyntaxCheckPath_ScriptID(t *testing.T) {
	root := t.TempDir()
	scriptPath := writeTestScript(t, root, "script.zeek", `const SCRIPT_ID = "SCRIPT";`)
	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	handler := NewHTTPHandler(&Service{scriptRegistry: registry}, nil)

	got, err := handler.resolveSyntaxCheckPath(SyntaxCheckReq{ScriptID: "SCRIPT"})
	if err != nil {
		t.Fatalf("resolveSyntaxCheckPath failed: %v", err)
	}
	if got != filepath.ToSlash(scriptPath) {
		t.Fatalf("expected %q, got %q", scriptPath, got)
	}
}

func TestValidateReq_MissingTaskID(t *testing.T) {
	req := AnalyzeReq{
		UUID:       "test-uuid",
		PcapID:     "pcap-001",
		PcapPath:   "/tmp/test.pcap",
		ScriptID:   "script-001",
		ScriptPath: "/tmp/test.zeek",
	}

	err := validateReq(req)
	if err == nil {
		t.Error("expected error for missing taskID")
	}
}

func TestValidateReq_MissingUUID(t *testing.T) {
	req := AnalyzeReq{
		TaskID:     "test-001",
		PcapID:     "pcap-001",
		PcapPath:   "/tmp/test.pcap",
		ScriptID:   "script-001",
		ScriptPath: "/tmp/test.zeek",
	}

	err := validateReq(req)
	if err == nil {
		t.Error("expected error for missing uuid")
	}
}

func TestValidateReq_MissingPcapID(t *testing.T) {
	req := AnalyzeReq{
		TaskID:     "test-001",
		UUID:       "test-uuid",
		PcapPath:   "/tmp/test.pcap",
		ScriptID:   "script-001",
		ScriptPath: "/tmp/test.zeek",
	}

	err := validateReq(req)
	if err == nil {
		t.Error("expected error for missing pcapID")
	}
}

func TestValidateReq_MissingScriptID(t *testing.T) {
	req := AnalyzeReq{
		TaskID:     "test-001",
		UUID:       "test-uuid",
		PcapID:     "pcap-001",
		PcapPath:   "/tmp/test.pcap",
		ScriptPath: "/tmp/test.zeek",
	}

	err := validateReq(req)
	if err == nil {
		t.Error("expected error for missing scriptID")
	}
}

func TestValidateReq_RelativePath(t *testing.T) {
	req := AnalyzeReq{
		TaskID:   "test-001",
		UUID:     "test-uuid",
		PcapID:   "pcap-001",
		PcapPath: "test.pcap",
		ScriptID: "script-001",
	}

	err := validateReq(req)
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestValidatePath_Valid(t *testing.T) {
	err := validatePath("/tmp/test.pcap", "pcap")
	if err != nil {
		t.Errorf("expected no error for valid path, got %v", err)
	}
}

func TestValidatePath_Relative(t *testing.T) {
	err := validatePath("test.pcap", "pcap")
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestValidateExtractReq_OutputDir(t *testing.T) {
	req := ExtractReq{
		TaskID:    "test-001",
		UUID:      "test-uuid",
		PcapID:    "pcap-001",
		PcapPath:  "/tmp/test.pcap",
		OutputDir: "/tmp/extracted",
	}

	err := validateExtractReq(req)
	if err == nil || err.Error() != "file not found: /tmp/test.pcap" {
		t.Fatalf("expected validation to pass outputDir alias before pcap existence check, got %v", err)
	}
}

func TestValidateExtractReq_MissingOutputDir(t *testing.T) {
	req := ExtractReq{
		TaskID:   "test-001",
		UUID:     "test-uuid",
		PcapID:   "pcap-001",
		PcapPath: "/tmp/test.pcap",
	}

	err := validateExtractReq(req)
	if err == nil || err.Error() != "missing outputDir" {
		t.Fatalf("expected missing outputDir error, got %v", err)
	}
}

func TestHTTPHandler_HandleExtract_InvalidParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHTTPHandler(nil, nil)

	router := gin.New()
	router.POST("/extract", handler.HandleExtract)

	jsonBody, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest(http.MethodPost, "/extract", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHTTPHandler_HandleExtractAsync_InvalidParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHTTPHandler(nil, nil)

	router := gin.New()
	router.POST("/extract/async", handler.HandleExtractAsync)

	jsonBody, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest(http.MethodPost, "/extract/async", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}
