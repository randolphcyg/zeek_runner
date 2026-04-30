package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		TaskID:     "test-001",
		UUID:       "test-uuid",
		PcapID:     "pcap-001",
		PcapPath:   "test.pcap",
		ScriptID:   "script-001",
		ScriptPath: "/tmp/test.zeek",
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
