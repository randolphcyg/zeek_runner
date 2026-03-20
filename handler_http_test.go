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

func TestDeriveTaskType_MaliciousScan(t *testing.T) {
	req := AnalyzeReq{
		ScriptPath: "/tmp/detect_ssh.zeek",
	}
	taskType := deriveTaskType(req)
	if taskType != "MALICIOUS_SCAN" {
		t.Errorf("expected MALICIOUS_SCAN, got %s", taskType)
	}
}

func TestDeriveTaskType_FileExtract(t *testing.T) {
	req := AnalyzeReq{
		ScriptPath:        "/tmp/extract_http.zeek",
		ExtractedFilePath: "/tmp/extracted",
	}
	taskType := deriveTaskType(req)
	if taskType != "FILE_EXTRACT" {
		t.Errorf("expected FILE_EXTRACT, got %s", taskType)
	}
}
