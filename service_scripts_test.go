package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServicePrepareAnalyzeReq_ResolvesManagedScript(t *testing.T) {
	root := t.TempDir()
	scriptPath := writeTestScript(t, root, "script.zeek", `const SCRIPT_ID = "SCRIPT";`)
	pcapPath := filepath.Join(t.TempDir(), "test.pcap")
	if err := os.WriteFile(pcapPath, []byte("pcap"), 0o644); err != nil {
		t.Fatalf("write pcap failed: %v", err)
	}
	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	service := &Service{scriptRegistry: registry}

	req, err := service.prepareAnalyzeReq(AnalyzeReq{
		TaskID:   "task",
		UUID:     "uuid",
		PcapID:   "pcap",
		PcapPath: pcapPath,
		ScriptID: "SCRIPT",
	})
	if err != nil {
		t.Fatalf("prepareAnalyzeReq failed: %v", err)
	}
	if req.ScriptPath != filepath.ToSlash(scriptPath) {
		t.Fatalf("expected resolved scriptPath %q, got %q", scriptPath, req.ScriptPath)
	}
}

func TestServicePrepareAnalyzeReq_RejectsMismatchedPath(t *testing.T) {
	root := t.TempDir()
	writeTestScript(t, root, "script.zeek", `const SCRIPT_ID = "SCRIPT";`)
	pcapPath := filepath.Join(t.TempDir(), "test.pcap")
	if err := os.WriteFile(pcapPath, []byte("pcap"), 0o644); err != nil {
		t.Fatalf("write pcap failed: %v", err)
	}
	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	service := &Service{scriptRegistry: registry}

	_, err = service.prepareAnalyzeReq(AnalyzeReq{
		TaskID:     "task",
		UUID:       "uuid",
		PcapID:     "pcap",
		PcapPath:   pcapPath,
		ScriptID:   "SCRIPT",
		ScriptPath: "/tmp/other.zeek",
	})
	if err == nil || !strings.Contains(err.Error(), "scriptPath mismatch") {
		t.Fatalf("expected scriptPath mismatch, got %v", err)
	}
}
