package main

import (
	"context"
	"testing"

	pb "zeek_runner/api/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCServer_VersionCheck_InvalidComponent(t *testing.T) {
	server := NewGRPCServer(nil, nil)

	req := &pb.VersionCheckRequest{
		Component: "invalid",
	}
	_, err := server.VersionCheck(context.Background(), req)

	if err == nil {
		t.Error("expected error for invalid component")
	}
}

func TestGRPCServer_ZeekSyntaxCheck_EmptyPath(t *testing.T) {
	server := NewGRPCServer(nil, nil)

	req := &pb.ZeekSyntaxCheckRequest{
		ScriptPath: "",
	}
	_, err := server.ZeekSyntaxCheck(context.Background(), req)

	if err == nil {
		t.Error("expected error for empty script path")
	}
}

func TestGRPCServer_ZeekSyntaxCheck_EmptyContent(t *testing.T) {
	server := NewGRPCServer(nil, nil)

	req := &pb.ZeekSyntaxCheckRequest{
		ScriptContent: "",
	}
	_, err := server.ZeekSyntaxCheck(context.Background(), req)

	if err == nil {
		t.Error("expected error for empty script content")
	}
}

func TestGRPCServer_ListGetReloadScripts(t *testing.T) {
	root := t.TempDir()
	writeTestScript(t, root, "script.zeek", `const SCRIPT_ID = "SCRIPT";`)
	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	cm := &ConfigManager{}
	cm.config.Store(&Config{Zeek: ZeekConfig{ScriptRoot: root}})
	server := NewGRPCServer(&Service{scriptRegistry: registry, configManager: cm}, nil)

	list, err := server.ListScripts(context.Background(), &pb.ListScriptsRequest{EnabledOnly: true})
	if err != nil {
		t.Fatalf("ListScripts failed: %v", err)
	}
	if len(list.GetScripts()) != 1 || list.GetScripts()[0].GetScriptID() != "SCRIPT" {
		t.Fatalf("unexpected scripts: %+v", list.GetScripts())
	}

	script, err := server.GetScript(context.Background(), &pb.GetScriptRequest{ScriptID: "SCRIPT"})
	if err != nil {
		t.Fatalf("GetScript failed: %v", err)
	}
	if script.GetExpCodeType() != "zeek" {
		t.Fatalf("unexpected script info: %+v", script)
	}

	reload, err := server.ReloadScripts(context.Background(), &pb.ReloadScriptsRequest{})
	if err != nil {
		t.Fatalf("ReloadScripts failed: %v", err)
	}
	if reload.GetTotal() != 1 || reload.GetValid() != 1 || reload.GetInvalid() != 0 {
		t.Fatalf("unexpected reload response: %+v", reload)
	}
}

func TestGRPCServer_GetScript_NotFound(t *testing.T) {
	registry, err := newScriptRegistry(t.TempDir())
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}
	server := NewGRPCServer(&Service{scriptRegistry: registry}, nil)

	_, err = server.GetScript(context.Background(), &pb.GetScriptRequest{ScriptID: "NOPE"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestGRPCServer_Analyze_EmptyTaskID(t *testing.T) {
	server := NewGRPCServer(nil, nil)

	req := &pb.AnalyzeRequest{
		TaskID: "",
		Uuid:   "test-uuid",
		PcapID: "pcap-001",
	}
	_, err := server.Analyze(context.Background(), req)

	if err == nil {
		t.Error("expected error for empty taskID")
	}
}

func TestGRPCServer_Analyze_EmptyUUID(t *testing.T) {
	server := NewGRPCServer(nil, nil)

	req := &pb.AnalyzeRequest{
		TaskID: "test-001",
		Uuid:   "",
		PcapID: "pcap-001",
	}
	_, err := server.Analyze(context.Background(), req)

	if err == nil {
		t.Error("expected error for empty uuid")
	}
}

func TestGRPCServer_Analyze_EmptyPcapID(t *testing.T) {
	server := NewGRPCServer(nil, nil)

	req := &pb.AnalyzeRequest{
		TaskID: "test-001",
		Uuid:   "test-uuid",
		PcapID: "",
	}
	_, err := server.Analyze(context.Background(), req)

	if err == nil {
		t.Error("expected error for empty pcapID")
	}
}

func TestExtractReqFromGRPC_OutputDir(t *testing.T) {
	req := extractReqFromGRPC(&pb.ExtractRequest{
		TaskID:               "task-1",
		Uuid:                 "uuid-1",
		PcapID:               "pcap-1",
		PcapPath:             "/tmp/test.pcap",
		OutputDir:            "/tmp/extracted",
		ExtractedFileMinSize: 1,
		ExtractedFileMaxSize: 20,
	})

	if req.OutputDir != "/tmp/extracted" {
		t.Fatalf("expected outputDir to be preserved, got %q", req.OutputDir)
	}
}
