package main

import (
	"context"
	"testing"

	pb "zeek_runner/api/pb"
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
