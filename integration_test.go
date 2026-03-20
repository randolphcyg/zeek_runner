//go:build integration
// +build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	pb "zeek_runner/api/pb"
)

func skipIfNoZeek(t *testing.T) {
	if _, err := exec.LookPath("zeek"); err != nil {
		t.Skip("zeek not installed, skipping integration test")
	}
}

func TestIntegration_SyntaxCheck_ValidScript(t *testing.T) {
	skipIfNoZeek(t)

	if _, err := os.Stat("scripts/detect_ssh_bruteforce.zeek"); os.IsNotExist(err) {
		t.Skip("script file not found")
	}

	content, err := os.ReadFile("scripts/detect_ssh_bruteforce.zeek")
	if err != nil {
		t.Fatalf("failed to read script: %v", err)
	}

	result, err := doSyntaxCheck("", string(content))
	if err != nil {
		t.Fatalf("syntax check failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid script, got error: %s", result.Error)
	}
}

func TestIntegration_SyntaxCheck_InvalidScript(t *testing.T) {
	skipIfNoZeek(t)

	invalidScript := `event connection_new(c: connection) {
		print invalid_identifier_here
	}`

	result, err := doSyntaxCheck("", invalidScript)
	if err != nil {
		t.Fatalf("syntax check failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid script to be detected")
	}

	if result.Error == "" {
		t.Error("expected error message for invalid script")
	}
}

func TestIntegration_SyntaxCheck_ScriptPath(t *testing.T) {
	skipIfNoZeek(t)

	if _, err := os.Stat("scripts/detect_http_cmd_injection.zeek"); os.IsNotExist(err) {
		t.Skip("script file not found")
	}

	result, err := doSyntaxCheck("scripts/detect_http_cmd_injection.zeek", "")
	if err != nil {
		t.Fatalf("syntax check failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid script, got error: %s", result.Error)
	}
}

func TestIntegration_ZeekVersion(t *testing.T) {
	skipIfNoZeek(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := NewGRPCServer(nil, nil)
	req := &pb.VersionCheckRequest{Component: "zeek"}

	resp, err := server.VersionCheck(ctx, req)
	if err != nil {
		t.Fatalf("failed to get zeek version: %v", err)
	}

	if resp.Component != "zeek" {
		t.Errorf("expected component 'zeek', got %s", resp.Component)
	}

	if resp.Version == "" {
		t.Error("expected non-empty version")
	}

	t.Logf("Zeek version: %s", resp.Version)
}

func TestIntegration_AllScripts(t *testing.T) {
	skipIfNoZeek(t)

	scripts := []string{
		"scripts/detect_dns_flood.zeek",
		"scripts/detect_http_cmd_injection.zeek",
		"scripts/detect_http_flood.zeek",
		"scripts/detect_http_suspicious_ua.zeek",
		"scripts/detect_http_webshell.zeek",
		"scripts/detect_slammer_worm.zeek",
		"scripts/detect_sqli_webshell.zeek",
		"scripts/detect_ssh_bruteforce.zeek",
		"scripts/detect_ssh_file_transfer.zeek",
		"scripts/detect_syn_flood.zeek",
	}

	for _, script := range scripts {
		t.Run(script, func(t *testing.T) {
			if _, err := os.Stat(script); os.IsNotExist(err) {
				t.Skipf("script %s not found", script)
			}

			result, err := doSyntaxCheck(script, "")
			if err != nil {
				t.Fatalf("syntax check failed: %v", err)
			}

			if !result.Valid {
				t.Errorf("script %s has syntax errors: %s", script, result.Error)
			}
		})
	}
}
