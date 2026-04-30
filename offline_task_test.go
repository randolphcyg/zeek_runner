package main

import "testing"

func TestNewOfflineScanTask_ZeekEnv(t *testing.T) {
	spec := newOfflineScanTask(AnalyzeReq{
		TaskID:               "task-1",
		UUID:                 "uuid-1",
		OnlyNotice:           true,
		PcapID:               "pcap-1",
		PcapPath:             "/tmp/test.pcap",
		ScriptID:             "script-1",
		ScriptPath:           "/tmp/test.zeek",
		ExtractedFileMinSize: 8,
	})

	env := spec.zeekEnv("kafka:9092")
	if spec.taskType() != "MALICIOUS_SCAN" {
		t.Fatalf("expected MALICIOUS_SCAN, got %s", spec.taskType())
	}
	if env["ONLY_NOTICE"] != "true" {
		t.Fatalf("expected ONLY_NOTICE=true, got %q", env["ONLY_NOTICE"])
	}
	if env["ENABLE_OFFLINE_INTEL_REPLAY"] != "true" {
		t.Fatalf("expected replay enabled, got %q", env["ENABLE_OFFLINE_INTEL_REPLAY"])
	}
	if env["SCRIPT_ID"] != "script-1" {
		t.Fatalf("expected SCRIPT_ID to be preserved, got %q", env["SCRIPT_ID"])
	}
	if env["EXTRACTED_FILE_MIN_SIZE"] != "8" {
		t.Fatalf("expected EXTRACTED_FILE_MIN_SIZE=8, got %q", env["EXTRACTED_FILE_MIN_SIZE"])
	}
}

func TestNewOfflineExtractTask_DefaultsAndEnv(t *testing.T) {
	spec := newOfflineExtractTask(ExtractReq{
		TaskID:               "task-2",
		UUID:                 "uuid-2",
		PcapID:               "pcap-2",
		PcapPath:             "/tmp/test.pcap",
		OutputDir:            "/tmp/out",
		ExtractedFileMinSize: 4,
		ExtractedFileMaxSize: 20,
	})

	env := spec.zeekEnv("kafka:9092")
	if spec.taskType() != "FILE_EXTRACT" {
		t.Fatalf("expected FILE_EXTRACT, got %s", spec.taskType())
	}
	if spec.scriptID != extractTaskScriptID {
		t.Fatalf("expected extract script id, got %q", spec.scriptID)
	}
	if spec.scriptPath != defaultExtractScriptPath {
		t.Fatalf("expected default extract script path, got %q", spec.scriptPath)
	}
	if env["ENABLE_OFFLINE_INTEL_REPLAY"] != "false" {
		t.Fatalf("expected replay disabled, got %q", env["ENABLE_OFFLINE_INTEL_REPLAY"])
	}
	if env["MIN_FILE_SIZE_KB"] != "4" || env["MAX_FILE_SIZE_MB"] != "20" {
		t.Fatalf("unexpected extract size envs: %q %q", env["MIN_FILE_SIZE_KB"], env["MAX_FILE_SIZE_MB"])
	}
	if _, ok := env["ONLY_NOTICE"]; ok {
		t.Fatalf("extract env should not include ONLY_NOTICE")
	}
}

func TestNewOfflineTaskFromStored_ExtractTask(t *testing.T) {
	spec := newOfflineTaskFromStored(&Task{
		TaskID:               "task-3",
		UUID:                 "uuid-3",
		PcapID:               "pcap-3",
		PcapPath:             "/tmp/test.pcap",
		ScriptID:             "ignored",
		ScriptPath:           "",
		OnlyNotice:           true,
		OutputDir:            "/tmp/out",
		ExtractedFileMinSize: 1,
		ExtractedFileMaxSize: 2,
	})

	if spec.taskType() != "FILE_EXTRACT" {
		t.Fatalf("expected FILE_EXTRACT, got %s", spec.taskType())
	}
	if spec.scriptID != extractTaskScriptID {
		t.Fatalf("expected extract script id, got %q", spec.scriptID)
	}
	if spec.scriptPath != defaultExtractScriptPath {
		t.Fatalf("expected default extract script path, got %q", spec.scriptPath)
	}
	if spec.onlyNotice {
		t.Fatalf("extract task should not preserve onlyNotice")
	}
}
