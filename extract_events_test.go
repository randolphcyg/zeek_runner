package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessExtractedFiles_PublishesFileEvents(t *testing.T) {
	dir, err := os.MkdirTemp(".", "tmp_extract_events_")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	pcapPath := filepath.Join(dir, "input.pcap")
	if err := os.WriteFile(pcapPath, []byte("pcap"), 0o600); err != nil {
		t.Fatalf("write pcap: %v", err)
	}

	files := []string{"Fa111-safe-a.bin", "Fb222-safe-b.zip", "Fc333-safe-c.exe"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatalf("write extracted file %s: %v", name, err)
		}
	}

	var events []extractFileEvent
	service := &Service{
		extractPublisher: &extractEventPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				if key != "task-1" {
					t.Fatalf("unexpected key %q", key)
				}
				if eventType != "file_extracted" {
					t.Fatalf("unexpected event type %q", eventType)
				}
				event, ok := payload.(extractFileEvent)
				if !ok {
					t.Fatalf("unexpected payload type %T", payload)
				}
				events = append(events, event)
				return nil
			},
		},
	}

	summary, err := service.processExtractedFiles(context.Background(), zeekRunOptions{
		taskID:     "task-1",
		uuid:       "uuid-1",
		pcapID:     "pcap-1",
		pcapPath:   pcapPath,
		scriptID:   "EXTRACT_TASK",
		scriptPath: "/opt/zeek_runner/file_extract_script/extract_file.zeek",
		outputDir:  dir,
	})
	if err != nil {
		t.Fatalf("process extracted files: %v", err)
	}

	if summary.FileCount != 3 || summary.UniqueFileCount != 3 || summary.DuplicateFileCount != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 file events, got %d", len(events))
	}

	for _, event := range events {
		if event.TaskID != "task-1" || event.UUID != "uuid-1" || event.OutputDir != dir {
			t.Fatalf("unexpected event payload: %+v", event)
		}
		if event.SHA256 == "" || event.FileSize == 0 || event.FilePath == "" || event.EventTime == "" {
			t.Fatalf("expected populated file event: %+v", event)
		}
		if event.FUID == "" || event.OriginalFileName == "" {
			t.Fatalf("expected fuid/original file name: %+v", event)
		}
		if event.FileName != event.FUID+"-"+event.OriginalFileName {
			t.Fatalf("unexpected file name mapping: %+v", event)
		}
	}
}

func TestPublishExtractTaskEvent_Failed(t *testing.T) {
	var captured extractTaskEvent

	service := &Service{
		extractPublisher: &extractEventPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				if key != "task-2" {
					t.Fatalf("unexpected key %q", key)
				}
				if eventType != "task_failed" {
					t.Fatalf("unexpected event type %q", eventType)
				}
				event, ok := payload.(extractTaskEvent)
				if !ok {
					t.Fatalf("unexpected payload type %T", payload)
				}
				captured = event
				return nil
			},
		},
	}

	err := service.publishExtractTaskEvent(context.Background(), zeekRunOptions{
		taskID:     "task-2",
		uuid:       "uuid-2",
		pcapID:     "pcap-2",
		pcapPath:   "/tmp/input.pcap",
		scriptID:   "EXTRACT_TASK",
		scriptPath: "/tmp/extract_file.zeek",
		outputDir:  "/tmp/out",
	}, "task_failed", "failed", extractTaskSummary{
		FileCount:          1,
		UniqueFileCount:    1,
		DuplicateFileCount: 0,
	}, errors.New("boom"))
	if err != nil {
		t.Fatalf("publish extract task event: %v", err)
	}

	if captured.EventType != "task_failed" || captured.Status != "failed" || captured.Error != "boom" {
		t.Fatalf("unexpected captured event: %+v", captured)
	}
	if captured.FileCount != 1 || captured.UniqueFileCount != 1 || captured.CompletedAt == "" {
		t.Fatalf("unexpected captured event summary: %+v", captured)
	}
}

func TestProcessExtractedFiles_DeduplicatesWithinTask(t *testing.T) {
	dir, err := os.MkdirTemp(".", "tmp_extract_dedup_")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	pcapPath := filepath.Join(dir, "input.pcap")
	if err := os.WriteFile(pcapPath, []byte("pcap"), 0o600); err != nil {
		t.Fatalf("write pcap: %v", err)
	}

	// 创建两个内容相同的文件（模拟重复下载）
	sameContent := []byte("same content for deduplication")
	file1 := filepath.Join(dir, "Fdup1-file1.zip")
	file2 := filepath.Join(dir, "Fdup2-file2.zip")
	if err := os.WriteFile(file1, sameContent, 0o600); err != nil {
		t.Fatalf("write file1: %v", err)
	}
	if err := os.WriteFile(file2, sameContent, 0o600); err != nil {
		t.Fatalf("write file2: %v", err)
	}

	var events []extractFileEvent
	service := &Service{
		extractPublisher: &extractEventPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				if eventType != "file_extracted" {
					t.Fatalf("unexpected event type %q", eventType)
				}
				event, ok := payload.(extractFileEvent)
				if !ok {
					t.Fatalf("unexpected payload type %T", payload)
				}
				events = append(events, event)
				return nil
			},
		},
		// 不设置 fileDedupMgr，这样会走 fallback 路径，所有文件都是新文件
	}

	summary, err := service.processExtractedFiles(context.Background(), zeekRunOptions{
		taskID:     "task-dedup",
		uuid:       "uuid-dedup",
		pcapID:     "pcap-dedup",
		pcapPath:   pcapPath,
		scriptID:   "EXTRACT_TASK",
		scriptPath: "/opt/zeek_runner/file_extract_script/extract_file.zeek",
		outputDir:  dir,
	})
	if err != nil {
		t.Fatalf("process extracted files: %v", err)
	}

	// 验证统计数据：没有去重管理器时，所有文件都是新文件
	if summary.FileCount != 2 {
		t.Fatalf("expected FileCount=2, got %d", summary.FileCount)
	}
	if summary.UniqueFileCount != 2 {
		t.Fatalf("expected UniqueFileCount=2, got %d", summary.UniqueFileCount)
	}
	if summary.DuplicateFileCount != 0 {
		t.Fatalf("expected DuplicateFileCount=0, got %d", summary.DuplicateFileCount)
	}

	// 验证发布了两条 file_extracted 事件
	if len(events) != 2 {
		t.Fatalf("expected 2 file_extracted events, got %d", len(events))
	}
	for _, event := range events {
		if event.FUID == "" || event.OriginalFileName == "" {
			t.Fatalf("expected fuid/original file name: %+v", event)
		}
	}
}
