package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishVerificationLogEvents_PublishesFullLogsForVerification(t *testing.T) {
	dir := t.TempDir()
	connLog := "#fields\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n" +
		"C1\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\n"
	noticeLog := "#fields\tnote\tmsg\n" +
		"HTTP_Command_Injection\tcommand injection\n"
	taskStatusLog := "#fields\tcompletedTime\n2026-05-05T00:00:00Z\n"

	for name, content := range map[string]string{
		"conn.log":        connLog,
		"notice.log":      noticeLog,
		"task_status.log": taskStatusLog,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	var events []verificationLogEvent
	service := &Service{
		verificationPublisher: &verificationLogPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				if key != "uuid-verify" {
					t.Fatalf("unexpected kafka key %q", key)
				}
				if eventType != "verification_log" {
					t.Fatalf("unexpected event type %q", eventType)
				}
				event, ok := payload.(verificationLogEvent)
				if !ok {
					t.Fatalf("unexpected payload type %T", payload)
				}
				events = append(events, event)
				return nil
			},
		},
	}

	opts := zeekRunOptions{
		taskID:     "task-verify",
		uuid:       "uuid-verify",
		taskType:   string(offlineTaskScan),
		pcapID:     "pcap-verify",
		pcapPath:   "/tmp/input.pcap",
		scriptID:   "script-verify",
		scriptPath: "/tmp/script.zeek",
		onlyNotice: false,
	}
	if err := service.publishVerificationLogEvents(context.Background(), opts, dir); err != nil {
		t.Fatalf("publish verification logs: %v", err)
	}
	if err := service.publishVerificationLogEvents(context.Background(), opts, dir); err != nil {
		t.Fatalf("publish verification logs again: %v", err)
	}

	if len(events) != 4 {
		t.Fatalf("expected two logs per publish and task_status skipped, got %d", len(events))
	}

	byType := map[string]verificationLogEvent{}
	for _, event := range events[:2] {
		byType[event.LogType] = event
		if event.EventID == "" || event.EventVersion != eventVersion || event.Producer != producerName {
			t.Fatalf("expected metadata: %+v", event)
		}
		if event.TaskID != opts.taskID || event.UUID != opts.uuid || event.PcapID != opts.pcapID || event.ScriptID != opts.scriptID {
			t.Fatalf("unexpected task identity: %+v", event)
		}
	}

	if byType["conn"].Content["uid"] != "C1" || byType["conn"].Content["proto"] != "tcp" {
		t.Fatalf("unexpected conn content: %+v", byType["conn"])
	}
	if byType["notice"].Content["note"] != "HTTP_Command_Injection" {
		t.Fatalf("unexpected notice content: %+v", byType["notice"])
	}
	if events[0].EventID != events[2].EventID || events[1].EventID != events[3].EventID {
		t.Fatalf("expected stable event ids across duplicate publishes")
	}
}

func TestPublishVerificationLogEvents_SkipsOnlyNoticeScans(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "conn.log"), []byte("#fields\tuid\nC1\n"), 0o600); err != nil {
		t.Fatalf("write conn log: %v", err)
	}

	published := false
	service := &Service{
		verificationPublisher: &verificationLogPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				published = true
				return nil
			},
		},
	}

	err := service.publishVerificationLogEvents(context.Background(), zeekRunOptions{
		taskID:     "task-detect",
		uuid:       "uuid-detect",
		taskType:   string(offlineTaskScan),
		onlyNotice: true,
	}, dir)
	if err != nil {
		t.Fatalf("publish verification logs: %v", err)
	}
	if published {
		t.Fatalf("expected onlyNotice scan to skip verification logs")
	}
}
