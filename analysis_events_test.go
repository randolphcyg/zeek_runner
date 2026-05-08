package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublishSubtaskHitEvents_AddsStableEventID(t *testing.T) {
	dir := t.TempDir()
	noticeLog := "#fields\tnote\tmsg\tsub\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n" +
		"HTTP_Command_Injection\tcommand injection\t/bin/sh\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\n"
	if err := os.WriteFile(filepath.Join(dir, "notice.log"), []byte(noticeLog), 0o600); err != nil {
		t.Fatalf("write notice log: %v", err)
	}

	var events []analysisSubtaskHitEvent
	service := &Service{
		analysisPublisher: &analysisEventPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				if key != "task-1" {
					t.Fatalf("unexpected kafka key %q", key)
				}
				if eventType != "subtask_hit" {
					t.Fatalf("unexpected event type %q", eventType)
				}
				event, ok := payload.(analysisSubtaskHitEvent)
				if !ok {
					t.Fatalf("unexpected payload type %T", payload)
				}
				events = append(events, event)
				return nil
			},
		},
	}

	opts := zeekRunOptions{
		taskID:     "task-1",
		uuid:       "uuid-1",
		taskType:   string(offlineTaskScan),
		pcapID:     "pcap-1",
		pcapPath:   "/tmp/input.pcap",
		scriptID:   "script-1",
		scriptPath: "/tmp/script.zeek",
	}
	if err := service.publishSubtaskHitEvents(context.Background(), opts, dir); err != nil {
		t.Fatalf("publish subtask hits: %v", err)
	}
	if err := service.publishSubtaskHitEvents(context.Background(), opts, dir); err != nil {
		t.Fatalf("publish subtask hits again: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 captured events, got %d", len(events))
	}
	first := events[0]
	if first.EventID == "" || first.EventType != "subtask_hit" || first.EventVersion != eventVersion {
		t.Fatalf("expected event metadata: %+v", first)
	}
	if first.EventID != events[1].EventID {
		t.Fatalf("expected stable event id, got %q and %q", first.EventID, events[1].EventID)
	}
	if first.RuleType != "HTTP_Command_Injection" || first.Message != "command injection" || first.Indicator != "/bin/sh" {
		t.Fatalf("unexpected notice mapping: %+v", first)
	}
	if first.SrcIp != "10.0.0.1" || first.SrcPort != 12345 || first.DstIp != "10.0.0.2" || first.DstPort != 80 || first.Proto != "tcp" {
		t.Fatalf("unexpected five tuple mapping: %+v", first)
	}
}

func TestPublishSubtaskEvent_CompletedAndFailedEventIDs(t *testing.T) {
	var events []analysisSubtaskEvent
	service := &Service{
		analysisPublisher: &analysisEventPublisher{
			publishFn: func(ctx context.Context, key string, eventType string, payload any) error {
				event, ok := payload.(analysisSubtaskEvent)
				if !ok {
					t.Fatalf("unexpected payload type %T", payload)
				}
				if event.EventType != eventType {
					t.Fatalf("event type mismatch: payload=%q header=%q", event.EventType, eventType)
				}
				events = append(events, event)
				return nil
			},
		},
	}
	opts := zeekRunOptions{
		taskID:     "task-1",
		uuid:       "uuid-1",
		taskType:   string(offlineTaskScan),
		pcapID:     "pcap-1",
		pcapPath:   "/tmp/input.pcap",
		scriptID:   "script-1",
		scriptPath: "/tmp/script.zeek",
	}

	service.publishSubtaskEvent(context.Background(), opts, zeekLogStats{NoticeCount: 1}, 1500*time.Millisecond, nil)
	service.publishSubtaskEvent(context.Background(), opts, zeekLogStats{}, 2*time.Second, errors.New("boom"))

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventID == "" || events[0].Status != "success" || events[0].Verdict != "malicious" || events[0].DurationMs != 1500 {
		t.Fatalf("unexpected completed event: %+v", events[0])
	}
	if events[1].EventID == "" || events[1].Status != "failed" || events[1].Verdict != "error" || events[1].Error != "boom" {
		t.Fatalf("unexpected failed event: %+v", events[1])
	}
	if events[0].EventID == events[1].EventID {
		t.Fatalf("expected different event ids for different terminal event types")
	}
}
