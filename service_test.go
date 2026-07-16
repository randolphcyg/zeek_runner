package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLimitWriter_AppendsTruncationMarker(t *testing.T) {
	var buf bytes.Buffer
	writer := &LimitWriter{w: &buf, n: 4}

	written, err := writer.Write([]byte("abcdefgh"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if written != 8 {
		t.Fatalf("expected original write length 8, got %d", written)
	}

	got := buf.String()
	if !strings.Contains(got, "abcd") {
		t.Fatalf("expected preserved prefix, got %q", got)
	}
	if !strings.Contains(got, "...[truncated]") {
		t.Fatalf("expected truncation marker, got %q", got)
	}
}

func TestLimitWriter_AppendsMarkerOnFollowUpWrite(t *testing.T) {
	var buf bytes.Buffer
	writer := &LimitWriter{w: &buf, n: 2}

	if _, err := writer.Write([]byte("ab")); err != nil {
		t.Fatalf("unexpected error on first write: %v", err)
	}
	if _, err := writer.Write([]byte("cd")); err != nil {
		t.Fatalf("unexpected error on second write: %v", err)
	}

	if count := strings.Count(buf.String(), "...[truncated]"); count != 1 {
		t.Fatalf("expected one truncation marker, got %d in %q", count, buf.String())
	}
}

func TestZeekRunOptions_ConfigPath(t *testing.T) {
	tests := []struct {
		name string
		opts zeekRunOptions
		want string
	}{
		{
			name: "default malicious scan skips intel feeds",
			opts: zeekRunOptions{taskType: string(offlineTaskScan), scriptID: "DETECT_HTTP_FLOOD_v1"},
			want: customConfigPath,
		},
		{
			name: "intel scan uses intel profile",
			opts: zeekRunOptions{taskType: string(offlineTaskScan), scriptID: "DETECT_INTEL_FEED_HIT_v1"},
			want: customIntelConfigPath,
		},
		{
			name: "extract uses extract profile",
			opts: zeekRunOptions{taskType: string(offlineTaskExtract), scriptID: "DETECT_INTEL_FEED_HIT_v1"},
			want: customExtractConfigPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.zeekConfigPath(); got != tt.want {
				t.Fatalf("expected config path %q, got %q", tt.want, got)
			}
		})
	}
}

func TestParentStatusFromTasksRepairsStaleRunningAggregate(t *testing.T) {
	status := parentStatusFromTasks("task-1", []*Task{
		{
			TaskID:      "task-1",
			UUID:        "uuid-success",
			PcapID:      "pcap-1",
			PcapPath:    "/tmp/a.pcap",
			Status:      TaskStatusSuccess,
			HitCount:    2,
			NoticeCount: 1,
		},
		{
			TaskID: "task-1",
			UUID:   "uuid-timeout",
			Status: TaskStatusTimeout,
		},
	})

	if status.Status != "partial_failed" {
		t.Fatalf("Status = %s, want partial_failed", status.Status)
	}
	if status.TotalCount != 2 || status.SuccessCount != 1 || status.TimeoutCount != 1 || status.PendingCount != 0 || status.RunningCount != 0 {
		t.Fatalf("unexpected counts: %+v", status)
	}
	if status.HitCount != 2 || status.NoticeCount != 1 {
		t.Fatalf("unexpected hit stats: %+v", status)
	}
}
