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
	if written != 4 {
		t.Fatalf("expected 4 bytes written, got %d", written)
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
