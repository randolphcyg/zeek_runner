package main

import (
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestIsScriptReloadEvent(t *testing.T) {
	if !isScriptReloadEvent(fsnotify.Event{Name: "/opt/zeek_runner/scripts/test.zeek", Op: fsnotify.Write}) {
		t.Fatal("expected .zeek write to trigger reload")
	}
	if !isScriptReloadEvent(fsnotify.Event{Name: "/opt/zeek_runner/scripts/test.zeek", Op: fsnotify.Rename}) {
		t.Fatal("expected .zeek rename to trigger reload")
	}
	if isScriptReloadEvent(fsnotify.Event{Name: "/opt/zeek_runner/scripts/test.tmp", Op: fsnotify.Write}) {
		t.Fatal("expected non-.zeek write to be ignored")
	}
	if isScriptReloadEvent(fsnotify.Event{Name: "/opt/zeek_runner/scripts/test.zeek", Op: fsnotify.Chmod}) {
		t.Fatal("expected chmod to be ignored")
	}
}

func TestScriptAutoReloadConfigChanged(t *testing.T) {
	base := ZeekConfig{
		ScriptRoot:           "/scripts",
		AutoReloadScripts:    true,
		ScriptReloadDebounce: "2s",
		ScriptReloadInterval: "60s",
	}
	if scriptAutoReloadConfigChanged(base, base) {
		t.Fatal("expected identical configs to be unchanged")
	}
	changed := base
	changed.ScriptReloadInterval = "30s"
	if !scriptAutoReloadConfigChanged(base, changed) {
		t.Fatal("expected interval change to be detected")
	}
}
