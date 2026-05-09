package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScriptRegistry_ListAndMetadata(t *testing.T) {
	root := t.TempDir()
	content := `# SCRIPT_ID: SCRIPT_ONE
# NoticeTypes: TestModule::TestNotice
# 行为类型：命令执行
# 行为分类：Web攻击
# 行为描述：检测命令执行
# 攻击特征：shell payload
event zeek_init() {}
`
	path := writeTestScript(t, root, "detect_one.zeek", content)
	writeTestScript(t, root, "missing.zeek", "event zeek_init() {}\n")
	writeTestScript(t, root, "dup_a.zeek", `const SCRIPT_ID = "DUP";`)
	writeTestScript(t, root, "dup_b.zeek", `const SCRIPT_ID = "DUP";`)
	writeTestScript(t, filepath.Join(root, "nested"), "nested.zeek", `const SCRIPT_ID = "NESTED";`)

	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}

	all := registry.List(ListScriptsRequest{})
	if len(all) != 4 {
		t.Fatalf("expected only top-level .zeek files, got %d", len(all))
	}

	script, err := registry.Get("SCRIPT_ONE")
	if err != nil {
		t.Fatalf("Get SCRIPT_ONE failed: %v", err)
	}
	if script.ScriptName != "detect_one" || script.ScriptPath != filepath.ToSlash(path) {
		t.Fatalf("unexpected script identity: %+v", script)
	}
	if script.ExpCodeType != "zeek" || !script.Enabled || !script.Valid {
		t.Fatalf("unexpected script status: %+v", script)
	}
	if script.BehaviorType != "命令执行" ||
		script.BehaviorCategory != "Web攻击" ||
		script.Description != "检测命令执行" ||
		script.AttackFeature != "shell payload" {
		t.Fatalf("metadata not parsed: %+v", script)
	}
	if !reflect.DeepEqual(script.NoticeTypes, []string{"TestModule::TestNotice"}) {
		t.Fatalf("notice types not parsed: %+v", script.NoticeTypes)
	}
	sum := sha256.Sum256([]byte(content))
	if script.Checksum != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum mismatch: %s", script.Checksum)
	}
	if script.UpdatedAt == "" || script.Size == "" {
		t.Fatalf("expected updatedAt and size: %+v", script)
	}

	enabled := registry.List(ListScriptsRequest{EnabledOnly: true})
	if len(enabled) != 1 || enabled[0].ScriptID != "SCRIPT_ONE" {
		t.Fatalf("enabledOnly returned unexpected scripts: %+v", enabled)
	}

	filtered := registry.List(ListScriptsRequest{Name: "one"})
	if len(filtered) != 1 || filtered[0].ScriptID != "SCRIPT_ONE" {
		t.Fatalf("name filter failed: %+v", filtered)
	}

	foundMissing := false
	for _, script := range all {
		if script.ScriptName == "missing" && !script.Valid && !script.Enabled && script.Error == "missing SCRIPT_ID" {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatalf("missing SCRIPT_ID script not returned as invalid: %+v", all)
	}
}

func TestScriptRegistry_InvalidScripts(t *testing.T) {
	root := t.TempDir()
	writeTestScript(t, root, "missing.zeek", "event zeek_init() {}\n")
	writeTestScript(t, root, "dup_a.zeek", `const SCRIPT_ID = "DUP";`)
	writeTestScript(t, root, "dup_b.zeek", `const SCRIPT_ID = "DUP";`)

	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}

	reload, err := registry.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if reload.Total != 3 || reload.Valid != 0 || reload.Invalid != 3 {
		t.Fatalf("unexpected reload stats: %+v", reload)
	}

	for _, script := range reload.Scripts {
		if script.Valid || script.Enabled || script.Error == "" {
			t.Fatalf("expected invalid disabled script with error: %+v", script)
		}
	}

	if _, err := registry.Resolve("DUP", ""); !errors.Is(err, ErrScriptInvalid) {
		t.Fatalf("expected duplicate script to be invalid, got %v", err)
	}
}

func TestScriptRegistry_ResolvePath(t *testing.T) {
	root := t.TempDir()
	path := writeTestScript(t, root, "script.zeek", `const SCRIPT_ID = "SCRIPT";`)

	registry, err := newScriptRegistry(root)
	if err != nil {
		t.Fatalf("newScriptRegistry failed: %v", err)
	}

	if _, err := registry.Resolve("SCRIPT", path); err != nil {
		t.Fatalf("expected matching scriptPath to resolve: %v", err)
	}
	if _, err := registry.Resolve("SCRIPT", "/tmp/other.zeek"); err == nil || !strings.Contains(err.Error(), "scriptPath mismatch") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
	if _, err := registry.Resolve("NOPE", ""); !errors.Is(err, ErrScriptNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestScriptRegistry_LegacyScriptIDFallback(t *testing.T) {
	root := t.TempDir()
	path := writeTestScript(t, root, "legacy.zeek", `const SCRIPT_ID = "LEGACY_SCRIPT";
module Legacy;
export {
    redef enum Notice::Type += {
        ## fallback comments must be ignored
        LegacyNotice,
    };
}
`)

	script, err := parseScriptInfo(path)
	if err != nil {
		t.Fatalf("parseScriptInfo failed: %v", err)
	}
	if script.ScriptID != "LEGACY_SCRIPT" {
		t.Fatalf("legacy SCRIPT_ID fallback failed: %+v", script)
	}
	if !reflect.DeepEqual(script.NoticeTypes, []string{"LegacyNotice"}) {
		t.Fatalf("enum notice fallback failed: %+v", script.NoticeTypes)
	}
}

func TestScriptRegistry_CommentMetadataPreferred(t *testing.T) {
	root := t.TempDir()
	path := writeTestScript(t, root, "preferred.zeek", `# SCRIPT_ID: COMMENT_SCRIPT
# NoticeTypes: Preferred::Notice, Preferred::Other
const SCRIPT_ID = "LEGACY_SCRIPT";
module Preferred;
export {
    redef enum Notice::Type += { FallbackNotice };
}
`)

	script, err := parseScriptInfo(path)
	if err != nil {
		t.Fatalf("parseScriptInfo failed: %v", err)
	}
	if script.ScriptID != "COMMENT_SCRIPT" {
		t.Fatalf("comment SCRIPT_ID should win over legacy const: %+v", script)
	}
	expected := []string{"Preferred::Notice", "Preferred::Other"}
	if !reflect.DeepEqual(script.NoticeTypes, expected) {
		t.Fatalf("comment NoticeTypes should win over enum fallback: got %+v want %+v", script.NoticeTypes, expected)
	}
}

func TestRepositoryScriptsUseCommentMetadata(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("scripts", "*.zeek"))
	if err != nil {
		t.Fatalf("glob scripts failed: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected repository scripts")
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s failed: %v", path, err)
		}
		content := string(data)
		if legacyScriptIDPattern.MatchString(content) {
			t.Fatalf("%s still defines top-level const SCRIPT_ID", path)
		}
		if matches := commentScriptIDPattern.FindAllStringSubmatch(content, -1); len(matches) != 1 {
			t.Fatalf("%s should have exactly one # SCRIPT_ID, got %d", path, len(matches))
		}
		if strings.Contains(content, "# BatchMode: disabled") {
			continue
		}
		if noticeTypes := extractNoticeTypes(content); len(noticeTypes) == 0 {
			t.Fatalf("%s should declare # NoticeTypes", path)
		}
	}
}

func writeTestScript(t *testing.T, root, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write script failed: %v", err)
	}
	return path
}
