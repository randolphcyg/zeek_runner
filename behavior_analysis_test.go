package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"zeek_runner/internal/upgradebehavior"
)

// --- 测试辅助 ---

// newTestBehaviorEngine 使用内置规则集构造测试用行为引擎（不含归档器）。
func newTestBehaviorEngine(t *testing.T) *behaviorEngine {
	t.Helper()
	rs := upgradebehavior.LoadEmbeddedRuleSet()
	matcher := upgradebehavior.NewBehaviorMatcher(rs, upgradebehavior.NewVendorDomainIndex(nil))
	return &behaviorEngine{
		matcher:    matcher,
		ruleSet:    rs,
		rulesetSHA: "test-sha-256",
		engineVer:  behaviorEngineVersion,
	}
}

// newTestBehaviorEngineWithArchiver 构造带归档器的测试引擎。
func newTestBehaviorEngineWithArchiver(t *testing.T) (*behaviorEngine, string) {
	t.Helper()
	eng := newTestBehaviorEngine(t)
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}
	eng.archiver = archiver
	return eng, dir
}

func TestBuildBehaviorBlockPreservesVendorID(t *testing.T) {
	block := buildBehaviorBlock(upgradebehavior.ClassificationResult{
		VendorID:       "V-TPLINK",
		BehaviorRuleID: "VENDOR-TPLINK-CHECK-001",
		IsIoTUpgrade:   true,
	}, &behaviorEngine{engineVer: "test", rulesetSHA: "test-sha"})
	if block.VendorID != "V-TPLINK" {
		t.Fatalf("VendorID = %q, want V-TPLINK", block.VendorID)
	}
}

// makeHTTPTransaction 构造一个 HTTP 事务用于测试。
func makeHTTPTransaction(method, uri string, statusCode int, respBody []byte) httpTransaction {
	return httpTransaction{
		SrcIP:           "10.0.0.1",
		SrcPort:         12345,
		DstIP:           "10.0.0.2",
		DstPort:         80,
		Method:          method,
		RequestURI:      uri,
		Host:            "example.com",
		RequestHeaders:  map[string]string{"host": "example.com"},
		ResponseHeaders: map[string]string{},
		StatusCode:      statusCode,
		ResponseBody:    respBody,
		TxSeq:           1,
	}
}

// --- HTTP 场景测试 ---

// 测试固件下载（GLOBAL-DOWNLOAD-001）
func TestBehavior_FirmwareDownload(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	firmwareBody := bytes.Repeat([]byte{0xFF, 0xFE, 0xFD}, 1024)

	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, firmwareBody)
	tx.ResponseHeaders["content-type"] = "application/octet-stream"
	tx.ResponseHeaders["content-length"] = itoa(len(firmwareBody))

	block := eng.analyzeHTTPTransaction(tx, "pcap-fw-001")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-001" {
		t.Fatalf("expected rule GLOBAL-DOWNLOAD-001, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "firmware_download" {
		t.Fatalf("expected urlType firmware_download, got %q", block.URLType)
	}
	if block.BehaviorStage != "download" {
		t.Fatalf("expected stage download, got %q", block.BehaviorStage)
	}
	if block.ArtifactKind != "firmware" {
		t.Fatalf("expected artifactKind firmware, got %q", block.ArtifactKind)
	}
	if block.DetectionScore < 60 {
		t.Fatalf("expected detectionScore >= 60, got %d", block.DetectionScore)
	}
	if block.PayloadSHA256 == "" {
		t.Fatal("expected non-empty payloadSHA256")
	}
	if block.PayloadAnalysisMode != "full" {
		t.Fatalf("expected payloadAnalysisMode full, got %q", block.PayloadAnalysisMode)
	}
	if block.EngineVersion != behaviorEngineVersion {
		t.Fatalf("expected engineVersion %q, got %q", behaviorEngineVersion, block.EngineVersion)
	}
	if block.RulesetSHA256 == "" {
		t.Fatal("expected non-empty rulesetSHA256")
	}
	// archive.enabled=true 但引擎无归档器 → not_requested
	if block.ArchiveStatus != archiveStatusNotRequested {
		t.Fatalf("expected archiveStatus not_requested (no archiver), got %q", block.ArchiveStatus)
	}
}

// 测试 APK 下载（GLOBAL-DOWNLOAD-002）
func TestBehavior_APKDownload(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	// APK 文件以 PK zip magic 开头
	apkBody := append([]byte{0x50, 0x4B, 0x03, 0x04}, bytes.Repeat([]byte{0x00}, 1024)...)

	tx := makeHTTPTransaction("GET", "/app.apk", 200, apkBody)
	tx.ResponseHeaders["content-type"] = "application/vnd.android.package-archive"
	tx.ResponseHeaders["content-length"] = itoa(len(apkBody))

	block := eng.analyzeHTTPTransaction(tx, "pcap-apk-001")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-002" {
		t.Fatalf("expected rule GLOBAL-DOWNLOAD-002, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "app_download" {
		t.Fatalf("expected urlType app_download, got %q", block.URLType)
	}
	if block.ArtifactKind != "app" {
		t.Fatalf("expected artifactKind app, got %q", block.ArtifactKind)
	}
	if block.DetectionScore < 50 {
		t.Fatalf("expected detectionScore >= 50, got %d", block.DetectionScore)
	}
}

// 测试 206+Range 分块下载（GLOBAL-DOWNLOAD-003）
func TestBehavior_OTAChunkDownload_206Range(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	chunkBody := bytes.Repeat([]byte{0xAA}, 512)

	tx := makeHTTPTransaction("GET", "/ota/firmware.bin", 206, chunkBody)
	tx.RequestHeaders["range"] = "bytes=0-511"
	tx.ResponseHeaders["content-range"] = "bytes 0-511/4096"
	tx.ResponseHeaders["content-length"] = itoa(len(chunkBody))

	block := eng.analyzeHTTPTransaction(tx, "pcap-ota-001")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-003" {
		t.Fatalf("expected rule GLOBAL-DOWNLOAD-003, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "ota_chunk_download" {
		t.Fatalf("expected urlType ota_chunk_download, got %q", block.URLType)
	}
	if block.BehaviorStage != "download" {
		t.Fatalf("expected stage download, got %q", block.BehaviorStage)
	}
	if block.DetectionScore < 50 {
		t.Fatalf("expected detectionScore >= 50, got %d", block.DetectionScore)
	}
}

// 测试 JSON 升级检查（GLOBAL-CHECK-002）
func TestBehavior_JSONUpgradeCheck(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	jsonBody := []byte(`{"version":"1.2.3","latest_version":"2.0.0","update_required":true,"firmware_url":"http://example.com/fw.bin"}`)

	tx := makeHTTPTransaction("GET", "/api/check-version", 200, jsonBody)
	tx.ResponseHeaders["content-type"] = "application/json"
	tx.ResponseHeaders["content-length"] = itoa(len(jsonBody))

	block := eng.analyzeHTTPTransaction(tx, "pcap-check-001")

	if block.BehaviorRuleID != "GLOBAL-CHECK-002" {
		t.Fatalf("expected rule GLOBAL-CHECK-002, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "upgrade_check" {
		t.Fatalf("expected urlType upgrade_check, got %q", block.URLType)
	}
	if block.BehaviorStage != "check" {
		t.Fatalf("expected stage check, got %q", block.BehaviorStage)
	}
	if block.ArtifactKind != "manifest" {
		t.Fatalf("expected artifactKind manifest, got %q", block.ArtifactKind)
	}
	// archive.enabled=false → not_requested
	if block.ArchiveStatus != archiveStatusNotRequested {
		t.Fatalf("expected archiveStatus not_requested, got %q", block.ArchiveStatus)
	}
}

// 测试 POST 状态上报（GLOBAL-STATUS-001）
func TestBehavior_PostStatus(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	requestBody := []byte(`{"status":"upgrading","progress":50,"device_id":"dev-001","firmware_version":"1.0"}`)

	tx := makeHTTPTransaction("POST", "/api/status/report", 200, nil)
	tx.RequestBody = requestBody
	tx.RequestHeaders["content-type"] = "application/json"
	tx.RequestHeaders["content-length"] = itoa(len(requestBody))
	// 响应为空正文，使 matcher 从请求体提取 JSON keys
	tx.ResponseHeaders["content-length"] = "0"

	block := eng.analyzeHTTPTransaction(tx, "pcap-status-001")

	if block.BehaviorRuleID != "GLOBAL-STATUS-001" {
		t.Fatalf("expected rule GLOBAL-STATUS-001, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "upgrade_status" {
		t.Fatalf("expected urlType upgrade_status, got %q", block.URLType)
	}
	if block.BehaviorStage != "status" {
		t.Fatalf("expected stage status, got %q", block.BehaviorStage)
	}
}

// 测试心跳上报（GLOBAL-HEARTBEAT-001）
func TestBehavior_Heartbeat(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	requestBody := []byte(`{"uptime":3600,"heartbeat":"ok","device_id":"dev-001","firmware_version":"1.0","status":"running"}`)

	tx := makeHTTPTransaction("POST", "/api/heartbeat", 200, nil)
	tx.RequestBody = requestBody
	tx.RequestHeaders["content-type"] = "application/json"
	tx.RequestHeaders["content-length"] = itoa(len(requestBody))
	tx.ResponseHeaders["content-length"] = "0"

	block := eng.analyzeHTTPTransaction(tx, "pcap-hb-001")

	if block.BehaviorRuleID != "GLOBAL-HEARTBEAT-001" {
		t.Fatalf("expected rule GLOBAL-HEARTBEAT-001, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "heartbeat" {
		t.Fatalf("expected urlType heartbeat, got %q", block.URLType)
	}
	if block.BehaviorStage != "heartbeat" {
		t.Fatalf("expected stage heartbeat, got %q", block.BehaviorStage)
	}
}

// 测试校验文件下载（GLOBAL-VERIFY-001）
func TestBehavior_ChecksumFile(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	checksumBody := []byte("a1b2c3d4e5f6  firmware.bin\n")

	tx := makeHTTPTransaction("GET", "/firmware.bin.sha256", 200, checksumBody)
	tx.ResponseHeaders["content-type"] = "text/plain"
	tx.ResponseHeaders["content-length"] = itoa(len(checksumBody))

	block := eng.analyzeHTTPTransaction(tx, "pcap-verify-001")

	if block.BehaviorRuleID != "GLOBAL-VERIFY-001" {
		t.Fatalf("expected rule GLOBAL-VERIFY-001, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "hash_check" {
		t.Fatalf("expected urlType hash_check, got %q", block.URLType)
	}
	if block.BehaviorStage != "verify" {
		t.Fatalf("expected stage verify, got %q", block.BehaviorStage)
	}
	if block.ArtifactKind != "checksum" {
		t.Fatalf("expected artifactKind checksum, got %q", block.ArtifactKind)
	}
}

// --- 压缩正文测试 ---

// 测试 gzip 压缩的固件下载
func TestBehavior_GzipFirmwareDownload(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	originalBody := bytes.Repeat([]byte{0xFF, 0xFE}, 1024)
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	gw.Write(originalBody)
	gw.Close()

	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, compressed.Bytes())
	tx.ResponseHeaders["content-type"] = "application/octet-stream"
	tx.ResponseHeaders["content-encoding"] = "gzip"
	tx.ResponseHeaders["content-length"] = itoa(compressed.Len())

	block := eng.analyzeHTTPTransaction(tx, "pcap-gzip-fw-001")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-001" {
		t.Fatalf("expected rule GLOBAL-DOWNLOAD-001 for gzip firmware, got %q", block.BehaviorRuleID)
	}
	// payload_sha256 应为解码后正文的 SHA256
	expectedSHA := sha256Hex(originalBody)
	if block.PayloadSHA256 != expectedSHA {
		t.Fatalf("payloadSHA256 mismatch: got %q, want %q", block.PayloadSHA256, expectedSHA)
	}
	if block.PayloadAnalysisMode != "full" {
		t.Fatalf("expected full analysis mode for gzip decode, got %q", block.PayloadAnalysisMode)
	}
}

// 测试 gzip 解码失败 → partial_payload
func TestBehavior_GzipDecodeFailure_PartialPayload(t *testing.T) {
	eng := newTestBehaviorEngine(t)

	// 提供截断的 gzip 数据
	originalBody := bytes.Repeat([]byte{0xFF}, 4096)
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	gw.Write(originalBody)
	gw.Close()
	truncated := compressed.Bytes()[:compressed.Len()/2]

	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, truncated)
	tx.ResponseHeaders["content-type"] = "application/octet-stream"
	tx.ResponseHeaders["content-encoding"] = "gzip"
	tx.ResponseHeaders["content-length"] = itoa(len(truncated))

	block := eng.analyzeHTTPTransaction(tx, "pcap-partial-001")

	// 解码失败时应标记 partial_payload，不得标记为 full
	if block.PayloadAnalysisMode != partialPayloadMode {
		t.Fatalf("expected partial_payload for truncated gzip, got %q", block.PayloadAnalysisMode)
	}
}

// --- TLS/DNS metadata_only 测试 ---

// 测试 HTTPS metadata_only（TLS SNI）
func TestBehavior_TLSMetadataOnly(t *testing.T) {
	eng := newTestBehaviorEngine(t)

	block := eng.analyzeSNIEvent("firmware-update.example.com", "firmware-update.example.com",
		"10.0.0.1", 443, "10.0.0.2", 8443)

	if block.BehaviorRuleID != "GLOBAL-CHECK-003" {
		t.Fatalf("expected rule GLOBAL-CHECK-003 for SNI, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "tls_sni" {
		t.Fatalf("expected urlType tls_sni, got %q", block.URLType)
	}
	// TLS 未解密流量只能输出 metadata_only
	if block.PayloadAnalysisMode != "metadata_only" {
		t.Fatalf("expected metadata_only for TLS, got %q", block.PayloadAnalysisMode)
	}
	if block.PayloadSHA256 != "" {
		t.Fatal("TLS metadata_only must not have payloadSHA256")
	}
	// SNI 事件不得伪造正文级命中
	if block.DetectionScore == 0 {
		t.Fatal("expected non-zero detection score for SNI match")
	}
}

// 测试 SNI 不匹配（无升级关键词）
func TestBehavior_SNI_NoMatch(t *testing.T) {
	eng := newTestBehaviorEngine(t)

	block := eng.analyzeSNIEvent("www.example.com", "www.example.com",
		"10.0.0.1", 443, "10.0.0.2", 8443)

	if block.BehaviorRuleID != "" {
		t.Fatalf("expected no rule match for non-upgrade SNI, got %q", block.BehaviorRuleID)
	}
	if block.PayloadAnalysisMode != "metadata_only" {
		t.Fatalf("expected metadata_only, got %q", block.PayloadAnalysisMode)
	}
}

// 测试 DNS 域名识别（GLOBAL-CHECK-004）
func TestBehavior_DNSIdentification(t *testing.T) {
	eng := newTestBehaviorEngine(t)

	block := eng.analyzeDNSEvent("upgrade.example.com", []string{"10.0.0.2"},
		"10.0.0.1", 53, "10.0.0.2", 53)

	if block.BehaviorRuleID != "GLOBAL-CHECK-004" {
		t.Fatalf("expected rule GLOBAL-CHECK-004 for DNS, got %q", block.BehaviorRuleID)
	}
	if block.URLType != "dns_domain" {
		t.Fatalf("expected urlType dns_domain, got %q", block.URLType)
	}
	if block.PayloadAnalysisMode != "metadata_only" {
		t.Fatalf("expected metadata_only for DNS, got %q", block.PayloadAnalysisMode)
	}
	if block.PayloadSHA256 != "" {
		t.Fatal("DNS metadata_only must not have payloadSHA256")
	}
}

// 测试 DNS 不匹配
func TestBehavior_DNS_NoMatch(t *testing.T) {
	eng := newTestBehaviorEngine(t)

	block := eng.analyzeDNSEvent("example.com", nil,
		"10.0.0.1", 53, "10.0.0.2", 53)

	if block.BehaviorRuleID != "" {
		t.Fatalf("expected no rule match for non-upgrade DNS, got %q", block.BehaviorRuleID)
	}
}

// --- 规则版本不一致测试 ---

func TestBehavior_RuleVersionMismatch(t *testing.T) {
	// 两个不同版本的规则 YAML 应产生不同的 rulesetSHA256
	yamlV1 := `version: "1.0.0"
rules:
- rule_id: TEST-001
  rule_version: "2026-07-12"
  url_type: firmware_download
  behavior_stage: download
  artifact_kind: firmware
  priority: 100
  score_threshold: 60
  hard_conditions:
  - dimension: source
    operator: equals
    values: [http_download]
  signals:
  - dimension: extension
    operator: suffix
    values: [".bin"]
    score: 80
    required: true
  archive:
    enabled: false
`

	yamlV2 := strings.Replace(yamlV1, "2026-07-12", "2026-07-13", 1)

	dir := t.TempDir()
	pathV1 := filepath.Join(dir, "rules_v1.yaml")
	pathV2 := filepath.Join(dir, "rules_v2.yaml")
	if err := os.WriteFile(pathV1, []byte(yamlV1), 0o600); err != nil {
		t.Fatalf("write v1: %v", err)
	}
	if err := os.WriteFile(pathV2, []byte(yamlV2), 0o600); err != nil {
		t.Fatalf("write v2: %v", err)
	}

	eng1, err := newBehaviorEngine(behaviorEngineConfig{RulesPath: pathV1})
	if err != nil {
		t.Fatalf("newBehaviorEngine v1: %v", err)
	}
	eng2, err := newBehaviorEngine(behaviorEngineConfig{RulesPath: pathV2})
	if err != nil {
		t.Fatalf("newBehaviorEngine v2: %v", err)
	}

	if eng1.rulesetSHA == eng2.rulesetSHA {
		t.Fatalf("expected different rulesetSHA for different rule versions: both=%q", eng1.rulesetSHA)
	}

	// 同一 YAML 多次加载应产生相同 SHA
	eng1Again, _ := newBehaviorEngine(behaviorEngineConfig{RulesPath: pathV1})
	if eng1.rulesetSHA != eng1Again.rulesetSHA {
		t.Fatalf("expected same rulesetSHA for same YAML: %q vs %q", eng1.rulesetSHA, eng1Again.rulesetSHA)
	}
}

// 测试空规则集拒绝启动
func TestBehavior_EmptyRulesetRefusesStartup(t *testing.T) {
	emptyYAML := `version: "1.0.0"
rules: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(emptyYAML), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := newBehaviorEngine(behaviorEngineConfig{RulesPath: path})
	if err == nil {
		t.Fatal("expected error for empty ruleset")
	}
	if !strings.Contains(err.Error(), "no rules") {
		t.Fatalf("expected 'no rules' in error, got: %v", err)
	}
}

// 测试规则路径为空拒绝启动
func TestBehavior_EmptyRulesPathRefusesStartup(t *testing.T) {
	_, err := newBehaviorEngine(behaviorEngineConfig{RulesPath: ""})
	if err == nil {
		t.Fatal("expected error for empty rules path")
	}
}

func TestBehaviorPolicyDisablesVendorRulesButKeepsGlobalRules(t *testing.T) {
	ruleSet, err := upgradebehavior.CompileRuntimeRuleSet("test", []upgradebehavior.BehaviorRule{
		{
			RuleID: "GLOBAL-DOWNLOAD", RuleVersion: "1", URLType: upgradebehavior.URLTypeFirmwareDownload,
			BehaviorStage: upgradebehavior.StageDownload, ArtifactKind: upgradebehavior.ArtifactFirmware, ScoreThreshold: 10,
			HardConditions: []upgradebehavior.HardCondition{{Dimension: upgradebehavior.DimSource, Operator: upgradebehavior.OpEquals, Values: []string{"http_download"}}},
			Signals:        []upgradebehavior.ScoreSignal{{Dimension: upgradebehavior.DimExtension, Operator: upgradebehavior.OpSuffix, Values: []string{".bin"}, Score: 10, Required: true}},
		},
		{
			RuleID: "V-TEST-CHECK", RuleVersion: "1", VendorID: "V-TEST", CoverageLevel: upgradebehavior.CoverageL1,
			URLType: upgradebehavior.URLTypeUpgradeCheck, BehaviorStage: upgradebehavior.StageCheck, ArtifactKind: upgradebehavior.ArtifactManifest, ScoreThreshold: 50,
			HardConditions: []upgradebehavior.HardCondition{{Dimension: upgradebehavior.DimSource, Operator: upgradebehavior.OpEquals, Values: []string{"http_request"}}},
			Signals:        []upgradebehavior.ScoreSignal{{Dimension: upgradebehavior.DimHost, Operator: upgradebehavior.OpSuffix, Values: []string{"test.example"}, Score: 50, Required: true}},
		},
	}, map[string]string{"test.example": "V-TEST"})
	if err != nil {
		t.Fatalf("CompileRuntimeRuleSet: %v", err)
	}
	eng := &behaviorEngine{matcher: upgradebehavior.NewRuntimeBehaviorMatcher(ruleSet), ruleSet: ruleSet, disabledVendors: make(map[string]struct{})}
	before := eng.matcher.Classify(upgradebehavior.EventMeta{Protocol: "http", Source: "http_request", Host: "api.test.example"})
	if before.BehaviorRuleID != "V-TEST-CHECK" {
		t.Fatalf("before policy = %#v", before)
	}
	count, disabled, err := eng.ApplyDisabledVendors([]string{"V-TEST"})
	if err != nil || count != 1 || len(disabled) != 1 {
		t.Fatalf("ApplyDisabledVendors = %d/%v/%v", count, disabled, err)
	}
	after := eng.matcher.Classify(upgradebehavior.EventMeta{Protocol: "http", Source: "http_request", Host: "api.test.example"})
	if after.BehaviorRuleID != "" {
		t.Fatalf("disabled vendor must not match: %#v", after)
	}
	if got := eng.matcher.Classify(upgradebehavior.EventMeta{Protocol: "http", Source: "http_download", Host: "api.test.example", URI: "/firmware.bin"}); got.BehaviorRuleID != "" {
		t.Fatalf("disabled vendor must not fall through to global rule: %#v", got)
	}
	global := eng.matcher.Classify(upgradebehavior.EventMeta{Protocol: "http", Source: "http_download", URI: "/firmware.bin"})
	if global.BehaviorRuleID != "GLOBAL-DOWNLOAD" {
		t.Fatalf("global rule must remain enabled: %#v", global)
	}
}

// --- Kafka 不含正文测试 ---

func TestBehavior_KafkaNoBody(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	firmwareBody := bytes.Repeat([]byte{0xFF}, 512)

	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, firmwareBody)
	tx.ResponseHeaders["content-type"] = "application/octet-stream"

	block := eng.analyzeHTTPTransaction(tx, "pcap-kafka-001")

	event := urlObservedEvent{
		EventType:    urlObservedEventType,
		EventVersion: eventVersion,
		TaskID:       "task-001",
		PcapID:       "pcap-kafka-001",
		UID:          "uid-kafka-001",
		Protocol:     "http",
		Source:       "http_download",
		Host:         "example.com",
		URI:          "/firmware.bin",
		Method:       "GET",
		StatusCode:   200,
		Behavior:     &block,
	}

	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	jsonStr := string(raw)

	// 禁止发送 requestBody、responseBody、decryptedBody、fileContent
	forbiddenFields := []string{"requestBody", "responseBody", "decryptedBody", "fileContent", "file_content"}
	for _, field := range forbiddenFields {
		if strings.Contains(jsonStr, field) {
			t.Fatalf("Kafka event JSON must not contain %q: %s", field, jsonStr)
		}
	}

	// 确认 behavior 块存在且包含关键字段
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	behaviorRaw, ok := parsed["behavior"]
	if !ok {
		t.Fatal("expected behavior field in JSON")
	}
	var behaviorMap map[string]json.RawMessage
	if err := json.Unmarshal(behaviorRaw, &behaviorMap); err != nil {
		t.Fatalf("unmarshal behavior: %v", err)
	}

	requiredFields := []string{
		"urlType", "behaviorStage", "artifactKind", "detectionScore",
		"behaviorRuleID", "payloadSHA256", "payloadAnalysisMode",
		"engineVersion", "rulesetSHA256", "archiveStatus",
	}
	for _, field := range requiredFields {
		if _, ok := behaviorMap[field]; !ok {
			t.Fatalf("behavior block missing field %q in JSON", field)
		}
	}

	// 确认 detectionEvidence 仅包含信号名，不包含匹配值
	if evidRaw, ok := behaviorMap["detectionEvidence"]; ok {
		var evidences []string
		if err := json.Unmarshal(evidRaw, &evidences); err != nil {
			t.Fatalf("unmarshal detectionEvidence: %v", err)
		}
		// detectionEvidence 应为字符串数组（信号名），不是对象数组
		for _, e := range evidences {
			if strings.Contains(e, "matched") || strings.Contains(e, "value") {
				t.Fatalf("detectionEvidence should only contain signal names, got %q", e)
			}
		}
	}
}

// --- 归档集成测试 ---

// 测试归档成功
func TestBehavior_ArchiveSuccess(t *testing.T) {
	eng, dir := newTestBehaviorEngineWithArchiver(t)

	firmwareBody := bytes.Repeat([]byte{0xFF, 0xFE}, 2048)
	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, firmwareBody)
	tx.ResponseHeaders["content-type"] = "application/octet-stream"
	tx.UID = "uid-archive-001"

	block := eng.analyzeHTTPTransaction(tx, "pcap-archive-001")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-001" {
		t.Fatalf("expected GLOBAL-DOWNLOAD-001, got %q", block.BehaviorRuleID)
	}
	// GLOBAL-DOWNLOAD-001 archive.enabled=true → 应归档
	if block.ArchiveStatus != archiveStatusArchived {
		t.Fatalf("expected archiveStatus archived, got %q", block.ArchiveStatus)
	}
	if block.PayloadArchiveRef == "" {
		t.Fatal("expected non-empty payloadArchiveRef")
	}

	// 验证归档对象文件存在
	manifestPath := filepath.Join(dir, block.PayloadArchiveRef+".manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest should exist: %v", err)
	}
}

// 测试加密不可用时归档失败
func TestBehavior_ArchiveEncryptionUnavailable(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	dir := t.TempDir()
	// 构造无密钥的归档器
	archiver, err := newPayloadArchiver(dir, "", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}
	eng.archiver = archiver

	firmwareBody := bytes.Repeat([]byte{0xFF}, 1024)
	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, firmwareBody)
	tx.ResponseHeaders["content-type"] = "application/octet-stream"
	tx.UID = "uid-noenc-002"

	block := eng.analyzeHTTPTransaction(tx, "pcap-noenc-002")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-001" {
		t.Fatalf("expected GLOBAL-DOWNLOAD-001, got %q", block.BehaviorRuleID)
	}
	// 加密不可用 → failed，禁止明文回退
	if block.ArchiveStatus != archiveStatusFailed {
		t.Fatalf("expected archiveStatus failed, got %q", block.ArchiveStatus)
	}
	if block.PayloadArchiveRef != "" {
		t.Fatal("expected empty payloadArchiveRef on archive failure")
	}

	// 验证无 .bin.enc 文件
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bin.enc") {
			t.Fatalf("found .bin.enc file — plaintext fallback should not occur")
		}
	}
}

// 测试同一事务重放不重复产生 archive ref
func TestBehavior_ArchiveReplayNoDuplicate(t *testing.T) {
	eng, dir := newTestBehaviorEngineWithArchiver(t)

	firmwareBody := bytes.Repeat([]byte{0xBB}, 1024)
	tx := makeHTTPTransaction("GET", "/firmware.bin", 200, firmwareBody)
	tx.ResponseHeaders["content-type"] = "application/octet-stream"
	tx.UID = "uid-replay-001"

	block1 := eng.analyzeHTTPTransaction(tx, "pcap-replay-001")
	if block1.ArchiveStatus != archiveStatusArchived {
		t.Fatalf("expected first archive status=archived, got %q", block1.ArchiveStatus)
	}

	// 同一事务重放
	block2 := eng.analyzeHTTPTransaction(tx, "pcap-replay-001")
	if block2.ArchiveStatus != archiveStatusArchived {
		t.Fatalf("expected second archive status=archived, got %q", block2.ArchiveStatus)
	}
	if block1.PayloadArchiveRef != block2.PayloadArchiveRef {
		t.Fatalf("expected same archive ref on replay: %q vs %q",
			block1.PayloadArchiveRef, block2.PayloadArchiveRef)
	}

	// 确保只有一个 .bin.enc 文件
	encCount := 0
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bin.enc") {
			encCount++
		}
	}
	if encCount != 1 {
		t.Fatalf("expected exactly 1 .bin.enc file, got %d", encCount)
	}
}

// --- gzip/deflate/br 内容解码集成测试 ---

func TestBehavior_DeflateUpgradeCheck(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	originalJSON := []byte(`{"version":"1.0.0","update_required":true,"firmware_url":"http://example.com/fw.bin"}`)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	zw.Write(originalJSON)
	zw.Close()

	tx := makeHTTPTransaction("GET", "/api/check-version", 200, compressed.Bytes())
	tx.ResponseHeaders["content-type"] = "application/json"
	tx.ResponseHeaders["content-encoding"] = "deflate"
	tx.ResponseHeaders["content-length"] = itoa(compressed.Len())

	block := eng.analyzeHTTPTransaction(tx, "pcap-deflate-001")

	if block.BehaviorRuleID != "GLOBAL-CHECK-002" {
		t.Fatalf("expected GLOBAL-CHECK-002 for deflate JSON, got %q", block.BehaviorRuleID)
	}
	if block.PayloadSHA256 != sha256Hex(originalJSON) {
		t.Fatalf("payloadSHA256 should match decoded JSON, got %q", block.PayloadSHA256)
	}
}

func TestBehavior_BrotliAPKDownload(t *testing.T) {
	eng := newTestBehaviorEngine(t)
	originalBody := append([]byte{0x50, 0x4B, 0x03, 0x04}, bytes.Repeat([]byte{0x00}, 1024)...)
	var compressed bytes.Buffer
	bw := brotli.NewWriterV2(&compressed, brotli.BestCompression)
	bw.Write(originalBody)
	bw.Close()

	tx := makeHTTPTransaction("GET", "/app.apk", 200, compressed.Bytes())
	tx.ResponseHeaders["content-type"] = "application/vnd.android.package-archive"
	tx.ResponseHeaders["content-encoding"] = "br"
	tx.ResponseHeaders["content-length"] = itoa(compressed.Len())

	block := eng.analyzeHTTPTransaction(tx, "pcap-br-001")

	if block.BehaviorRuleID != "GLOBAL-DOWNLOAD-002" {
		t.Fatalf("expected GLOBAL-DOWNLOAD-002 for brotli APK, got %q", block.BehaviorRuleID)
	}
	if block.PayloadSHA256 != sha256Hex(originalBody) {
		t.Fatalf("payloadSHA256 should match decoded body, got %q", block.PayloadSHA256)
	}
}

// --- 辅助函数 ---

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
