package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testArchiveKeyHex 返回 32 字节（64 hex 字符）的测试密钥。
func testArchiveKeyHex() string {
	return strings.Repeat("ab", 32)
}

func TestArchive_Success(t *testing.T) {
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}
	if !archiver.encryptionAvailable() {
		t.Fatal("expected encryption to be available")
	}

	payload := []byte("firmware-binary-payload-" + strings.Repeat("X", 1024))
	ref := archiveRef{
		PcapID:        "pcap-001",
		UID:           "C192_168_1_10043192_168_1_20080",
		TxSeq:         1,
		PayloadSHA256: "abc123",
		RuleID:        "GLOBAL-DOWNLOAD-001",
	}

	result, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if result.Status != "archived" {
		t.Fatalf("expected status=archived, got %q", result.Status)
	}
	if result.RefID == "" {
		t.Fatal("expected non-empty refID")
	}
	if !result.Encrypted {
		t.Fatal("expected encrypted=true")
	}
	if result.ObjectSize == 0 {
		t.Fatal("expected non-zero object size")
	}
	if result.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero expires_at")
	}
	if time.Until(result.ExpiresAt) < 29*24*time.Hour {
		t.Fatalf("expires_at should be ~30 days in the future, got %v", result.ExpiresAt)
	}

	// 验证对象文件存在且以 magic 开头
	data, err := os.ReadFile(result.ObjectPath)
	if err != nil {
		t.Fatalf("read archive object: %v", err)
	}
	if !strings.HasPrefix(string(data), archiveMagic) {
		t.Fatal("archive object should start with magic header")
	}
}

func TestArchive_DecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}

	payload := []byte("round-trip-test-" + strings.Repeat("Y", 200*1024)) // 跨多个 chunk
	ref := archiveRef{
		PcapID:        "pcap-002",
		UID:           "uid-rt-001",
		TxSeq:         2,
		PayloadSHA256: "def456",
		RuleID:        "GLOBAL-DOWNLOAD-002",
	}

	result, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if result.Status != "archived" {
		t.Fatalf("expected status=archived, got %q", result.Status)
	}

	// 解密并验证内容一致
	decrypted, err := archiver.decryptArchive(result)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Fatalf("decrypt mismatch: got %d bytes, want %d", len(decrypted), len(payload))
	}
}

func TestArchive_EncryptionUnavailable_FailedNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	// 不传入密钥 → 加密不可用
	archiver, err := newPayloadArchiver(dir, "", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}
	if archiver.encryptionAvailable() {
		t.Fatal("expected encryption to be unavailable")
	}

	payload := []byte("should-not-be-archived-in-plaintext")
	ref := archiveRef{
		PcapID:        "pcap-003",
		UID:           "uid-noenc-001",
		TxSeq:         1,
		PayloadSHA256: "ghi789",
		RuleID:        "GLOBAL-DOWNLOAD-001",
	}

	result, err := archiver.archive(ref, payload)
	if err == nil {
		t.Fatal("expected error when encryption unavailable")
	}
	if result.Status != "failed" {
		t.Fatalf("expected status=failed, got %q", result.Status)
	}
	if result.Reason != "encryption_unavailable" {
		t.Fatalf("expected reason=encryption_unavailable, got %q", result.Reason)
	}

	// 禁止明文回退：不应存在 .bin.enc 对象文件
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bin.enc") {
			t.Fatalf("found encrypted object file %q — plaintext fallback should not occur", entry.Name())
		}
	}
}

func TestArchive_IdempotentRef_SameTransactionReplay(t *testing.T) {
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}

	payload := []byte("idempotent-test-payload")
	ref := archiveRef{
		PcapID:        "pcap-004",
		UID:           "uid-idem-001",
		TxSeq:         1,
		PayloadSHA256: "sha-idem-001",
		RuleID:        "GLOBAL-DOWNLOAD-001",
	}

	// 第一次归档
	first, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("first archive: %v", err)
	}
	if first.Status != "archived" {
		t.Fatalf("expected first status=archived, got %q", first.Status)
	}

	// 同一事务重放：不应重复产生 archive ref
	second, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("second archive (replay): %v", err)
	}
	if second.RefID != first.RefID {
		t.Fatalf("expected same RefID on replay: first=%q second=%q", first.RefID, second.RefID)
	}
	if second.Status != "archived" {
		t.Fatalf("expected second status=archived, got %q", second.Status)
	}
	if second.ObjectPath != first.ObjectPath {
		t.Fatalf("expected same ObjectPath on replay")
	}

	// 确保目录中只有一个 .bin.enc 文件
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

func TestArchive_ComputeRefID_StableAndTraceable(t *testing.T) {
	// 同一事务输入应产生相同 RefID
	refID1 := computeArchiveRefID("pcap-A", "uid-A", 1, "sha-A", "rule-A")
	refID2 := computeArchiveRefID("pcap-A", "uid-A", 1, "sha-A", "rule-A")
	if refID1 != refID2 {
		t.Fatalf("expected stable RefID: %q vs %q", refID1, refID2)
	}

	// 任一字段不同应产生不同 RefID
	refID3 := computeArchiveRefID("pcap-A", "uid-A", 2, "sha-A", "rule-A") // 不同 tx_seq
	if refID3 == refID1 {
		t.Fatal("expected different RefID for different tx_seq")
	}

	refID4 := computeArchiveRefID("pcap-A", "uid-A", 1, "sha-B", "rule-A") // 不同 sha
	if refID4 == refID1 {
		t.Fatal("expected different RefID for different payload_sha256")
	}

	refID5 := computeArchiveRefID("pcap-A", "uid-A", 1, "sha-A", "rule-B") // 不同 rule_id
	if refID5 == refID1 {
		t.Fatal("expected different RefID for different rule_id")
	}
}

func TestArchive_30DayExpiryCleanup(t *testing.T) {
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}

	// 归档一个载荷
	payload := []byte("expiry-test")
	ref := archiveRef{
		PcapID:        "pcap-expiry",
		UID:           "uid-expiry-001",
		TxSeq:         1,
		PayloadSHA256: "sha-expiry",
		RuleID:        "GLOBAL-DOWNLOAD-001",
	}
	archived, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	// 确认对象文件存在
	if _, err := os.Stat(archived.ObjectPath); err != nil {
		t.Fatalf("archive object should exist: %v", err)
	}
	manifestPath := archiver.manifestPath(archived.RefID)
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest should exist: %v", err)
	}

	// 模拟过期：将 now 设为 31 天后
	archiver.now = func() time.Time {
		return time.Now().Add(31 * 24 * time.Hour)
	}

	deleted, err := archiver.cleanupExpiredArchives()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}

	// 验证对象和 manifest 都已被删除
	if _, err := os.Stat(archived.ObjectPath); !os.IsNotExist(err) {
		t.Fatalf("expected object file to be deleted, got err=%v", err)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("expected manifest to be deleted, got err=%v", err)
	}
}

func TestArchive_CleanupKeepsNonExpired(t *testing.T) {
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}

	payload := []byte("not-yet-expired")
	ref := archiveRef{
		PcapID:        "pcap-keep",
		UID:           "uid-keep-001",
		TxSeq:         1,
		PayloadSHA256: "sha-keep",
		RuleID:        "GLOBAL-DOWNLOAD-001",
	}
	archived, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	// 未过期：不应删除
	deleted, err := archiver.cleanupExpiredArchives()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted, got %d", deleted)
	}
	if _, err := os.Stat(archived.ObjectPath); err != nil {
		t.Fatalf("object file should still exist: %v", err)
	}
}

func TestArchive_InvalidKeyHex(t *testing.T) {
	dir := t.TempDir()

	// 太短的密钥
	_, err := newPayloadArchiver(dir, "abcd", 30*24*time.Hour)
	if err == nil {
		t.Fatal("expected error for too-short key")
	}

	// 非 hex 字符串
	_, err = newPayloadArchiver(dir, "zz" + strings.Repeat("ab", 31), 30*24*time.Hour)
	if err == nil {
		t.Fatal("expected error for invalid hex key")
	}
}

func TestArchive_KeyID_Stable(t *testing.T) {
	key, _ := hex.DecodeString(testArchiveKeyHex())
	id1 := archiveKeyID(key)
	id2 := archiveKeyID(key)
	if id1 != id2 {
		t.Fatalf("expected stable key ID: %q vs %q", id1, id2)
	}
	if len(id1) != 16 {
		t.Fatalf("expected 16-char key ID, got %d", len(id1))
	}

	// 不同密钥应产生不同 key ID
	key2, _ := hex.DecodeString(strings.Repeat("cd", 32))
	id3 := archiveKeyID(key2)
	if id3 == id1 {
		t.Fatal("expected different key ID for different key")
	}
}

func TestArchive_FailedDeletionAuditLog(t *testing.T) {
	dir := t.TempDir()
	archiver, err := newPayloadArchiver(dir, testArchiveKeyHex(), 1*time.Hour)
	if err != nil {
		t.Fatalf("newPayloadArchiver: %v", err)
	}

	// 归档一个载荷（保留时间 1 小时）
	payload := []byte("audit-test")
	ref := archiveRef{
		PcapID:        "pcap-audit",
		UID:           "uid-audit-001",
		TxSeq:         1,
		PayloadSHA256: "sha-audit",
		RuleID:        "GLOBAL-DOWNLOAD-001",
	}
	archived, err := archiver.archive(ref, payload)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}

	// 手动删除对象文件，使 cleanup 时 manifest 存在但对象文件不存在
	os.Remove(archived.ObjectPath)

	// 模拟过期
	archiver.now = func() time.Time {
		return time.Now().Add(2 * time.Hour)
	}

	// cleanup 应处理 manifest（对象文件已不存在不算错误）
	deleted, _ := archiver.cleanupExpiredArchives()
	if deleted != 1 {
		t.Fatalf("expected 1 deleted (manifest only), got %d", deleted)
	}
	manifestPath := filepath.Join(dir, archived.RefID+".manifest.json")
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("manifest should be deleted: %v", err)
	}
}
