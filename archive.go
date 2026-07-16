package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	archiveMagic     = "ZEBE1\n"
	archiveChunkSize = 64 * 1024
	archiveKeySize   = 32 // AES-256
	archiveRetention = 30 * 24 * time.Hour
)

// archiveRef 描述一个已归档（或归档失败）的命中载荷引用。
// ref 必须稳定且可追溯，至少关联 pcap_id、uid、事务序号、payload_sha256、规则 ID、创建时间和 30 天 expires_at。
type archiveRef struct {
	RefID         string    `json:"refID"`
	PcapID        string    `json:"pcapID"`
	UID           string    `json:"uid"`
	TxSeq         int       `json:"txSeq"`
	PayloadSHA256 string    `json:"payloadSha256"`
	RuleID        string    `json:"ruleID"`
	CreatedAt     time.Time `json:"createdAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	ObjectPath    string    `json:"objectPath"`
	ObjectSize    int64     `json:"objectSize"`
	Encrypted     bool      `json:"encrypted"`
	KeyID         string    `json:"keyID"`
	Status        string    `json:"status"` // archived / failed
	Reason        string    `json:"reason,omitempty"`
}

// payloadArchiver 在本地（或可挂载的对象存储路径）写入流式加密的命中载荷。
// 加密不可用时 archiveStatus=failed，禁止明文回退。
type payloadArchiver struct {
	dir       string
	key       []byte // AES-256 key；为空则加密不可用
	keyID     string
	retention time.Duration
	now       func() time.Time
	mu        sync.Mutex
}

// newPayloadArchiver 构造归档器。encryptionKeyHex 为空或非法时加密不可用（归档将返回 failed）。
func newPayloadArchiver(dir, encryptionKeyHex string, retention time.Duration) (*payloadArchiver, error) {
	if dir == "" {
		return nil, errors.New("archive dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create archive dir: %w", err)
	}
	a := &payloadArchiver{
		dir:       dir,
		retention: retention,
		now:       time.Now,
	}
	if retention <= 0 {
		a.retention = archiveRetention
	}
	if encryptionKeyHex != "" {
		key, err := hex.DecodeString(strings.TrimSpace(encryptionKeyHex))
		if err != nil || len(key) != archiveKeySize {
			return nil, fmt.Errorf("invalid encryption key: expected %d-byte hex, got %d bytes", archiveKeySize, len(key))
		}
		a.key = key
		a.keyID = archiveKeyID(key)
	}
	return a, nil
}

// encryptionAvailable 返回加密是否可用。
func (a *payloadArchiver) encryptionAvailable() bool {
	return a != nil && len(a.key) == archiveKeySize
}

// archiveKeyID 派生自密钥的 HMAC，用于归档引用中追溯使用的密钥，而不泄露密钥本身。
func archiveKeyID(key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("zeek_runner.archive.keyid"))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// computeArchiveRefID 生成稳定且可追溯的归档引用 ID：
// 关联 pcap_id、uid、事务序号、payload_sha256、规则 ID。同一事务重放不重复产生 archive ref。
func computeArchiveRefID(pcapID, uid string, txSeq int, payloadSHA256, ruleID string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%s|%s", pcapID, uid, txSeq, payloadSHA256, ruleID)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// archive 将命中原始载荷以流式加密写入归档。
// 同一事务重放（相同 ref 输入）不重复产生 archive ref：若 manifest 已存在则直接返回。
// 加密不可用时返回 Status=failed 的引用，且不写入任何明文。
func (a *payloadArchiver) archive(ref archiveRef, payload []byte) (*archiveRef, error) {
	if a == nil {
		return nil, errors.New("archiver is nil")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	ref.RefID = computeArchiveRefID(ref.PcapID, ref.UID, ref.TxSeq, ref.PayloadSHA256, ref.RuleID)
	manifestPath := a.manifestPath(ref.RefID)

	// 幂等：同一事务重放不重复产生 archive ref。
	if existing, err := loadArchiveManifest(manifestPath); err == nil && existing != nil {
		return existing, nil
	}

	now := a.now()
	if ref.CreatedAt.IsZero() {
		ref.CreatedAt = now
	}
	ref.ExpiresAt = ref.CreatedAt.Add(a.retention)
	ref.Encrypted = a.encryptionAvailable()
	ref.KeyID = a.keyID

	if !a.encryptionAvailable() {
		// 加密不可用：禁止明文回退，仅记录 failed manifest 以便审计/重试。
		ref.Status = "failed"
		ref.Reason = "encryption_unavailable"
		_ = saveArchiveManifest(manifestPath, &ref)
		return &ref, errors.New("archive failed: encryption unavailable")
	}

	objectPath := a.objectPath(ref.RefID)
	objSize, err := a.encryptToPath(objectPath, payload)
	if err != nil {
		ref.Status = "failed"
		ref.Reason = "encrypt_failed: " + err.Error()
		_ = saveArchiveManifest(manifestPath, &ref)
		return &ref, fmt.Errorf("encrypt payload: %w", err)
	}

	ref.ObjectPath = objectPath
	ref.ObjectSize = objSize
	ref.Status = "archived"
	if err := saveArchiveManifest(manifestPath, &ref); err != nil {
		_ = os.Remove(objectPath)
		ref.Status = "failed"
		ref.Reason = "manifest_save_failed: " + err.Error()
		return &ref, fmt.Errorf("save manifest: %w", err)
	}
	return &ref, nil
}

// encryptToPath 以分块 AES-256-GCM 流式加密写入对象文件。
// 格式: archiveMagic | baseNonce(12) | { 4字节BE密文长度 | 密文+16字节tag }* | 0x00000000 终止标记
func (a *payloadArchiver) encryptToPath(path string, plaintext []byte) (int64, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}
	baseNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(baseNonce); err != nil {
		return 0, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	if _, err := bw.WriteString(archiveMagic); err != nil {
		return 0, err
	}
	if _, err := bw.Write(baseNonce); err != nil {
		return 0, err
	}

	var total int64
	chunkIndex := uint32(0)
	for offset := 0; offset < len(plaintext); offset += archiveChunkSize {
		end := offset + archiveChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[offset:end]
		nonce := archiveChunkNonce(baseNonce, chunkIndex)
		ct := gcm.Seal(nil, nonce, chunk, nil)
		if err := binary.Write(bw, binary.BigEndian, uint32(len(ct))); err != nil {
			return 0, err
		}
		if _, err := bw.Write(ct); err != nil {
			return 0, err
		}
		total += int64(len(ct))
		chunkIndex++
	}
	if err := binary.Write(bw, binary.BigEndian, uint32(0)); err != nil {
		return 0, err
	}
	return total, bw.Flush()
}

// archiveChunkNonce 由 baseNonce 与块序号派生，保证同一对象内每块 nonce 唯一。
func archiveChunkNonce(base []byte, index uint32) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)
	for i := 0; i < 4; i++ {
		b := byte(index >> (8 * (3 - i)))
		nonce[len(nonce)-4+i] ^= b
	}
	return nonce
}

// decryptArchive 读取归档对象并解密返回明文（用于自检/取证）。
func (a *payloadArchiver) decryptArchive(ref *archiveRef) ([]byte, error) {
	if a == nil || !a.encryptionAvailable() {
		return nil, errors.New("encryption unavailable")
	}
	data, err := os.ReadFile(ref.ObjectPath)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, []byte(archiveMagic)) {
		return nil, errors.New("bad archive magic")
	}
	body := data[len(archiveMagic):]
	if len(body) < 12 {
		return nil, errors.New("truncated archive: missing nonce")
	}
	baseNonce := body[:12]
	body = body[12:]

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	chunkIndex := uint32(0)
	for {
		if len(body) < 4 {
			return nil, errors.New("truncated archive: missing length")
		}
		ln := binary.BigEndian.Uint32(body[:4])
		body = body[4:]
		if ln == 0 {
			break
		}
		if int(ln) > len(body) {
			return nil, errors.New("truncated archive: chunk body")
		}
		ct := body[:ln]
		body = body[ln:]
		nonce := archiveChunkNonce(baseNonce, chunkIndex)
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", chunkIndex, err)
		}
		out.Write(pt)
		chunkIndex++
	}
	return out.Bytes(), nil
}

func (a *payloadArchiver) manifestPath(refID string) string {
	return filepath.Join(a.dir, refID+".manifest.json")
}
func (a *payloadArchiver) objectPath(refID string) string {
	return filepath.Join(a.dir, refID+".bin.enc")
}

func loadArchiveManifest(path string) (*archiveRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ref archiveRef
	if err := json.Unmarshal(data, &ref); err != nil {
		return nil, err
	}
	return &ref, nil
}

func saveArchiveManifest(path string, ref *archiveRef) error {
	data, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cleanupExpiredArchives 扫描归档目录，删除 expires_at 已过期的对象与 manifest。
// 删除失败时记录审计行到 failed_deletions.log 并返回错误以便上层重试。
func (a *payloadArchiver) cleanupExpiredArchives() (int, error) {
	if a == nil {
		return 0, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return 0, err
	}
	now := a.now()
	deleted := 0
	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".manifest.json") {
			continue
		}
		manifestPath := filepath.Join(a.dir, name)
		ref, err := loadArchiveManifest(manifestPath)
		if err != nil {
			a.auditDeleteFailure(name, "load_manifest_failed", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !now.After(ref.ExpiresAt) {
			continue
		}
		if ref.ObjectPath != "" {
			if err := os.Remove(ref.ObjectPath); err != nil && !os.IsNotExist(err) {
				a.auditDeleteFailure(name, "remove_object_failed", err)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
			a.auditDeleteFailure(name, "remove_manifest_failed", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		deleted++
	}
	return deleted, firstErr
}

func (a *payloadArchiver) auditDeleteFailure(manifestName, reason string, err error) {
	logPath := filepath.Join(a.dir, "failed_deletions.log")
	line := fmt.Sprintf("%s\t%s\t%s\t%v\n", a.now().Format(time.RFC3339), manifestName, reason, err)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("archive: failed to write delete audit", "reason", reason, "err", err)
		return
	}
	defer f.Close()
	_, _ = io.WriteString(f, line)
}
