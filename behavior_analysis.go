package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"zeek_runner/internal/upgradebehavior"
)

// behaviorBlock 是 Kafka url_observed 事件中的 behavior 扩展字段。
// 字段名保持稳定，确保下游消费侧可直接解析。
// 所有字段 optional，旧版消费者不会解析失败。
type behaviorBlock struct {
	URLType             string   `json:"urlType,omitempty"`
	IsIoTUpgrade        bool     `json:"isIoTUpgrade,omitempty"`
	IsDownloadCandidate bool     `json:"isDownloadCandidate,omitempty"`
	IsExtractable       bool     `json:"isExtractable,omitempty"`
	BehaviorStage       string   `json:"behaviorStage,omitempty"`
	ArtifactKind        string   `json:"artifactKind,omitempty"`
	DetectionScore      int      `json:"detectionScore,omitempty"`
	DetectionConfidence string   `json:"detectionConfidence,omitempty"`
	CoverageLevel       string   `json:"coverageLevel,omitempty"`
	IsCandidate         bool     `json:"isCandidate,omitempty"`
	VendorID            string   `json:"vendorID,omitempty"`
	BehaviorRuleID      string   `json:"behaviorRuleID,omitempty"`
	BehaviorRuleVersion string   `json:"behaviorRuleVersion,omitempty"`
	DetectionEvidence   []string `json:"detectionEvidence,omitempty"` // 仅脱敏信号名
	PayloadSHA256       string   `json:"payloadSHA256,omitempty"`
	PayloadAnalysisMode string   `json:"payloadAnalysisMode,omitempty"` // full / metadata_only / partial_payload
	EngineVersion       string   `json:"engineVersion,omitempty"`
	RulesetSHA256       string   `json:"rulesetSHA256,omitempty"`
	PayloadArchiveRef   string   `json:"payloadArchiveRef,omitempty"`
	ArchiveStatus       string   `json:"archiveStatus,omitempty"` // not_requested / archived / failed
}

// archive statuses
const (
	archiveStatusNotRequested = "not_requested"
	archiveStatusArchived     = "archived"
	archiveStatusFailed       = "failed"
)

// partialPayloadMode 表示内容解码失败或 TCP 重组不完整时的扩展模式。
// 当内容解码失败时使用，覆盖 matcher 返回的 full/metadata_only。
const partialPayloadMode = "partial_payload"

// analyzeHTTPTransaction 对单个 HTTP 事务执行行为识别。
// 返回 behaviorBlock（不含 requestBody、responseBody、解密正文或完整文件内容）。
func (eng *behaviorEngine) analyzeHTTPTransaction(tx httpTransaction, pcapID string) behaviorBlock {
	if eng == nil {
		return behaviorBlock{}
	}

	// 提取并规范化为小写 map 的请求/响应头
	reqHeaders := normalizeHTTPHeaders(tx.RequestHeaders)
	respHeaders := normalizeHTTPHeaders(tx.ResponseHeaders)

	// 内容解码：对 gzip、deflate、br 正文解压后执行内容识别
	// payload_sha256 定义为"HTTP 传输解码后、内容解码后的响应实体正文 SHA256"
	var decodedResponseBody []byte
	partialPayload := false
	encoding := ""
	if respHeaders != nil {
		encoding = respHeaders["content-encoding"]
	}
	if len(tx.ResponseBody) > 0 && encoding != "" {
		result := decodeHTTPContent(encoding, tx.ResponseBody)
		decodedResponseBody = result.Body
		if !result.Complete {
			// 无法解压时标记 payload_analysis_mode=partial_payload，不得标记为 full
			partialPayload = true
			slog.Debug("content decoding incomplete, marking partial_payload",
				"uid", tx.UID, "tx_seq", tx.TxSeq, "encoding", encoding, "err", result.Err)
		}
	} else {
		decodedResponseBody = tx.ResponseBody
	}

	// 构建 EventMeta
	contentType := ""
	contentDisposition := ""
	if respHeaders != nil {
		contentType = respHeaders["content-type"]
		contentDisposition = respHeaders["content-disposition"]
	}
	host := tx.Host
	if host == "" {
		host = reqHeaders["host"]
	}

	// 确定 source：二进制下载为 http_download，其余（JSON 检查、POST 状态/心跳/通知）为 http_request
	source := "http_request"
	if tx.Method == "GET" && (tx.StatusCode == 200 || tx.StatusCode == 206) {
		if isBinaryDownloadContent(contentType, tx.RequestURI) {
			source = "http_download"
		}
	}

	meta := upgradebehavior.EventMeta{
		Protocol:           "http",
		Source:             source,
		Method:             tx.Method,
		StatusCode:         tx.StatusCode,
		SrcIP:              tx.SrcIP,
		SrcPort:            tx.SrcPort,
		DstIP:              tx.DstIP,
		DstPort:            tx.DstPort,
		Host:               host,
		URI:                tx.RequestURI,
		FullURL:            makeFullURL(host, tx.RequestURI),
		Headers:            respHeaders,
		ContentType:        contentType,
		ContentDisposition: contentDisposition,
		Filename:           filenameFromURI(tx.RequestURI),
	}

	// 设置 ContentLength（使用解码后的长度）
	meta.ContentLength = int64(len(decodedResponseBody))

	// 创建独立 matcher session
	session := eng.matcher.NewSession(meta)
	if tx.PartialPayload {
		session.MarkPartialPayload(tx.PartialReason)
	}

	// Feed(DirRequest, requestBodyChunk) 与 Feed(DirResponse, decodedResponseBodyChunk) 按流顺序调用
	if len(tx.RequestBody) > 0 {
		session.Feed(upgradebehavior.DirRequest, tx.RequestBody)
	}
	if len(decodedResponseBody) > 0 {
		session.Feed(upgradebehavior.DirResponse, decodedResponseBody)
	}

	// Finish() 后输出完整 ClassificationResult
	result := session.Finish()

	// 覆盖 payload_analysis_mode：内容解码失败时标记为 partial_payload
	if partialPayload {
		result.PayloadAnalysisMode = partialPayloadMode
	}

	// 重新计算 payload_sha256：HTTP 传输解码后、内容解码后的响应实体正文 SHA256
	// matcher 内部的 SHA256 是 Feed 时增量计算的，与解码后正文一致。
	// 但当内容解码失败时，matcher 收到的是部分解码内容，SHA256 仍由 matcher 计算。
	// 为确保 payload_sha256 始终是"内容解码后的响应实体正文 SHA256"，在解码成功时重新计算。
	if len(decodedResponseBody) > 0 && result.PayloadSHA256 == "" {
		h := sha256.Sum256(decodedResponseBody)
		result.PayloadSHA256 = hex.EncodeToString(h[:])
	}

	// 构建行为块
	block := buildBehaviorBlock(result, eng)

	// 归档：仅当规则 archive.enabled=true 且行为成功分类后归档
	if result.BehaviorRuleID != "" && result.ArchiveRetainDays > 0 && eng.archiver != nil {
		eng.archivePayload(&block, result, tx, pcapID)
	} else {
		block.ArchiveStatus = archiveStatusNotRequested
	}

	return block
}

// analyzeSNIEvent 对 TLS SNI 事件执行行为识别（仅元数据，无正文）。
// TLS 未解密流量只能输出 metadata_only；SNI/DNS 事件不得伪造正文级命中。
func (eng *behaviorEngine) analyzeSNIEvent(sni, host, srcIP string, srcPort int, dstIP string, dstPort int) behaviorBlock {
	if eng == nil {
		return behaviorBlock{}
	}
	meta := upgradebehavior.EventMeta{
		Protocol: "https",
		Source:   "tls_sni",
		SNI:      sni,
		Host:     host,
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
	}
	result := eng.matcher.NewSession(meta).Finish()
	return buildBehaviorBlock(result, eng)
}

// analyzeDNSEvent 对 DNS 事件执行行为识别（仅元数据，无正文）。
func (eng *behaviorEngine) analyzeDNSEvent(query string, answers []string, srcIP string, srcPort int, dstIP string, dstPort int) behaviorBlock {
	if eng == nil {
		return behaviorBlock{}
	}
	meta := upgradebehavior.EventMeta{
		Protocol:   "dns",
		Source:     "dns_query",
		DNSQuery:   query,
		DNSAnswers: answers,
		Host:       query,
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		DstIP:      dstIP,
		DstPort:    dstPort,
	}
	result := eng.matcher.NewSession(meta).Finish()
	return buildBehaviorBlock(result, eng)
}

// buildBehaviorBlock 将 ClassificationResult 转换为 Kafka 行为块。
// 禁止将 requestBody、responseBody、解密正文或完整文件内容发送到 Kafka。
func buildBehaviorBlock(result upgradebehavior.ClassificationResult, eng *behaviorEngine) behaviorBlock {
	// detectionEvidence 仅脱敏信号名（不含匹配值）
	var evidenceSignals []string
	for _, e := range result.DetectionEvidence {
		evidenceSignals = append(evidenceSignals, e.Signal)
	}

	block := behaviorBlock{
		URLType:             result.URLType,
		IsIoTUpgrade:        result.IsIoTUpgrade,
		IsDownloadCandidate: result.IsDownloadCandidate,
		IsExtractable:       result.IsExtractable,
		BehaviorStage:       result.BehaviorStage,
		ArtifactKind:        result.ArtifactKind,
		DetectionScore:      result.DetectionScore,
		DetectionConfidence: result.DetectionConfidence,
		CoverageLevel:       result.CoverageLevel,
		IsCandidate:         result.IsCandidate,
		VendorID:            result.VendorID,
		BehaviorRuleID:      result.BehaviorRuleID,
		BehaviorRuleVersion: result.BehaviorRuleVersion,
		DetectionEvidence:   evidenceSignals,
		PayloadSHA256:       result.PayloadSHA256,
		PayloadAnalysisMode: result.PayloadAnalysisMode,
		EngineVersion:       eng.engineVer,
		RulesetSHA256:       eng.rulesetSHA,
		ArchiveStatus:       archiveStatusNotRequested,
	}

	// 如果未匹配到规则，仍输出 engine/ruleset 版本供消费侧校验
	if result.BehaviorRuleID == "" {
		block.URLType = result.URLType // 保留回退的 URLType（如 tls_sni/dns_domain）
	}

	return block
}

// archivePayload 执行命中载荷归档。
// 在本地写入命中原始载荷，使用流式加密；加密不可用时 archiveStatus=failed，禁止明文回退。
// archive ref 必须稳定且可追溯，至少关联 pcap_id、uid、事务序号、payload_sha256、规则 ID、创建时间和 30 天 expires_at。
func (eng *behaviorEngine) archivePayload(block *behaviorBlock, result upgradebehavior.ClassificationResult, tx httpTransaction, pcapID string) {
	if eng.archiver == nil {
		block.ArchiveStatus = archiveStatusNotRequested
		return
	}

	uid := tx.UID
	if uid == "" {
		uid = fmt.Sprintf("%s:%d-%s:%d", tx.SrcIP, tx.SrcPort, tx.DstIP, tx.DstPort)
	}

	ref := archiveRef{
		PcapID:        pcapID,
		UID:           uid,
		TxSeq:         tx.TxSeq,
		PayloadSHA256: result.PayloadSHA256,
		RuleID:        result.BehaviorRuleID,
	}

	// 命中原始载荷 = 传输解码后的响应正文（含内容编码）
	payload := tx.ResponseBody

	archived, err := eng.archiver.archive(ref, payload)
	if err != nil {
		slog.Warn("payload archive failed",
			"pcap_id", pcapID, "uid", uid, "tx_seq", tx.TxSeq,
			"rule_id", result.BehaviorRuleID, "err", err)
		block.ArchiveStatus = archiveStatusFailed
		return
	}

	block.PayloadArchiveRef = archived.RefID
	if archived.Status == "archived" {
		block.ArchiveStatus = archiveStatusArchived
	} else {
		block.ArchiveStatus = archiveStatusFailed
	}
}

// filenameFromURI 从 URI 中提取文件名。
func filenameFromURI(uri string) string {
	if uri == "" {
		return ""
	}
	path := parseURIPath(uri)
	if path == "" {
		return ""
	}
	// 取最后一段
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// isBinaryDownloadContent 判断是否为二进制下载内容（固件/APK/压缩包等）。
// 用于区分 http_download（二进制下载）与 http_request（JSON 检查、状态上报等）。
func isBinaryDownloadContent(contentType, uri string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/octet-stream", "application/x-firmware", "application/x-msdownload",
		"application/vnd.android.package-archive", "application/vnd.android.package":
		return true
	}
	path := strings.ToLower(parseURIPath(uri))
	for _, ext := range binaryDownloadExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// binaryDownloadExtensions 是被视为二进制下载的 URI 扩展名（与 GLOBAL-DOWNLOAD-001/002/003 一致）。
var binaryDownloadExtensions = []string{
	".bin", ".img", ".rom", ".fw", ".firmware", ".trx", ".chk", ".npk",
	".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".pkg", ".ipk",
	".upd", ".ota", ".upg", ".stk", ".pat", ".apk",
}
