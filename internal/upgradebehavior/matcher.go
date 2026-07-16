package upgradebehavior

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"sync"
)

// defaultMaxBodyBytes 限制请求/响应体缓冲上限，避免将完整载荷加载到内存。
// 设为 4 MiB 以支持固件/APK 下载场景的 magic 检测和 JSON key 提取；
// 超过此上限的载荷部分被丢弃，并标记为 partial_payload。
const defaultMaxBodyBytes = 4 * 1024 * 1024

// Session 单次匹配会话的流式状态。每条 HTTP/TLS/DNS 流独享一个 Session，
// 因此 Feed/Finish 方法无需加锁，可安全地在单流内顺序调用。
type Session struct {
	meta            EventMeta
	ruleSet         *RuleSet            // 创建时捕获的规则集（不可变）
	vendorIndex     *VendorDomainIndex  // 创建时捕获的厂商索引
	disabledVendors map[string]struct{} // 创建时捕获的厂商启停策略
	reqBuf          *bytes.Buffer       // 请求体缓冲（限制大小）
	respBuf         *bytes.Buffer       // 响应体缓冲（限制大小）
	sha256          hash.Hash           // 增量 SHA256
	jsonKeys        map[string]bool     // 提取到的 JSON keys
	magicDetected   string              // 检测到的文件 magic
	hasBody         bool                // 是否已馈送过正文
	maxBodyBytes    int                 // 缓冲上限
	partialPayload  bool                // 载荷是否不完整（TCP缺段/乱序/重传/超过上限）
	partialReason   string              // 载荷不完整的原因
}

// BehaviorMatcher 无状态行为匹配器。
// ruleSet 创建后不可变；vendorIndex 可通过 UpdateVendorIndex 异步替换。
// 所有分类状态由调用方持有的 Session 管理，匹配器本身可安全并发调用。
type BehaviorMatcher struct {
	ruleSet         *RuleSet
	vendorIndex     *VendorDomainIndex
	disabledVendors map[string]struct{}
	maxBodyBytes    int
	mu              sync.RWMutex // 保护 vendorIndex 的并发读写
}

// NewBehaviorMatcher 创建匹配器。
// ruleSet 为 nil 时自动加载编译期内置的默认规则集，确保匹配器永不为空。
// vendorIndex 为 nil 时初始化为空索引（仅使用全局规则）。
func NewBehaviorMatcher(ruleSet *RuleSet, vendorIndex *VendorDomainIndex) *BehaviorMatcher {
	if ruleSet == nil {
		ruleSet = LoadEmbeddedRuleSet()
	}
	if vendorIndex == nil {
		vendorIndex = NewVendorDomainIndex(nil)
	}
	return &BehaviorMatcher{
		ruleSet:         ruleSet,
		vendorIndex:     vendorIndex,
		disabledVendors: make(map[string]struct{}),
		maxBodyBytes:    defaultMaxBodyBytes,
	}
}

// NewRuntimeBehaviorMatcher 使用运行时规则产物内的厂商域名索引创建匹配器。
// 运行时产物是自包含 YAML，可由部署侧生成或直接维护。
func NewRuntimeBehaviorMatcher(ruleSet *RuleSet) *BehaviorMatcher {
	if ruleSet == nil {
		ruleSet = LoadEmbeddedRuleSet()
	}
	return NewBehaviorMatcher(ruleSet, NewVendorDomainIndex(ruleSet.VendorDomains))
}

// NewSession 为单条流创建独立会话。捕获当前 ruleSet 和 vendorIndex 快照，
// 后续 Feed/Finish 无需加锁，可安全地在单流内顺序调用。
func (m *BehaviorMatcher) NewSession(meta EventMeta) *Session {
	m.mu.RLock()
	vendorIdx := m.vendorIndex
	rs := m.ruleSet
	disabled := m.disabledVendors
	m.mu.RUnlock()
	return &Session{
		meta:            meta,
		ruleSet:         rs,
		vendorIndex:     vendorIdx,
		disabledVendors: disabled,
		reqBuf:          bytes.NewBuffer(nil),
		respBuf:         bytes.NewBuffer(nil),
		sha256:          sha256.New(),
		jsonKeys:        make(map[string]bool),
		maxBodyBytes:    m.maxBodyBytes,
	}
}

// Classify 是线程安全的便捷方法，等价于 NewSession + Finish。
// 适用于无正文馈送的元数据分类场景（如离线 pcap 分析）。
func (m *BehaviorMatcher) Classify(meta EventMeta) ClassificationResult {
	return m.NewSession(meta).Finish()
}

// UpdateVendorIndex 原子替换厂商域名索引，支持启动后异步加载厂商规则。
// 并发安全：与新创建的 Session 互不干扰（Session 在创建时捕获快照）。
func (m *BehaviorMatcher) UpdateVendorIndex(idx *VendorDomainIndex) {
	m.mu.Lock()
	m.vendorIndex = idx
	m.mu.Unlock()
}

// UpdateRuleSet 原子替换规则集，支持启动后异步加载厂商规则。
// 并发安全：与新创建的 Session 互不干扰（Session 在创建时捕获快照）。
func (m *BehaviorMatcher) UpdateRuleSet(ruleSet *RuleSet) {
	if ruleSet == nil {
		return
	}
	m.mu.Lock()
	m.ruleSet = ruleSet
	m.mu.Unlock()
}

// UpdateDisabledVendors 原子替换厂商启停策略。禁用厂商会在规则评分前被拒绝，
// 因而不会被全局规则绕过；已创建的 Session 保持创建时的策略快照。
func (m *BehaviorMatcher) UpdateDisabledVendors(vendorIDs []string) {
	disabled := make(map[string]struct{}, len(vendorIDs))
	for _, vendorID := range vendorIDs {
		if vendorID != "" {
			disabled[vendorID] = struct{}{}
		}
	}
	m.mu.Lock()
	m.disabledVendors = disabled
	m.mu.Unlock()
}

// WithMaxBodyBytes 设置正文缓冲上限，返回匹配器自身以支持链式调用。
func (m *BehaviorMatcher) WithMaxBodyBytes(n int) *BehaviorMatcher {
	if n > 0 {
		m.maxBodyBytes = n
	}
	return m
}

// Feed 馈送流式数据块。方向决定写入请求缓冲还是响应缓冲。
// SHA256 始终增量更新；正文缓冲在 maxBodyBytes 上限内追加。
// 超过缓冲上限时标记为 partial_payload。
func (s *Session) Feed(direction Direction, chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	// SHA256 始终更新，不受缓冲上限影响
	s.sha256.Write(chunk)
	s.hasBody = true

	var buf *bytes.Buffer
	if direction == DirRequest {
		buf = s.reqBuf
	} else {
		buf = s.respBuf
	}
	// 缓冲在上限内追加，超出部分丢弃（仅影响正文级信号，不影响哈希）
	if buf.Len() < s.maxBodyBytes {
		remaining := s.maxBodyBytes - buf.Len()
		if len(chunk) <= remaining {
			buf.Write(chunk)
		} else {
			buf.Write(chunk[:remaining])
			// 超过缓冲上限，标记为 partial_payload
			s.markPartialPayload("body exceeded max buffer size")
		}
	} else {
		// 缓冲已满，后续数据全部丢弃
		s.markPartialPayload("body exceeded max buffer size")
	}

	// magic 仅从首个响应块检测
	if direction == DirResponse && s.magicDetected == "" && len(chunk) > 0 {
		s.magicDetected = detectMagic(chunk)
	}
}

// MarkPartialPayload 标记载荷为不完整。供外部调用方在检测到 TCP 缺段、
// 乱序、重传或不支持的 PCAP 格式时调用。多次调用会记录第一个原因。
func (s *Session) MarkPartialPayload(reason string) {
	s.markPartialPayload(reason)
}

// markPartialPayload 内部实现，标记载荷不完整并记录原因。
// 已标记时保留第一个原因（通常是根本原因）。
func (s *Session) markPartialPayload(reason string) {
	s.partialPayload = true
	if s.partialReason == "" {
		s.partialReason = reason
	}
}

// Finish 执行最终分类：硬条件门控 → 评分 → 选最优规则 → 返回结果。
// 调用后 Session 仍保留，可读取结果中的证据。
func (s *Session) Finish() ClassificationResult {
	// 计算最终 SHA256
	payloadSHA256 := ""
	if s.hasBody {
		payloadSHA256 = hex.EncodeToString(s.sha256.Sum(nil))
	}

	// 判定分析模式：无正文则为 metadata_only
	metadataOnly := !s.hasBody

	// 提取 JSON 顶层 keys（从响应或请求缓冲）
	if !metadataOnly {
		s.jsonKeys = extractJSONKeysFromBody(s)
	}

	source := strings.ToLower(s.meta.Source)

	// 获取候选规则
	var candidates []*BehaviorRule
	if s.ruleSet != nil && s.ruleSet.compiled != nil {
		candidates = s.ruleSet.compiled.Candidates(s.meta)
	}

	// 厂商检测
	vendorID := ""
	if s.vendorIndex != nil {
		vendorID = s.vendorIndex.Match(s.meta.SNI, s.meta.DNSQuery, s.meta.Host)
	}
	if vendorID != "" {
		if _, disabled := s.disabledVendors[vendorID]; disabled {
			return buildResult(s, nil, 0, nil, payloadSHA256, metadataOnly)
		}
	}

	// 评估候选规则
	var bestRule *BehaviorRule
	var bestScore int
	var bestEvidence []Evidence
	var bestRequiredHits int

	for _, rule := range candidates {
		// 硬条件门控
		if !matchHardConditions(rule.HardConditions, s.meta) {
			continue
		}
		// 厂商专属规则需匹配检测到的厂商
		if rule.VendorID != "" && rule.VendorID != vendorID {
			continue
		}

		score, evidence, requiredHits, allRequiredHit, denied := evaluateSignals(
			rule.Signals, s, payloadSHA256, metadataOnly,
		)
		if denied {
			continue
		}
		if !allRequiredHit {
			continue
		}
		if score < rule.ScoreThreshold {
			continue
		}

		if isBetterCandidate(rule, score, requiredHits, bestRule, bestScore, bestRequiredHits) {
			bestRule = rule
			bestScore = score
			bestEvidence = evidence
			bestRequiredHits = requiredHits
		}
	}

	// 构建结果
	result := buildResult(s, bestRule, bestScore, bestEvidence, payloadSHA256, metadataOnly)
	// 载荷不完整时覆盖分析模式：partial_payload 优先级高于 full
	// metadataOnly 仍然优先（无正文时不讨论完整性）
	if s.partialPayload && !metadataOnly {
		result.PayloadAnalysisMode = AnalysisModePartialPayload
	}

	// 无规则匹配时，按数据源回退 URLType
	if bestRule == nil {
		switch source {
		case "tls_sni":
			result.URLType = URLTypeTLSSNI
		case "dns_query":
			result.URLType = URLTypeDNSDomain
		}
	}

	return result
}

// extractJSONKeysFromBody 从响应或请求缓冲中提取 JSON 顶层 keys。
func extractJSONKeysFromBody(s *Session) map[string]bool {
	if s.respBuf.Len() > 0 {
		return extractJSONKeys(s.respBuf.Bytes())
	}
	if s.reqBuf.Len() > 0 {
		return extractJSONKeys(s.reqBuf.Bytes())
	}
	return make(map[string]bool)
}

// matchHardConditions 检查所有硬条件是否全部满足。
func matchHardConditions(conditions []HardCondition, meta EventMeta) bool {
	for _, hc := range conditions {
		if !matchHardCondition(hc, meta) {
			return false
		}
	}
	return true
}

// matchHardCondition 检查单个硬条件。
func matchHardCondition(hc HardCondition, meta EventMeta) bool {
	switch hc.Dimension {
	case DimProtocol:
		return matchValuesIgnoreCase(hc.Values, meta.Protocol)
	case DimSource:
		return matchValuesIgnoreCase(hc.Values, meta.Source)
	case DimMethod:
		return matchValuesIgnoreCase(hc.Values, meta.Method)
	case DimStatusCode:
		target := strconv.Itoa(meta.StatusCode)
		for _, v := range hc.Values {
			if target == strings.TrimSpace(v) {
				return true
			}
		}
		return false
	case DimPort:
		for _, v := range hc.Values {
			if port, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				if meta.SrcPort == port || meta.DstPort == port {
					return true
				}
			}
		}
		return false
	case DimDirection:
		source := strings.ToLower(meta.Source)
		for _, v := range hc.Values {
			dv := strings.ToLower(strings.TrimSpace(v))
			if dv == "request" && source == "http_request" {
				return true
			}
			if dv == "response" && (source == "http_response_body" || source == "http_download") {
				return true
			}
		}
		return false
	}
	return true
}

// matchValuesIgnoreCase 判断目标值是否匹配任一候选值（大小写不敏感）。
func matchValuesIgnoreCase(values []string, target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	for _, v := range values {
		if lower == strings.ToLower(strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

// evaluateSignals 评估规则的所有评分信号。
// 返回：总分、命中证据、必需信号命中数、是否所有必需信号均命中、是否被 deny 信号排除。
func evaluateSignals(signals []ScoreSignal, s *Session, payloadSHA256 string, metadataOnly bool) (int, []Evidence, int, bool, bool) {
	totalScore := 0
	var evidence []Evidence
	requiredHits := 0
	allRequiredHit := true

	// 先检查 deny 信号：任一命中则立即排除此规则
	for _, sig := range signals {
		if !sig.Deny {
			continue
		}
		// metadata_only 模式跳过依赖正文的 deny 信号
		if metadataOnly && bodyDependentDimensions[sig.Dimension] {
			continue
		}
		if hit, _, _ := evaluateSignal(sig, s, payloadSHA256); hit {
			return 0, nil, 0, false, true
		}
	}

	for _, sig := range signals {
		if sig.Deny {
			continue
		}
		// metadata_only 模式跳过依赖正文的信号
		if metadataOnly && bodyDependentDimensions[sig.Dimension] {
			if sig.Required {
				allRequiredHit = false
			}
			continue
		}

		hit, matched, score := evaluateSignal(sig, s, payloadSHA256)
		if hit {
			totalScore += score
			if sig.Required {
				requiredHits++
			}
			evidence = append(evidence, Evidence{
				Signal:   sig.Dimension,
				Matched:  matched,
				Score:    score,
				Required: sig.Required,
			})
		} else if sig.Required {
			allRequiredHit = false
		}
	}

	return totalScore, evidence, requiredHits, allRequiredHit, false
}

// evaluateSignal 评估单个评分信号，返回是否命中、匹配值、得分。
func evaluateSignal(sig ScoreSignal, s *Session, payloadSHA256 string) (bool, string, int) {
	switch sig.Dimension {
	case DimURI:
		return matchStringOperator(sig, strings.ToLower(s.meta.URI))
	case DimHost:
		return matchStringOperator(sig, strings.ToLower(s.meta.Host))
	case DimSNI:
		return matchStringOperator(sig, strings.ToLower(s.meta.SNI))
	case DimDNS:
		// DNS query 与每个 answer 分别匹配。不能拼接后做 suffix 匹配，
		// 否则 query 后的空格会使 "ui.com " 无法命中 "ui.com"。
		if ok, matched, score := matchStringOperator(sig, strings.ToLower(s.meta.DNSQuery)); ok {
			return ok, matched, score
		}
		for _, answer := range s.meta.DNSAnswers {
			if ok, matched, score := matchStringOperator(sig, strings.ToLower(answer)); ok {
				return ok, matched, score
			}
		}
		return false, "", 0
	case DimContentType:
		return matchStringOperator(sig, normalizeMIME(strings.ToLower(s.meta.ContentType)))
	case DimContentDisposition:
		return matchStringOperator(sig, strings.ToLower(s.meta.ContentDisposition))
	case DimExtension:
		return matchStringOperator(sig, extractExtension(s.meta))
	case DimRangeStatus:
		return matchRangeStatus(sig, s.meta)
	case DimJSONKeys:
		return matchSetOperator(sig, s.jsonKeys)
	case DimFileMagic:
		return matchMagic(sig, s.magicDetected)
	case DimBodyKeyword:
		return matchBodyKeyword(sig, s)
	case DimBodyRegex:
		return matchBodyRegex(sig, s)
	case DimFileHash:
		return matchFileHash(sig, payloadSHA256)
	}
	return false, "", 0
}

// matchStringOperator 对字符串维度执行操作符匹配。
func matchStringOperator(sig ScoreSignal, target string) (bool, string, int) {
	switch sig.Operator {
	case OpEquals:
		for _, v := range sig.Values {
			if target == strings.ToLower(v) {
				return true, truncate(v), sig.Score
			}
		}
	case OpPrefix:
		for _, v := range sig.Values {
			if strings.HasPrefix(target, strings.ToLower(v)) {
				return true, truncate(v), sig.Score
			}
		}
	case OpSuffix:
		for _, v := range sig.Values {
			if strings.HasSuffix(target, strings.ToLower(v)) {
				return true, truncate(v), sig.Score
			}
		}
	case OpContains:
		for _, v := range sig.Values {
			if strings.Contains(target, strings.ToLower(v)) {
				return true, truncate(v), sig.Score
			}
		}
	case OpRegex:
		if re := sig.compiledRe(); re != nil {
			if m := re.FindString(target); m != "" {
				return true, truncate(m), sig.Score
			}
		}
	case OpSetContains, OpJSONKey:
		for _, v := range sig.Values {
			if target == strings.ToLower(v) {
				return true, truncate(v), sig.Score
			}
		}
	}
	return false, "", 0
}

// matchSetOperator 对集合维度（json_keys、body_keyword）执行匹配。
func matchSetOperator(sig ScoreSignal, set map[string]bool) (bool, string, int) {
	if sig.Operator == OpMagic {
		return false, "", 0
	}
	for _, v := range sig.Values {
		k := strings.ToLower(strings.TrimSpace(v))
		if set[k] {
			return true, truncate(v), sig.Score
		}
	}
	return false, "", 0
}

// matchRangeStatus 检查 206 + Range 头部（OTA 分块下载）。
func matchRangeStatus(sig ScoreSignal, meta EventMeta) (bool, string, int) {
	hasRange := meta.StatusCode == 206
	if !hasRange {
		if v, ok := meta.Headers["range"]; ok && v != "" {
			hasRange = true
		}
		if v, ok := meta.Headers["content-range"]; ok && v != "" {
			hasRange = true
		}
	}
	if !hasRange {
		return false, "", 0
	}
	for _, v := range sig.Values {
		dv := strings.ToLower(strings.TrimSpace(v))
		if dv == "true" || dv == "206" {
			return true, "206+range", sig.Score
		}
	}
	// 无指定值时默认命中
	if len(sig.Values) == 0 {
		return true, "206+range", sig.Score
	}
	return false, "", 0
}

// matchMagic 检查文件 magic 是否匹配。
func matchMagic(sig ScoreSignal, detected string) (bool, string, int) {
	if detected == "" {
		return false, "", 0
	}
	for _, v := range sig.Values {
		if detected == strings.ToLower(strings.TrimSpace(v)) {
			return true, detected, sig.Score
		}
	}
	return false, "", 0
}

// matchBodyKeyword 在正文缓冲中扫描关键词。
func matchBodyKeyword(sig ScoreSignal, s *Session) (bool, string, int) {
	body := s.respBuf.Bytes()
	if len(body) == 0 {
		body = s.reqBuf.Bytes()
	}
	if len(body) == 0 {
		return false, "", 0
	}
	lower := strings.ToLower(string(body))
	for _, v := range sig.Values {
		k := strings.ToLower(strings.TrimSpace(v))
		if k == "" {
			continue
		}
		if strings.Contains(lower, k) {
			return true, truncate(k), sig.Score
		}
	}
	return false, "", 0
}

// matchBodyRegex 使用预编译正则在正文缓冲中查找匹配。
func matchBodyRegex(sig ScoreSignal, s *Session) (bool, string, int) {
	re := sig.compiledRe()
	if re == nil {
		return false, "", 0
	}
	body := s.respBuf.Bytes()
	if len(body) == 0 {
		body = s.reqBuf.Bytes()
	}
	if len(body) == 0 {
		return false, "", 0
	}
	if m := re.Find(body); m != nil {
		return true, truncate(string(m)), sig.Score
	}
	return false, "", 0
}

// matchFileHash 检查载荷 SHA256 是否匹配。
func matchFileHash(sig ScoreSignal, payloadSHA256 string) (bool, string, int) {
	if payloadSHA256 == "" {
		return false, "", 0
	}
	for _, v := range sig.Values {
		if strings.EqualFold(strings.TrimSpace(v), payloadSHA256) {
			return true, payloadSHA256, sig.Score
		}
	}
	return false, "", 0
}

// isBetterCandidate 规则优先级比较：
// 1. 厂商规则 > 全局规则
// 2. 分数最高
// 3. required 信号命中更多
// 4. priority 更高
// 5. rule_id 字典序（小者优先），保证可复现
func isBetterCandidate(rule *BehaviorRule, score, requiredHits int, best *BehaviorRule, bestScore, bestRequiredHits int) bool {
	if best == nil {
		return true
	}
	ruleIsVendor := rule.VendorID != ""
	bestIsVendor := best.VendorID != ""
	if ruleIsVendor != bestIsVendor {
		return ruleIsVendor
	}
	if score != bestScore {
		return score > bestScore
	}
	if requiredHits != bestRequiredHits {
		return requiredHits > bestRequiredHits
	}
	if rule.Priority != best.Priority {
		return rule.Priority > best.Priority
	}
	return rule.RuleID < best.RuleID
}

// buildResult 构建分类结果。
func buildResult(s *Session, rule *BehaviorRule, score int, evidence []Evidence, payloadSHA256 string, metadataOnly bool) ClassificationResult {
	result := ClassificationResult{
		PayloadSHA256:       payloadSHA256,
		DetectionEvidence:   evidence,
		PayloadAnalysisMode: AnalysisModeFull,
		MetadataOnly:        metadataOnly,
	}
	if metadataOnly {
		result.PayloadAnalysisMode = AnalysisModeMetadataOnly
	}

	if rule == nil {
		result.URLType = URLTypeUnknown
		result.ArtifactKind = ArtifactUnknown
		result.DetectionConfidence = ConfidenceLow
		return result
	}

	result.URLType = rule.URLType
	result.BehaviorStage = rule.BehaviorStage
	result.ArtifactKind = rule.ArtifactKind
	result.DetectionScore = score
	result.VendorID = rule.VendorID
	result.BehaviorRuleID = rule.RuleID
	result.BehaviorRuleVersion = rule.RuleVersion
	result.CoverageLevel = rule.CoverageLevel
	if result.CoverageLevel == "" {
		if rule.VendorID == "" {
			result.CoverageLevel = CoverageL2
		} else {
			result.CoverageLevel = CoverageL1
		}
	}
	result.IsCandidate = result.CoverageLevel == CoverageL1
	result.IsIoTUpgrade = true
	result.IsDownloadCandidate = isDownloadType(rule.URLType)
	result.IsExtractable = result.IsDownloadCandidate &&
		strings.ToLower(s.meta.Source) == "http_download" &&
		s.meta.ContentLength > 0
	if result.IsCandidate {
		// L1 只做候选发现，不得驱动自动提取、归档或后续处置。
		result.IsExtractable = false
	}

	// 规则启用归档时，传递保留天数给 Sink
	if rule.Archive.Enabled && !result.IsCandidate {
		result.ArchiveRetainDays = rule.Archive.RetainDays
		if result.ArchiveRetainDays <= 0 {
			result.ArchiveRetainDays = 30 // 默认保留 30 天
		}
	}

	// 置信度：metadata_only 始终 low；full 模式按分数/阈值比判定
	if result.IsCandidate || metadataOnly {
		result.DetectionConfidence = ConfidenceLow
	} else if score >= rule.ScoreThreshold*2 {
		result.DetectionConfidence = ConfidenceHigh
	} else {
		result.DetectionConfidence = ConfidenceMedium
	}

	return result
}

// isDownloadType 判断 URLType 是否为下载类。
func isDownloadType(urlType string) bool {
	switch urlType {
	case URLTypeFirmwareDownload, URLTypeAppDownload, URLTypeOTAChunk:
		return true
	}
	return false
}

// unknownResult 返回未分类结果。
func unknownResult() ClassificationResult {
	return ClassificationResult{
		URLType:             URLTypeUnknown,
		ArtifactKind:        ArtifactUnknown,
		DetectionConfidence: ConfidenceLow,
		PayloadAnalysisMode: AnalysisModeMetadataOnly,
		MetadataOnly:        true,
	}
}

// truncate 脱敏截断匹配值，避免证据中暴露过长内容。
func truncate(s string) string {
	const maxEvidenceLen = 128
	if len(s) > maxEvidenceLen {
		return s[:maxEvidenceLen] + "..."
	}
	return s
}

// normalizeMIME 规范化 MIME 类型：去除参数部分（; charset=utf-8 等），
// 仅保留主类型/子类型。例如 "application/json; charset=utf-8" → "application/json"。
func normalizeMIME(s string) string {
	if idx := strings.IndexByte(s, ';'); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}
