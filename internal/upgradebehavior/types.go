// Package upgradebehavior 提供可复用的物联网升级行为识别能力。
//
// 本包为纯 Go 实现，仅依赖标准库与 gopkg.in/yaml.v3，可供离线 HTTP 解析
// 与外部 zeek_runner 采集侧共同调用。核心入口为 BehaviorMatcher，采用
// Begin/Feed/Finish 流式接口，避免将完整文件或正文加载到内存。
package upgradebehavior

// 行为阶段常量。
const (
	StageCheck     = "check"
	StageNotify    = "notify"
	StageDownload  = "download"
	StageVerify    = "verify"
	StageStatus    = "status"
	StageHeartbeat = "heartbeat"
)

// 制品类型常量。
const (
	ArtifactFirmware = "firmware"
	ArtifactApp      = "app"
	ArtifactManifest = "manifest"
	ArtifactChecksum = "checksum"
	ArtifactUnknown  = "unknown"
)

// 置信度常量。
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
	CoverageL1       = "L1"
	CoverageL2       = "L2"
	CoverageL3       = "L3"
)

// 载荷分析模式常量。
const (
	AnalysisModeFull           = "full"
	AnalysisModeMetadataOnly   = "metadata_only"
	AnalysisModePartialPayload = "partial_payload" // 载荷不完整：TCP缺段/乱序/重传/超过缓冲上限
)

// URLType 常量，兼容 internal/types.UpgradeURLInfo.URLType 的取值。
const (
	URLTypeUpgradeCheck     = "upgrade_check"
	URLTypeFirmwareDownload = "firmware_download"
	URLTypeAppDownload      = "app_download"
	URLTypeTLSSNI           = "tls_sni"
	URLTypeDNSDomain        = "dns_domain"
	URLTypeUnknown          = "unknown"
	URLTypeUpgradeStatus    = "upgrade_status"
	URLTypeUpgradeNotify    = "upgrade_notify"
	URLTypeOTAChunk         = "ota_chunk_download"
	URLTypeHashCheck        = "hash_check"
	URLTypeAppUpgrade       = "app_upgrade"
	URLTypeHeartbeat        = "heartbeat"
)

// Direction 表示流式数据方向。
type Direction int

const (
	// DirRequest 请求体。
	DirRequest Direction = iota
	// DirResponse 响应体。
	DirResponse
)

// EventMeta 事件元数据，在 Begin 时传入。包含协议、方法、状态码、头部、
// URI、文件信息、SNI/DNS、端口等连接级与请求级元数据。
type EventMeta struct {
	Protocol           string // http/https/mqtt/coap/ftp/tftp
	Source             string // http_request/http_response_body/http_download/tls_sni/dns_query
	Method             string // GET/POST/PUT
	StatusCode         int
	SrcIP              string
	DstIP              string
	SrcPort            int
	DstPort            int
	Host               string
	URI                string
	FullURL            string
	SNI                string
	DNSQuery           string
	DNSAnswers         []string
	Filename           string
	OrigFilename       string
	ContentType        string
	ContentDisposition string
	ContentLength      int64
	Headers            map[string]string // 关键头部
}

// Evidence 命中证据（脱敏），仅记录信号维度名、匹配值、分数与是否必需。
type Evidence struct {
	Signal   string // 信号维度名
	Matched  string // 匹配到的值（脱敏后）
	Score    int
	Required bool
}

// SignalHit 评分信号命中记录，用于内部评分过程。
type SignalHit struct {
	Dimension string
	Operator  Operator
	Matched   string
	Score     int
	Required  bool
}

// ClassificationResult 分类结果。
type ClassificationResult struct {
	URLType             string // 兼容现有 url_type
	BehaviorStage       string // check/notify/download/verify/status/heartbeat
	ArtifactKind        string // firmware/app/manifest/checksum/unknown
	DetectionScore      int
	DetectionConfidence string // high/medium/low
	CoverageLevel       string // L1/L2/L3；L1 仅候选发现
	IsCandidate         bool   // true 时不得作为已确认升级或自动处置依据
	// VendorID 是命中厂商行为规则的目录 ID。它用于消费侧回填厂商配置，
	// 不等同于业务配置 RuleID；全局规则为空。
	VendorID            string
	BehaviorRuleID      string
	BehaviorRuleVersion string
	DetectionEvidence   []Evidence
	PayloadSHA256       string
	PayloadArchiveRef   string
	PayloadAnalysisMode string // full/metadata_only
	IsIoTUpgrade        bool
	IsDownloadCandidate bool
	IsExtractable       bool
	MetadataOnly        bool // HTTPS 无正文时
	ArchiveRetainDays   int  // 规则启用归档时的保留天数（>0 表示需归档）
}
