package upgradebehavior

import (
	"fmt"
	"regexp"
	"strings"
)

// Operator 受限操作符集合。规则加载时仅允许以下取值，正则在加载阶段预编译。
type Operator string

const (
	OpEquals      Operator = "equals"
	OpPrefix      Operator = "prefix"
	OpSuffix      Operator = "suffix"
	OpContains    Operator = "contains"
	OpRegex       Operator = "regex"
	OpSetContains Operator = "set_contains"
	OpMagic       Operator = "magic"
	OpJSONKey     Operator = "json_key"
)

// 硬条件维度名。
const (
	DimProtocol   = "protocol"
	DimSource     = "source"
	DimMethod     = "method"
	DimStatusCode = "status_code"
	DimPort       = "port"
	DimDirection  = "direction"
)

// 评分信号维度名。
const (
	DimURI                = "uri"
	DimHost               = "host"
	DimSNI                = "sni"
	DimDNS                = "dns"
	DimContentType        = "content_type"
	DimContentDisposition = "content_disposition"
	DimExtension          = "extension"
	DimRangeStatus        = "range_status"
	DimJSONKeys           = "json_keys"
	DimFileMagic          = "file_magic"
	DimBodyKeyword        = "body_keyword"
	DimBodyRegex          = "body_regex"
	DimFileHash           = "file_hash"
)

// bodyDependentDimensions 依赖正文的信号维度集合。metadata_only 模式下跳过这些维度。
var bodyDependentDimensions = map[string]bool{
	DimJSONKeys:    true,
	DimFileMagic:   true,
	DimBodyKeyword: true,
	DimBodyRegex:   true,
	DimFileHash:    true,
}

// HardCondition 硬条件，不满足则不进入规则评分。
type HardCondition struct {
	Dimension string   `yaml:"dimension"` // protocol/source/method/status_code/port/direction
	Operator  Operator `yaml:"operator"`
	Values    []string `yaml:"values,omitempty"`
}

// ScoreSignal 评分信号。
type ScoreSignal struct {
	Dimension string   `yaml:"dimension"` // 见 Dim* 常量
	Operator  Operator `yaml:"operator"`
	Values    []string `yaml:"values,omitempty"`
	Regex     string   `yaml:"regex,omitempty"` // 仅 OpRegex 时使用，加载时预编译
	Score     int      `yaml:"score"`
	Required  bool     `yaml:"required,omitempty"`
	Deny      bool     `yaml:"deny,omitempty"` // 命中则立即排除此规则（否定条件）
	// compiledRegex 预编译正则，仅 OpRegex 时非空。
	compiledRegex *regexp.Regexp
}

// ArchivePolicy 归档策略。
type ArchivePolicy struct {
	Enabled    bool `yaml:"enabled"`
	RetainDays int  `yaml:"retain_days,omitempty"`
}

// BehaviorRule 行为规则。
type BehaviorRule struct {
	RuleID         string `yaml:"rule_id"`
	RuleVersion    string `yaml:"rule_version"`
	URLType        string `yaml:"url_type"`
	BehaviorStage  string `yaml:"behavior_stage"`
	ArtifactKind   string `yaml:"artifact_kind"`
	Priority       int    `yaml:"priority"`
	ScoreThreshold int    `yaml:"score_threshold"`
	VendorID       string `yaml:"vendor_id,omitempty"` // 空=全局规则
	// CoverageLevel 表示规则证据等级：L1 仅候选发现，L2/L3 才可用于确认行为。
	// 全局规则未显式设置时按 L2 处理；厂商规则未显式设置时按 L1 处理。
	CoverageLevel  string          `yaml:"behavior_coverage,omitempty"`
	HardConditions []HardCondition `yaml:"hard_conditions"`
	Signals        []ScoreSignal   `yaml:"signals"`
	Archive        ArchivePolicy   `yaml:"archive,omitempty"`
	Description    string          `yaml:"description,omitempty"`
	Source         string          `yaml:"source,omitempty"` // 规则来源说明
}

// RuleSet 规则集，加载后不可变。
type RuleSet struct {
	Version       string            `yaml:"version"`
	Rules         []BehaviorRule    `yaml:"rules"`
	VendorDomains map[string]string `yaml:"vendor_domains,omitempty"`
	compiled      *CompiledIndex    // 编译后的索引
}

// validateOperator 校验操作符合法性。
func validateOperator(op Operator) error {
	switch op {
	case OpEquals, OpPrefix, OpSuffix, OpContains,
		OpRegex, OpSetContains, OpMagic, OpJSONKey:
		return nil
	default:
		return fmt.Errorf("unsupported operator %q", op)
	}
}

// compile 预编译单个信号的正则，返回编译后的信号副本。
func (s ScoreSignal) compile() (ScoreSignal, error) {
	if err := validateOperator(s.Operator); err != nil {
		return s, fmt.Errorf("signal dimension=%s: %w", s.Dimension, err)
	}
	if s.Operator == OpRegex {
		if strings.TrimSpace(s.Regex) == "" {
			return s, fmt.Errorf("signal dimension=%s operator=regex but regex is empty", s.Dimension)
		}
		re, err := regexp.Compile(s.Regex)
		if err != nil {
			return s, fmt.Errorf("signal dimension=%s regex %q: %w", s.Dimension, s.Regex, err)
		}
		s.compiledRegex = re
	}
	return s, nil
}

// compiledRe 返回预编译正则，调用前需确保已 compile。
func (s ScoreSignal) compiledRe() *regexp.Regexp {
	return s.compiledRegex
}
