package upgradebehavior

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed embedded_rules.yaml
var embeddedRulesYAML []byte

// LoadRuleSet 从 YAML 文件加载规则集，执行预编译、校验与索引构建。
// 加载失败即返回错误，不返回部分结果。
func LoadRuleSet(yamlPath string) (*RuleSet, error) {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("read ruleset %s: %w", yamlPath, err)
	}
	return LoadRuleSetFromBytes(data)
}

// LoadEmbeddedRuleSet 加载编译期内置的默认规则集。
// 用于外部 YAML 缺失或加载失败时的兜底，确保匹配器永不为空。
func LoadEmbeddedRuleSet() *RuleSet {
	rs, err := LoadRuleSetFromBytes(embeddedRulesYAML)
	if err != nil {
		// 内置规则集编译失败是编程错误，直接 panic
		panic(fmt.Sprintf("embedded ruleset is invalid: %v", err))
	}
	return rs
}

// LoadRuleSetFromBytes 从 YAML 字节流加载规则集。
// 流程：YAML 解析 → 校验 → 预编译正则 → 建立索引 → 返回不可变 RuleSet。
func LoadRuleSetFromBytes(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("unmarshal ruleset: %w", err)
	}
	if err := validateRuleSet(&rs); err != nil {
		return nil, err
	}
	idx, err := CompileIndex(rs.Rules)
	if err != nil {
		return nil, fmt.Errorf("compile index: %w", err)
	}
	rs.compiled = idx
	return &rs, nil
}

// validateRuleSet 校验规则集：版本、重复 rule_id、规则字段合法性。
func validateRuleSet(rs *RuleSet) error {
	if strings.TrimSpace(rs.Version) == "" {
		return fmt.Errorf("ruleset version is required")
	}
	if len(rs.Rules) == 0 {
		return fmt.Errorf("ruleset has no rules")
	}
	seenRuleIDs := make(map[string]struct{}, len(rs.Rules))
	for i := range rs.Rules {
		rule := &rs.Rules[i]
		if err := validateRule(rule); err != nil {
			return err
		}
		if _, exists := seenRuleIDs[rule.RuleID]; exists {
			return fmt.Errorf("duplicate rule_id %s", rule.RuleID)
		}
		seenRuleIDs[rule.RuleID] = struct{}{}
	}
	return nil
}

// CompileRuleSet 编译规则列表为 RuleSet（含索引），供外部调用方动态构建规则集。
// 与 LoadRuleSetFromBytes 不同，此函数不要求规则集版本字段，仅校验单条规则字段并构建索引。
func CompileRuleSet(rules []BehaviorRule) (*RuleSet, error) {
	rs := &RuleSet{Rules: rules}
	return compileRuleSet(rs)
}

// CompileRuntimeRuleSet 编译包含厂商域名索引的完整运行时规则集。
// 两个服务应加载同一 YAML 产物并基于其原始字节计算 SHA。
func CompileRuntimeRuleSet(version string, rules []BehaviorRule, vendorDomains map[string]string) (*RuleSet, error) {
	rs := &RuleSet{Version: version, Rules: rules, VendorDomains: vendorDomains}
	if err := validateRuleSet(rs); err != nil {
		return nil, err
	}
	return compileRuleSet(rs)
}

func compileRuleSet(rs *RuleSet) (*RuleSet, error) {
	compiled, err := CompileIndex(rs.Rules)
	if err != nil {
		return nil, err
	}
	rs.compiled = compiled
	return rs, nil
}

// validateRule 校验单条规则字段合法性。
func validateRule(rule *BehaviorRule) error {
	if strings.TrimSpace(rule.RuleID) == "" {
		return fmt.Errorf("rule_id is required")
	}
	if strings.TrimSpace(rule.URLType) == "" {
		return fmt.Errorf("%s url_type is required", rule.RuleID)
	}
	if strings.TrimSpace(rule.BehaviorStage) == "" {
		return fmt.Errorf("%s behavior_stage is required", rule.RuleID)
	}
	if !validBehaviorStage(rule.BehaviorStage) {
		return fmt.Errorf("%s invalid behavior_stage %q", rule.RuleID, rule.BehaviorStage)
	}
	if strings.TrimSpace(rule.ArtifactKind) == "" {
		rule.ArtifactKind = ArtifactUnknown
	}
	if !validArtifactKind(rule.ArtifactKind) {
		return fmt.Errorf("%s invalid artifact_kind %q", rule.RuleID, rule.ArtifactKind)
	}
	if rule.ScoreThreshold <= 0 {
		return fmt.Errorf("%s score_threshold must be > 0", rule.RuleID)
	}
	if rule.CoverageLevel != "" && rule.CoverageLevel != CoverageL1 && rule.CoverageLevel != CoverageL2 && rule.CoverageLevel != CoverageL3 {
		return fmt.Errorf("%s invalid behavior_coverage %q", rule.RuleID, rule.CoverageLevel)
	}
	// 校验硬条件维度合法性
	for _, hc := range rule.HardConditions {
		if !validHardConditionDimension(hc.Dimension) {
			return fmt.Errorf("%s invalid hard_condition dimension %q", rule.RuleID, hc.Dimension)
		}
		if len(hc.Values) == 0 {
			return fmt.Errorf("%s hard_condition dimension=%s requires values", rule.RuleID, hc.Dimension)
		}
	}
	// 校验信号维度与操作符合法性
	for _, sig := range rule.Signals {
		if !validSignalDimension(sig.Dimension) {
			return fmt.Errorf("%s invalid signal dimension %q", rule.RuleID, sig.Dimension)
		}
		if sig.Score < 0 {
			return fmt.Errorf("%s signal dimension=%s score must be >= 0", rule.RuleID, sig.Dimension)
		}
		if sig.Operator == OpRegex && strings.TrimSpace(sig.Regex) == "" {
			return fmt.Errorf("%s signal dimension=%s operator=regex requires regex field", rule.RuleID, sig.Dimension)
		}
		if sig.Operator != OpRegex && len(sig.Values) == 0 {
			return fmt.Errorf("%s signal dimension=%s requires values", rule.RuleID, sig.Dimension)
		}
		// deny 信号不可同时 required，且 score 无意义（强制为 0）
		if sig.Deny {
			if sig.Required {
				return fmt.Errorf("%s signal dimension=%s: deny and required are mutually exclusive", rule.RuleID, sig.Dimension)
			}
			if sig.Score != 0 {
				return fmt.Errorf("%s signal dimension=%s: deny signal must have score=0", rule.RuleID, sig.Dimension)
			}
		}
	}
	return nil
}

func validBehaviorStage(stage string) bool {
	switch stage {
	case StageCheck, StageNotify, StageDownload, StageVerify, StageStatus, StageHeartbeat:
		return true
	default:
		return false
	}
}

func validArtifactKind(kind string) bool {
	switch kind {
	case ArtifactFirmware, ArtifactApp, ArtifactManifest, ArtifactChecksum, ArtifactUnknown:
		return true
	default:
		return false
	}
}

func validHardConditionDimension(dim string) bool {
	switch dim {
	case DimProtocol, DimSource, DimMethod, DimStatusCode, DimPort, DimDirection:
		return true
	default:
		return false
	}
}

func validSignalDimension(dim string) bool {
	switch dim {
	case DimURI, DimHost, DimSNI, DimDNS, DimContentType, DimContentDisposition,
		DimExtension, DimRangeStatus, DimJSONKeys, DimFileMagic,
		DimBodyKeyword, DimBodyRegex, DimFileHash:
		return true
	default:
		return false
	}
}

// ComputeRulesetSHA256 计算规则集的规范化 SHA256 摘要。
// 用于不同进程之间比对行为规则版本，不一致时可标记 ruleset_mismatch。
// 摘要基于规则的规范化 YAML 序列化（仅 Version + Rules 字段），排除 compiled 索引。
func ComputeRulesetSHA256(rs *RuleSet) string {
	if rs == nil {
		return ""
	}
	// 构建只含 Version 和 Rules 的规范化结构，确保 compiled 不参与摘要
	canonical := struct {
		Version       string            `yaml:"version"`
		Rules         []BehaviorRule    `yaml:"rules"`
		VendorDomains map[string]string `yaml:"vendor_domains,omitempty"`
	}{
		Version:       rs.Version,
		Rules:         rs.Rules,
		VendorDomains: rs.VendorDomains,
	}
	data, err := yaml.Marshal(canonical)
	if err != nil {
		// 序列化失败不应发生；回退到空串，调用方应视为 SHA 不可用
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComputeRulesetSHA256FromBytes 直接从 YAML 字节流计算 SHA256。
// 与 ComputeRulesetSHA256 不同，此函数基于原始 YAML 字节而非反序列化后的结构，
// 适用于采集侧仅需对文件内容做摘要而不加载规则的场景。
func ComputeRulesetSHA256FromBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
