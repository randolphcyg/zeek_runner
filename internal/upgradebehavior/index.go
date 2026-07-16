package upgradebehavior

import (
	"fmt"
	"strconv"
	"strings"
)

// CompiledIndex 编译期建立的不可变索引，用于快速缩小候选规则集。
// 索引按硬条件维度（protocol/source/method/status_code/port）与必需信号维度
// （extension/content_type）分组，查询时取并集再由调用方做完整硬条件检查。
type CompiledIndex struct {
	byProtocol    map[string][]*BehaviorRule
	bySource      map[string][]*BehaviorRule
	byMethod      map[string][]*BehaviorRule
	byStatus      map[int][]*BehaviorRule
	byPort        map[int][]*BehaviorRule
	byExt         map[string][]*BehaviorRule
	byContentType map[string][]*BehaviorRule
	// noHardCond 无硬条件的规则，始终为候选。
	noHardCond []*BehaviorRule
	// all 全部规则指针，作为回退。
	all []*BehaviorRule
}

// CompileIndex 编译规则集索引：预编译正则、校验必需信号、建立多维度索引。
// 返回的索引不可变，调用方不应修改。
func CompileIndex(rules []BehaviorRule) (*CompiledIndex, error) {
	idx := &CompiledIndex{
		byProtocol:    make(map[string][]*BehaviorRule),
		bySource:      make(map[string][]*BehaviorRule),
		byMethod:      make(map[string][]*BehaviorRule),
		byStatus:      make(map[int][]*BehaviorRule),
		byPort:        make(map[int][]*BehaviorRule),
		byExt:         make(map[string][]*BehaviorRule),
		byContentType: make(map[string][]*BehaviorRule),
	}

	for i := range rules {
		rule := &rules[i]

		// 预编译所有信号正则
		for j := range rule.Signals {
			compiled, err := rule.Signals[j].compile()
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.RuleID, err)
			}
			rule.Signals[j] = compiled
		}

		// 校验硬条件操作符
		for _, hc := range rule.HardConditions {
			if err := validateOperator(hc.Operator); err != nil {
				return nil, fmt.Errorf("rule %s hard_condition dimension=%s: %w", rule.RuleID, hc.Dimension, err)
			}
		}

		// 建立硬条件索引
		hasHardCond := false
		for _, hc := range rule.HardConditions {
			hasHardCond = true
			idx.indexHardCondition(rule, hc)
		}

		// 建立必需信号索引（extension/content_type）
		for _, sig := range rule.Signals {
			if !sig.Required {
				continue
			}
			switch sig.Dimension {
			case DimExtension:
				for _, v := range sig.Values {
					key := strings.ToLower(strings.TrimSpace(v))
					if key != "" {
						idx.byExt[key] = append(idx.byExt[key], rule)
					}
				}
			case DimContentType:
				for _, v := range sig.Values {
					key := strings.ToLower(strings.TrimSpace(v))
					if key != "" {
						idx.byContentType[key] = append(idx.byContentType[key], rule)
					}
				}
			}
		}

		if !hasHardCond {
			idx.noHardCond = append(idx.noHardCond, rule)
		}
		idx.all = append(idx.all, rule)
	}

	return idx, nil
}

// indexHardCondition 根据硬条件维度将规则加入对应索引。
func (idx *CompiledIndex) indexHardCondition(rule *BehaviorRule, hc HardCondition) {
	switch hc.Dimension {
	case DimProtocol:
		for _, v := range hc.Values {
			key := strings.ToLower(strings.TrimSpace(v))
			if key != "" {
				idx.byProtocol[key] = append(idx.byProtocol[key], rule)
			}
		}
	case DimSource:
		for _, v := range hc.Values {
			key := strings.ToLower(strings.TrimSpace(v))
			if key != "" {
				idx.bySource[key] = append(idx.bySource[key], rule)
			}
		}
	case DimMethod:
		for _, v := range hc.Values {
			key := strings.ToLower(strings.TrimSpace(v))
			if key != "" {
				idx.byMethod[key] = append(idx.byMethod[key], rule)
			}
		}
	case DimStatusCode:
		for _, v := range hc.Values {
			if code, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				idx.byStatus[code] = append(idx.byStatus[code], rule)
			}
		}
	case DimPort:
		for _, v := range hc.Values {
			if port, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				idx.byPort[port] = append(idx.byPort[port], rule)
			}
		}
	case DimDirection:
		// direction 硬条件不参与索引，在 matchHardConditions 中检查
	}
}

// Candidates 根据事件元数据返回候选规则集（并集去重）。
// 包含：无硬条件规则 + 各维度索引命中的规则。
// 若结果为空则回退到全部规则，保证不遗漏。
func (idx *CompiledIndex) Candidates(meta EventMeta) []*BehaviorRule {
	if idx == nil {
		return nil
	}
	seen := make(map[*BehaviorRule]bool, len(idx.all))
	result := make([]*BehaviorRule, 0, len(idx.all))

	add := func(rules []*BehaviorRule) {
		for _, r := range rules {
			if !seen[r] {
				seen[r] = true
				result = append(result, r)
			}
		}
	}

	// 无硬条件规则始终为候选
	add(idx.noHardCond)
	// 按各维度索引查找
	add(idx.byProtocol[strings.ToLower(meta.Protocol)])
	add(idx.bySource[strings.ToLower(meta.Source)])
	add(idx.byMethod[strings.ToLower(meta.Method)])
	if meta.StatusCode != 0 {
		add(idx.byStatus[meta.StatusCode])
	}
	if meta.DstPort != 0 {
		add(idx.byPort[meta.DstPort])
	}
	// 必需信号预过滤：extension / content_type
	ext := extractExtension(meta)
	if ext != "" {
		add(idx.byExt[ext])
	}
	ct := normalizeMIME(strings.ToLower(strings.TrimSpace(meta.ContentType)))
	if ct != "" {
		add(idx.byContentType[ct])
	}

	if len(result) == 0 {
		return idx.all
	}
	return result
}

// extractExtension 从元数据中提取文件扩展名（小写，含点）。
func extractExtension(meta EventMeta) string {
	for _, name := range []string{meta.Filename, meta.OrigFilename, meta.URI} {
		if name == "" {
			continue
		}
		// 去除查询串
		if q := strings.IndexByte(name, '?'); q >= 0 {
			name = name[:q]
		}
		dot := strings.LastIndexByte(name, '.')
		if dot < 0 || dot == len(name)-1 {
			continue
		}
		ext := strings.ToLower(name[dot:])
		return ext
	}
	return ""
}
