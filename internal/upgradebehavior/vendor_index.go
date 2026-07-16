package upgradebehavior

import (
	"strings"
)

// VendorDomainIndex 厂商域名后缀索引，编译期建立后不可变。
// 采用 map 实现精确后缀匹配：将域名按层级拆分后建立索引，
// 查询时从最长后缀开始逐级回溯，保证最具体匹配优先。
type VendorDomainIndex struct {
	// byDomain 将完整注册域名映射到 vendor_id，如 "tp-link.com" -> "V-TPLINK"。
	byDomain map[string]string
	// suffixes 按域名标签数降序排列，用于最长后缀匹配查询。
	suffixes []string
}

// NewVendorDomainIndex 根据域名→厂商映射构建不可变索引。
func NewVendorDomainIndex(mapping map[string]string) *VendorDomainIndex {
	idx := &VendorDomainIndex{
		byDomain: make(map[string]string, len(mapping)),
	}
	for domain, vendorID := range mapping {
		key := normalizeDomain(domain)
		if key == "" || vendorID == "" {
			continue
		}
		// 首次插入优先保留，保证结果可复现。
		if _, exists := idx.byDomain[key]; !exists {
			idx.byDomain[key] = vendorID
			idx.suffixes = append(idx.suffixes, key)
		}
	}
	// 按标签数降序排列，使更具体的域名优先匹配。
	sortSuffixes(idx.suffixes)
	return idx
}

// Match 在 SNI、DNS 查询、Host 中查找厂商 ID，返回首个命中的厂商。
// 查询策略：对每个候选域名，从最长后缀开始逐级回溯匹配 byDomain。
func (v *VendorDomainIndex) Match(sni, dnsQuery, host string) string {
	if v == nil || len(v.byDomain) == 0 {
		return ""
	}
	for _, candidate := range []string{sni, dnsQuery, host} {
		if vendorID := v.matchSingle(candidate); vendorID != "" {
			return vendorID
		}
	}
	return ""
}

// matchSingle 对单个域名执行最长后缀匹配。
func (v *VendorDomainIndex) matchSingle(domain string) string {
	d := normalizeDomain(domain)
	if d == "" {
		return ""
	}
	// 逐级去掉最左侧标签，从最具体到最宽泛匹配。
	for {
		if vendorID, ok := v.byDomain[d]; ok {
			return vendorID
		}
		dot := strings.Index(d, ".")
		if dot < 0 || dot >= len(d)-1 {
			break
		}
		d = d[dot+1:]
		// 防止匹配到裸 TLD（如 "com"），要求至少包含一个点。
		if !strings.Contains(d, ".") {
			break
		}
	}
	return ""
}

// normalizeDomain 规范化域名：去首尾空白与点、转小写。
func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.Trim(d, ".")
	return d
}

// sortSuffixes 按域名标签数降序排列（标签数多的更具体，优先匹配）。
// 同标签数时按字典序排列，保证结果可复现。
func sortSuffixes(suffixes []string) {
	// 简单插入排序，域名后缀集合通常较小（数百量级），避免引入 sort 依赖开销。
	for i := 1; i < len(suffixes); i++ {
		for j := i; j > 0 && lessSuffix(suffixes[j], suffixes[j-1]); j-- {
			suffixes[j], suffixes[j-1] = suffixes[j-1], suffixes[j]
		}
	}
}

// lessSuffix 标签数多者优先；同标签数按字典序。
func lessSuffix(a, b string) bool {
	la, lb := labelCount(a), labelCount(b)
	if la != lb {
		return la > lb
	}
	return a < b
}

// labelCount 统计域名标签数（按点分隔）。
func labelCount(domain string) int {
	if domain == "" {
		return 0
	}
	return strings.Count(domain, ".") + 1
}
