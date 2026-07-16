package upgradebehavior

import (
	"bytes"
	"strings"
)

// 文件 magic 常量。detectMagic 返回这些标识符，规则中以 magic 操作符匹配。
const (
	MagicZIP    = "zip"    // PK\x03\x04，ZIP/APK/JAR
	MagicGzip   = "gzip"   // \x1f\x8b
	MagicELF    = "elf"    // \x7fELF
	MagicRar    = "rar"    // Rar!\x1a\x07
	Magic7z     = "7z"     // 7z\xbc\xaf\x27\x1c
	MagicBzip2  = "bzip2"  // BZh
	MagicUImage = "uimage" // \x27\x05\x19\x56，U-Boot uImage
	MagicBin    = "bin"    // \xde\xad\xbe\xef，通用固件二进制标记
	MagicDEX    = "dex"    // dex\n035，Android DEX
)

// magicSignatures 按 magic 前缀降序排列，保证最长前缀优先匹配。
var magicSignatures = []struct {
	prefix []byte
	name   string
}{
	{[]byte{0x50, 0x4b, 0x03, 0x04}, MagicZIP},
	{[]byte{0x1f, 0x8b}, MagicGzip},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07}, MagicRar},
	{[]byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, Magic7z},
	{[]byte{0x42, 0x5a, 0x68}, MagicBzip2},
	{[]byte{0x7f, 0x45, 0x4c, 0x46}, MagicELF},
	{[]byte{0x27, 0x05, 0x19, 0x56}, MagicUImage},
	{[]byte{0xde, 0xad, 0xbe, 0xef}, MagicBin},
	{[]byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35}, MagicDEX},
}

// detectMagic 检测数据开头的文件 magic，返回 magic 标识符；无匹配返回空串。
// 仅检查前 8 字节，适合流式首块检测。
func detectMagic(data []byte) string {
	for _, sig := range magicSignatures {
		if bytes.HasPrefix(data, sig.prefix) {
			return sig.name
		}
	}
	return ""
}

// extractJSONKeys 从 JSON 数据中提取顶层对象的键名。
// 采用轻量状态机实现，不依赖完整 JSON 解析，仅提取 depth==1 处的键。
// 非合法 JSON 或非对象开头时返回空集合。
func extractJSONKeys(data []byte) map[string]bool {
	keys := make(map[string]bool)
	i := 0
	n := len(data)
	// 跳过前导空白
	i = skipJSONWhitespace(data, i)
	if i >= n || data[i] != '{' {
		return keys
	}
	i++ // 跳过 '{'
	depth := 1

	for i < n {
		i = skipJSONWhitespace(data, i)
		if i >= n {
			break
		}
		switch data[i] {
		case '}':
			depth--
			i++
			if depth == 0 {
				return keys
			}
		case ',':
			i++
		case '{', '[':
			depth++
			i++
		case ']':
			depth--
			i++
		case '"':
			// 尝试解析为键名
			key, next := parseJSONString(data, i)
			if key == "" {
				i = next
				continue
			}
			i = next
			// 跳过键名后的空白，检查是否紧跟 ':'
			j := skipJSONWhitespace(data, i)
			if j < n && data[j] == ':' {
				if depth == 1 {
					keys[strings.ToLower(key)] = true
				}
				i = j + 1 // 跳过 ':'
				// 跳过值
				i = skipJSONValue(data, i, &depth)
			}
		default:
			// 裸值（数字/布尔/null），跳过
			i = skipJSONValue(data, i, &depth)
		}
	}
	return keys
}

// parseJSONString 解析从 pos 开始的 JSON 字符串（pos 指向开引号）。
// 返回去转义后的字符串内容与下一个待处理位置。
func parseJSONString(data []byte, pos int) (string, int) {
	n := len(data)
	if pos >= n || data[pos] != '"' {
		return "", pos + 1
	}
	var b strings.Builder
	i := pos + 1
	for i < n {
		c := data[i]
		if c == '\\' && i+1 < n {
			// 简单去转义，仅处理常见转义符
			next := data[i+1]
			switch next {
			case '"', '\\', '/':
				b.WriteByte(next)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(next)
			}
			i += 2
			continue
		}
		if c == '"' {
			return b.String(), i + 1
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), i
}

// skipJSONWhitespace 跳过 JSON 空白字符，返回下一个非空白位置。
func skipJSONWhitespace(data []byte, pos int) int {
	n := len(data)
	for pos < n {
		switch data[pos] {
		case ' ', '\t', '\n', '\r':
			pos++
		default:
			return pos
		}
	}
	return pos
}

// skipJSONValue 跳过一个 JSON 值，更新 depth。
func skipJSONValue(data []byte, pos int, depth *int) int {
	n := len(data)
	pos = skipJSONWhitespace(data, pos)
	if pos >= n {
		return pos
	}
	switch data[pos] {
	case '"':
		_, next := parseJSONString(data, pos)
		return next
	case '{':
		*depth++
		return pos + 1
	case '}':
		*depth--
		return pos + 1
	case '[':
		*depth++
		return pos + 1
	case ']':
		*depth--
		return pos + 1
	default:
		// 裸值：数字/true/false/null，扫描到分隔符为止
		for pos < n {
			c := data[pos]
			if c == ',' || c == '}' || c == ']' {
				return pos
			}
			pos++
		}
		return pos
	}
}

// scanKeywords 在数据中扫描多个关键词，返回命中的关键词集合（小写）。
// 优先使用 strings.Contains 实现多模式匹配，适合关键词数量适中的场景。
func scanKeywords(data []byte, keywords []string) map[string]bool {
	hits := make(map[string]bool)
	if len(keywords) == 0 {
		return hits
	}
	lower := strings.ToLower(string(data))
	for _, kw := range keywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k == "" {
			continue
		}
		if strings.Contains(lower, k) {
			hits[k] = true
		}
	}
	return hits
}
