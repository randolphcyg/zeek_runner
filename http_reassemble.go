package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// maxStreamBufferBytes 限制单个 TCP 流重组缓冲上限，防止超大 pcap 耗尽内存。
const maxStreamBufferBytes = 4 * 1024 * 1024

// httpTransaction 描述一个完整的 HTTP 请求/响应事务。
type httpTransaction struct {
	// 连接五元组
	UID     string // Zeek UID（如果从 Zeek 日志关联）；为空时用五元组派生
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int

	// 请求
	Method         string
	RequestURI     string
	Host           string
	RequestHeaders map[string]string // 规范化为小写 key
	RequestBody    []byte

	// 响应
	StatusCode      int
	ResponseHeaders map[string]string // 规范化为小写 key
	ResponseBody    []byte            // 传输解码后的实体正文（未做内容解码）

	// 事务序号（同连接内从 1 开始）
	TxSeq int

	// 时间戳
	TS string

	// PartialPayload 表示重组发现缺段、乱序重叠或超出缓冲上限。
	PartialPayload bool
	PartialReason  string
}

// reassembledStream 是按方向重组后的 TCP 流。
type reassembledStream struct {
	srcIP    string
	srcPort  int
	dstIP    string
	dstPort  int
	ts       string
	data     []byte
	segments []tcpSegment
	partial  bool
	reason   string
}

type tcpSegment struct {
	seq  uint32
	data []byte
}

// connectionKey 标识一个 TCP 连接方向。
type connectionKey struct {
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
}

// peerKey 标识一个 TCP 连接（不区分方向），用于配对请求流和响应流。
func peerKey(ip1 string, port1 int, ip2 string, port2 int) string {
	if ip1 < ip2 || (ip1 == ip2 && port1 < port2) {
		return fmt.Sprintf("%s:%d-%s:%d", ip1, port1, ip2, port2)
	}
	return fmt.Sprintf("%s:%d-%s:%d", ip2, port2, ip1, port1)
}

// reassembleHTTPTransactions 从 pcap 文件中重组 HTTP 事务。
// 按 Zeek UID/连接五元组和 HTTP 事务序号关联 request 与 response，支持 keep-alive 与同连接多请求。
func reassembleHTTPTransactions(pcapPath string) ([]httpTransaction, error) {
	streams, err := extractTCPStreams(pcapPath)
	if err != nil {
		return nil, err
	}

	// 按 peer key 配对请求流和响应流
	streamsByPeer := make(map[string][]*reassembledStream)
	for _, s := range streams {
		pk := peerKey(s.srcIP, s.srcPort, s.dstIP, s.dstPort)
		streamsByPeer[pk] = append(streamsByPeer[pk], s)
	}

	var transactions []httpTransaction
	for pk, dirStreams := range streamsByPeer {
		var reqStream, respStream *reassembledStream
		for _, s := range dirStreams {
			if isHTTPRequest(s.data) {
				if reqStream == nil {
					reqStream = s
				}
			} else if isHTTPResponse(s.data) {
				if respStream == nil {
					respStream = s
				}
			}
		}
		// 需要至少有请求或响应
		if reqStream == nil && respStream == nil {
			continue
		}

		// 确定连接方向：请求流的方向即为连接方向
		var srcIP string
		var srcPort, dstPort int
		var dstIP string
		var ts string
		if reqStream != nil {
			srcIP = reqStream.srcIP
			srcPort = reqStream.srcPort
			dstIP = reqStream.dstIP
			dstPort = reqStream.dstPort
			ts = reqStream.ts
		} else {
			// 仅有响应流：反转方向
			srcIP = respStream.dstIP
			srcPort = respStream.dstPort
			dstIP = respStream.srcIP
			dstPort = respStream.srcPort
			ts = respStream.ts
		}
		_ = pk

		// 解析 HTTP 事务（支持 keep-alive 多事务）
		txs := parseHTTPStreamPair(reqStream, respStream)
		for i := range txs {
			txs[i].SrcIP = srcIP
			txs[i].SrcPort = srcPort
			txs[i].DstIP = dstIP
			txs[i].DstPort = dstPort
			txs[i].TS = ts
			txs[i].PartialPayload = (reqStream != nil && reqStream.partial) || (respStream != nil && respStream.partial)
			if reqStream != nil && reqStream.reason != "" {
				txs[i].PartialReason = reqStream.reason
			} else if respStream != nil {
				txs[i].PartialReason = respStream.reason
			}
		}
		transactions = append(transactions, txs...)
	}
	return transactions, nil
}

// extractTCPStreams 从 pcap 文件中提取 TCP 流（按连接方向分组的 payload 拼接）。
func extractTCPStreams(pcapPath string) ([]*reassembledStream, error) {
	file, err := os.Open(pcapPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	globalHeader := make([]byte, 24)
	if _, err := io.ReadFull(reader, globalHeader); err != nil {
		return nil, err
	}
	var order binary.ByteOrder = binary.LittleEndian
	if binary.LittleEndian.Uint32(globalHeader[:4]) == 0xD4C3B2A1 {
		order = binary.BigEndian
	}

	streams := make(map[connectionKey]*reassembledStream)
	for {
		packetHeader := make([]byte, 16)
		if _, err := io.ReadFull(reader, packetHeader); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, err
		}
		tsSec := order.Uint32(packetHeader[0:4])
		tsUsec := order.Uint32(packetHeader[4:8])
		inclLen := order.Uint32(packetHeader[8:12])
		if inclLen == 0 || inclLen > 16*1024*1024 {
			break
		}
		packet := make([]byte, inclLen)
		if _, err := io.ReadFull(reader, packet); err != nil {
			return nil, err
		}
		if len(packet) < 34 || binary.BigEndian.Uint16(packet[12:14]) != 0x0800 {
			continue
		}
		ip := packet[14:]
		ihl := int(ip[0]&0x0f) * 4
		if len(ip) < ihl+20 || ihl < 20 || ip[9] != 6 {
			continue
		}
		tcp := ip[ihl:]
		dataOffset := int(tcp[12]>>4) * 4
		if len(tcp) < dataOffset || dataOffset < 20 {
			continue
		}
		payload := tcp[dataOffset:]
		if len(payload) == 0 {
			continue
		}
		srcIP := parseIPv4String(ip[12:16])
		dstIP := parseIPv4String(ip[16:20])
		srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
		dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))
		key := connectionKey{srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
		stream := streams[key]
		if stream == nil {
			stream = &reassembledStream{
				srcIP:   srcIP,
				srcPort: srcPort,
				dstIP:   dstIP,
				dstPort: dstPort,
				ts:      fmt.Sprintf("%d.%06d", tsSec, tsUsec),
			}
			streams[key] = stream
		}
		stream.segments = append(stream.segments, tcpSegment{seq: binary.BigEndian.Uint32(tcp[4:8]), data: append([]byte(nil), payload...)})
	}

	result := make([]*reassembledStream, 0, len(streams))
	for _, s := range streams {
		reassembleStreamSegments(s)
		result = append(result, s)
	}
	return result, nil
}

func reassembleStreamSegments(stream *reassembledStream) {
	if stream == nil || len(stream.segments) == 0 {
		return
	}
	sort.SliceStable(stream.segments, func(i, j int) bool { return stream.segments[i].seq < stream.segments[j].seq })
	var expected uint32
	initialized := false
	for _, segment := range stream.segments {
		payload := segment.data
		if !initialized {
			expected = segment.seq
			initialized = true
		}
		if segment.seq > expected {
			stream.markPartial("tcp sequence gap")
			expected = segment.seq
		}
		if segment.seq < expected {
			offset := expected - segment.seq
			if offset >= uint32(len(payload)) {
				continue // 完整重传
			}
			payload = payload[offset:] // 重叠重传只保留新增尾部
		}
		if len(stream.data)+len(payload) > maxStreamBufferBytes {
			room := maxStreamBufferBytes - len(stream.data)
			if room > 0 {
				stream.data = append(stream.data, payload[:room]...)
			}
			stream.markPartial("tcp stream exceeded max buffer size")
			return
		}
		stream.data = append(stream.data, payload...)
		expected += uint32(len(payload))
	}
}

func (stream *reassembledStream) markPartial(reason string) {
	stream.partial = true
	if stream.reason == "" {
		stream.reason = reason
	}
}

// isHTTPRequest 判断数据是否以 HTTP 请求行开头。
func isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	prefix := string(data[:4])
	switch prefix {
	case "GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "TRAC", "CONN":
		return true
	}
	return false
}

// isHTTPResponse 判断数据是否以 HTTP 响应行开头。
func isHTTPResponse(data []byte) bool {
	return bytes.HasPrefix(data, []byte("HTTP/"))
}

// parseHTTPStreamPair 解析配对的请求流和响应流，提取 HTTP 事务（支持 keep-alive 多事务）。
func parseHTTPStreamPair(reqStream, respStream *reassembledStream) []httpTransaction {
	var txs []httpTransaction

	var reqMsgs []httpMessage
	if reqStream != nil {
		reqMsgs = parseHTTPMessages(reqStream.data)
	}
	var respMsgs []httpMessage
	if respStream != nil {
		respMsgs = parseHTTPMessages(respStream.data)
	}

	// 按顺序配对请求和响应
	maxLen := len(reqMsgs)
	if len(respMsgs) > maxLen {
		maxLen = len(respMsgs)
	}
	for i := 0; i < maxLen; i++ {
		tx := httpTransaction{TxSeq: i + 1}
		if i < len(reqMsgs) {
			fillRequestFromMessage(&tx, &reqMsgs[i])
		}
		if i < len(respMsgs) {
			fillResponseFromMessage(&tx, &respMsgs[i])
		}
		txs = append(txs, tx)
	}
	return txs
}

// httpMessage 是解析出的单个 HTTP 消息（请求或响应）。
type httpMessage struct {
	startLine string
	headers   map[string]string
	body      []byte
}

// parseHTTPMessages 从流数据中解析多个 HTTP 消息（支持 keep-alive）。
func parseHTTPMessages(data []byte) []httpMessage {
	var messages []httpMessage
	offset := 0
	for offset < len(data) {
		// 查找头部结束标记 \r\n\r\n
		headerEnd := bytes.Index(data[offset:], []byte("\r\n\r\n"))
		if headerEnd < 0 {
			break
		}
		headerSection := string(data[offset : offset+headerEnd])
		bodyStart := offset + headerEnd + 4

		// 解析头部
		lines := strings.Split(headerSection, "\r\n")
		if len(lines) == 0 {
			break
		}
		msg := httpMessage{
			startLine: lines[0],
			headers:   parseHTTPHeaderLines(lines[1:]),
		}

		_, hasCL := msg.headers["content-length"]
		te := strings.ToLower(msg.headers["transfer-encoding"])
		hasTE := strings.Contains(te, "chunked")

		// 请求行无 Content-Length 且非 chunked → 视为无正文（GET/HEAD 等无正文请求），
		// 否则 extractHTTPBody 会将后续请求作为正文消费，破坏 keep-alive 多事务解析。
		if !hasCL && !hasTE && isHTTPRequest([]byte(msg.startLine)) {
			messages = append(messages, msg)
			offset = bodyStart
			continue
		}

		// 确定正文长度
		body, consumed := extractHTTPBody(data, bodyStart, msg.headers)
		msg.body = body
		messages = append(messages, msg)

		offset = bodyStart + consumed
		// 每次迭代 offset 至少前进 headerEnd+4，不会无限循环。
		// 无 CL/TE 的响应会把剩余数据作为正文，offset 到达末尾后循环自然结束。
	}
	return messages
}

// parseHTTPHeaderLines 将 "Key: Value" 行解析为小写 key 的 map。
func parseHTTPHeaderLines(lines []string) map[string]string {
	headers := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if name != "" {
			headers[name] = value
		}
	}
	return headers
}

// extractHTTPBody 根据 Transfer-Encoding 或 Content-Length 提取正文。
// 返回 (正文, 消耗的字节数)。
func extractHTTPBody(data []byte, bodyStart int, headers map[string]string) ([]byte, int) {
	te := strings.ToLower(headers["transfer-encoding"])
	if strings.Contains(te, "chunked") {
		return extractChunkedBody(data, bodyStart)
	}
	clStr := headers["content-length"]
	if clStr != "" {
		cl, err := strconv.Atoi(clStr)
		if err != nil || cl < 0 {
			return nil, 0
		}
		if bodyStart+cl > len(data) {
			cl = len(data) - bodyStart
			if cl < 0 {
				cl = 0
			}
		}
		return data[bodyStart : bodyStart+cl], cl
	}
	// 无 Content-Length 且非 chunked：剩余数据作为正文（适用于无 keep-alive 的简单场景）
	if len(data) > bodyStart {
		return data[bodyStart:], len(data) - bodyStart
	}
	return nil, 0
}

// extractChunkedBody 解析 chunked transfer-encoding 正文。
// 先完成 HTTP 传输层解码，再将实体正文送入识别器。
func extractChunkedBody(data []byte, start int) ([]byte, int) {
	var body bytes.Buffer
	offset := start
	for offset < len(data) {
		// 查找 chunk 大小行
		lineEnd := bytes.Index(data[offset:], []byte("\r\n"))
		if lineEnd < 0 {
			break
		}
		sizeStr := strings.TrimSpace(string(data[offset : offset+lineEnd]))
		// chunk 大小可能带扩展（如 "1a;ext=val"），取分号前部分
		if semi := strings.IndexByte(sizeStr, ';'); semi >= 0 {
			sizeStr = sizeStr[:semi]
		}
		chunkSize, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			break
		}
		offset += lineEnd + 2 // 跳过大小行 + \r\n

		if chunkSize == 0 {
			// 最后一个 chunk
			// 跳过尾随的 \r\n（如果有）
			if offset+2 <= len(data) && data[offset] == '\r' && data[offset+1] == '\n' {
				offset += 2
			}
			break
		}

		if offset+int(chunkSize) > len(data) {
			// 数据不完整，取可用部分
			body.Write(data[offset:])
			offset = len(data)
			break
		}
		body.Write(data[offset : offset+int(chunkSize)])
		offset += int(chunkSize)
		// 跳过 chunk 后的 \r\n
		if offset+2 <= len(data) && data[offset] == '\r' && data[offset+1] == '\n' {
			offset += 2
		}
	}
	return body.Bytes(), offset - start
}

// fillRequestFromMessage 从 HTTP 消息填充请求字段到事务。
func fillRequestFromMessage(tx *httpTransaction, msg *httpMessage) {
	parts := strings.SplitN(msg.startLine, " ", 3)
	if len(parts) >= 2 {
		tx.Method = parts[0]
		tx.RequestURI = parts[1]
	}
	tx.RequestHeaders = msg.headers
	tx.Host = msg.headers["host"]
	tx.RequestBody = msg.body
}

// fillResponseFromMessage 从 HTTP 消息填充响应字段到事务。
func fillResponseFromMessage(tx *httpTransaction, msg *httpMessage) {
	parts := strings.SplitN(msg.startLine, " ", 3)
	if len(parts) >= 2 {
		tx.StatusCode = parseIntField(parts[1])
	}
	tx.ResponseHeaders = msg.headers
	tx.ResponseBody = msg.body
}

// normalizeHTTPHeaders 提取并规范化为小写 map 的请求/响应头：
// range、content-range、content-type、content-disposition、content-encoding、
// transfer-encoding、content-length、host。
// 输入 headers 的 key 可能是混合大小写（直接构造而非来自 parseHTTPHeaderLines），
// 此处统一转小写后匹配。
func normalizeHTTPHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	tracked := map[string]bool{
		"range": true, "content-range": true, "content-type": true,
		"content-disposition": true, "content-encoding": true,
		"transfer-encoding": true, "content-length": true, "host": true,
	}
	out := make(map[string]string, len(tracked))
	for k, v := range headers {
		lk := strings.ToLower(k)
		if tracked[lk] {
			out[lk] = v
		}
	}
	return out
}

// parseURIPath 从 URI 中提取路径部分（去除查询串）。
func parseURIPath(uri string) string {
	if u, err := url.Parse(uri); err == nil {
		return u.Path
	}
	if q := strings.IndexByte(uri, '?'); q >= 0 {
		return uri[:q]
	}
	return uri
}
