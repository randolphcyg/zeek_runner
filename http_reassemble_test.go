package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// --- pcap 文件构建辅助 ---

// pcapPacket 描述一个 TCP 包。
type pcapPacket struct {
	srcIP   string
	dstIP   string
	srcPort int
	dstPort int
	payload []byte
	seq     uint32 // 0 时由 helper 按同一方向连续分配
}

// writePcapFile 构建一个合法的 pcap 文件，包含给定的 TCP 包列表。
func writePcapFile(t *testing.T, path string, packets []pcapPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	// 全局头（little-endian）
	globalHeader := make([]byte, 24)
	binary.LittleEndian.PutUint32(globalHeader[0:4], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(globalHeader[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(globalHeader[6:8], 4)          // version minor
	binary.LittleEndian.PutUint32(globalHeader[8:12], 0)         // thiszone
	binary.LittleEndian.PutUint32(globalHeader[12:16], 0)        // sigfigs
	binary.LittleEndian.PutUint32(globalHeader[16:20], 65535)    // snaplen
	binary.LittleEndian.PutUint32(globalHeader[20:24], 1)        // network: Ethernet
	if _, err := f.Write(globalHeader); err != nil {
		t.Fatalf("write global header: %v", err)
	}

	nextSeq := make(map[string]uint32)
	for i, pkt := range packets {
		ethHeader := make([]byte, 14)
		ethHeader[12] = 0x08
		ethHeader[13] = 0x00 // IPv4

		ipTotalLen := 20 + 20 + len(pkt.payload)
		ipHeader := make([]byte, 20)
		ipHeader[0] = 0x45 // version=4, ihl=5
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(ipTotalLen))
		ipHeader[8] = 64 // ttl
		ipHeader[9] = 6  // protocol: TCP
		copy(ipHeader[12:16], parseIPv4Bytes(pkt.srcIP))
		copy(ipHeader[16:20], parseIPv4Bytes(pkt.dstIP))

		tcpHeader := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(pkt.srcPort))
		binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(pkt.dstPort))
		streamKey := pkt.srcIP + ":" + strconv.Itoa(pkt.srcPort) + ">" + pkt.dstIP + ":" + strconv.Itoa(pkt.dstPort)
		seq := pkt.seq
		if seq == 0 {
			seq = nextSeq[streamKey]
			if seq == 0 {
				seq = 1000
			}
		}
		binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
		if seq+uint32(len(pkt.payload)) > nextSeq[streamKey] {
			nextSeq[streamKey] = seq + uint32(len(pkt.payload))
		}
		binary.BigEndian.PutUint32(tcpHeader[8:12], 1)      // ack
		tcpHeader[12] = 0x50                                // data offset = 5 (20 bytes)
		tcpHeader[13] = 0x18                                // flags: PSH|ACK
		binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // window

		packetData := append(ethHeader, ipHeader...)
		packetData = append(packetData, tcpHeader...)
		packetData = append(packetData, pkt.payload...)

		pktHeader := make([]byte, 16)
		binary.LittleEndian.PutUint32(pktHeader[0:4], uint32(i+1))               // ts_sec
		binary.LittleEndian.PutUint32(pktHeader[4:8], 0)                         // ts_usec
		binary.LittleEndian.PutUint32(pktHeader[8:12], uint32(len(packetData)))  // incl_len
		binary.LittleEndian.PutUint32(pktHeader[12:16], uint32(len(packetData))) // orig_len

		if _, err := f.Write(pktHeader); err != nil {
			t.Fatalf("write packet header %d: %v", i, err)
		}
		if _, err := f.Write(packetData); err != nil {
			t.Fatalf("write packet data %d: %v", i, err)
		}
	}
}

func parseIPv4Bytes(ip string) []byte {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return []byte{0, 0, 0, 0}
	}
	out := make([]byte, 4)
	for i, p := range parts {
		var v uint
		for _, c := range p {
			v = v*10 + uint(c-'0')
		}
		out[i] = byte(v)
	}
	return out
}

// --- parseHTTPMessages 测试 ---

func TestParseHTTPMessages_KeepAliveMultiTransactions(t *testing.T) {
	// 同一 TCP 流中两个 HTTP 请求（keep-alive）
	stream := []byte(strings.Join([]string{
		"GET /api/version HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
		"GET /firmware.bin HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
	}, ""))

	msgs := parseHTTPMessages(stream)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 HTTP messages, got %d", len(msgs))
	}
	if msgs[0].startLine != "GET /api/version HTTP/1.1" {
		t.Fatalf("first message startLine mismatch: %q", msgs[0].startLine)
	}
	if msgs[1].startLine != "GET /firmware.bin HTTP/1.1" {
		t.Fatalf("second message startLine mismatch: %q", msgs[1].startLine)
	}
}

func TestParseHTTPMessages_ChunkedBody(t *testing.T) {
	// chunked transfer-encoding 正文
	stream := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nHello\r\n" +
		"7\r\n, world\r\n" +
		"0\r\n\r\n")

	msgs := parseHTTPMessages(stream)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	expected := "Hello, world"
	if string(msgs[0].body) != expected {
		t.Fatalf("chunked body mismatch: got %q, want %q", msgs[0].body, expected)
	}
}

func TestParseHTTPMessages_ChunkedMultiTransactions(t *testing.T) {
	// 两个 chunked 响应（keep-alive）
	stream := []byte(strings.Join([]string{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndefg\r\n0\r\n\r\n",
	}, ""))

	msgs := parseHTTPMessages(stream)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 chunked messages, got %d", len(msgs))
	}
	if string(msgs[0].body) != "abc" {
		t.Fatalf("first chunked body: got %q", msgs[0].body)
	}
	if string(msgs[1].body) != "defg" {
		t.Fatalf("second chunked body: got %q", msgs[1].body)
	}
}

func TestParseHTTPMessages_EmptyBody(t *testing.T) {
	// Content-Length: 0 → 空正文
	stream := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

	msgs := parseHTTPMessages(stream)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if len(msgs[0].body) != 0 {
		t.Fatalf("expected empty body, got %d bytes", len(msgs[0].body))
	}
}

func TestParseHTTPMessages_ContentLengthBody(t *testing.T) {
	body := `{"version":"1.0"}`
	stream := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n" + body)

	msgs := parseHTTPMessages(stream)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if string(msgs[0].body) != body {
		t.Fatalf("body mismatch: got %q, want %q", msgs[0].body, body)
	}
}

func TestParseHTTPMessages_MalformedHTTP_NoHeaderEnd(t *testing.T) {
	// 没有 \r\n\r\n 结束标记
	stream := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n")
	msgs := parseHTTPMessages(stream)
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages for malformed HTTP (no header end), got %d", len(msgs))
	}
}

func TestParseHTTPMessages_MalformedHTTP_GarbledData(t *testing.T) {
	stream := []byte("GARBAGE DATA NOT HTTP\r\n\r\n")
	msgs := parseHTTPMessages(stream)
	// parseHTTPMessages 不校验 startLine 格式，只要有 \r\n\r\n 就会解析
	// 这里验证不会 panic 或无限循环
	if len(msgs) > 1 {
		t.Fatalf("expected at most 1 message for garbled data, got %d", len(msgs))
	}
}

func TestExtractChunkedBody_Basic(t *testing.T) {
	data := []byte("5\r\nHello\r\n7\r\n, world\r\n0\r\n\r\n")
	body, consumed := extractChunkedBody(data, 0)
	if string(body) != "Hello, world" {
		t.Fatalf("chunked body mismatch: got %q", body)
	}
	if consumed != len(data) {
		t.Fatalf("consumed mismatch: got %d, want %d", consumed, len(data))
	}
}

func TestExtractChunkedBody_WithExtension(t *testing.T) {
	// chunk 大小行带扩展: "5;ext=val\r\n"
	data := []byte("5;ext=val\r\nHello\r\n0\r\n\r\n")
	body, _ := extractChunkedBody(data, 0)
	if string(body) != "Hello" {
		t.Fatalf("chunked body with ext mismatch: got %q", body)
	}
}

func TestExtractChunkedBody_Truncated(t *testing.T) {
	// 不完整的 chunked 数据
	data := []byte("5\r\nHel")
	body, _ := extractChunkedBody(data, 0)
	// 应返回已解出的部分，不 panic
	if string(body) != "Hel" {
		t.Fatalf("truncated chunked body: got %q, want %q", body, "Hel")
	}
}

// --- normalizeHTTPHeaders 测试 ---

func TestNormalizeHTTPHeaders_TrackedHeaders(t *testing.T) {
	headers := map[string]string{
		"Range":               "bytes=0-1023",
		"Content-Range":       "bytes 0-1023/2048",
		"Content-Type":        "application/octet-stream",
		"Content-Disposition": `attachment; filename="fw.bin"`,
		"Content-Encoding":    "gzip",
		"Transfer-Encoding":   "chunked",
		"Content-Length":      "1024",
		"Host":                "example.com",
		"X-Custom":            "should-be-excluded",
	}

	normalized := normalizeHTTPHeaders(headers)
	expected := map[string]string{
		"range":               "bytes=0-1023",
		"content-range":       "bytes 0-1023/2048",
		"content-type":        "application/octet-stream",
		"content-disposition": `attachment; filename="fw.bin"`,
		"content-encoding":    "gzip",
		"transfer-encoding":   "chunked",
		"content-length":      "1024",
		"host":                "example.com",
	}
	for k, v := range expected {
		if normalized[k] != v {
			t.Fatalf("normalized header %q: got %q, want %q", k, normalized[k], v)
		}
	}
	if _, ok := normalized["x-custom"]; ok {
		t.Fatal("x-custom should not be in normalized headers")
	}
}

func TestNormalizeHTTPHeaders_AlreadyLowercase(t *testing.T) {
	headers := map[string]string{
		"content-type": "application/json",
		"host":         "example.com",
	}
	normalized := normalizeHTTPHeaders(headers)
	if normalized["content-type"] != "application/json" {
		t.Fatalf("expected application/json, got %q", normalized["content-type"])
	}
	if normalized["host"] != "example.com" {
		t.Fatalf("expected example.com, got %q", normalized["host"])
	}
}

func TestNormalizeHTTPHeaders_Nil(t *testing.T) {
	if normalized := normalizeHTTPHeaders(nil); normalized != nil {
		t.Fatalf("expected nil for nil input, got %v", normalized)
	}
}

// --- extractTCPStreams / reassembleHTTPTransactions 测试 ---

func TestReassembleHTTPTransactions_CrossTCPFragments(t *testing.T) {
	// 单个 HTTP 请求被拆分到多个 TCP 包中
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "fragments.pcap")

	fullRequest := "GET /firmware.bin HTTP/1.1\r\nHost: fw.example.com\r\nContent-Length: 0\r\n\r\n"
	fullResponse := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 12\r\n\r\nfirmware!!"

	// 请求拆成两个包，响应拆成两个包
	packets := []pcapPacket{
		// 请求片段 1
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 12345, dstPort: 80, payload: []byte(fullRequest[:30])},
		// 请求片段 2
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 12345, dstPort: 80, payload: []byte(fullRequest[30:])},
		// 响应片段 1
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 12345, payload: []byte(fullResponse[:40])},
		// 响应片段 2
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 12345, payload: []byte(fullResponse[40:])},
	}
	writePcapFile(t, pcapPath, packets)

	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
	tx := txs[0]
	if tx.Method != "GET" {
		t.Fatalf("expected method GET, got %q", tx.Method)
	}
	if tx.RequestURI != "/firmware.bin" {
		t.Fatalf("expected URI /firmware.bin, got %q", tx.RequestURI)
	}
	if tx.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", tx.StatusCode)
	}
	if string(tx.ResponseBody) != "firmware!!" {
		t.Fatalf("expected response body 'firmware!!', got %q", tx.ResponseBody)
	}
	if tx.Host != "fw.example.com" {
		t.Fatalf("expected host fw.example.com, got %q", tx.Host)
	}
}

func TestReassembleHTTPTransactions_KeepAliveMultiTransactions(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "keepalive.pcap")

	// 同一连接两个请求/响应对（keep-alive）
	req1 := "GET /api/version HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp1 := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
	req2 := "GET /firmware.bin HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp2 := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nFW!!"

	// 请求方向流：req1 + req2
	// 响应方向流：resp1 + resp2
	packets := []pcapPacket{
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 50000, dstPort: 80, payload: []byte(req1)},
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 50000, dstPort: 80, payload: []byte(req2)},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 50000, payload: []byte(resp1)},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 50000, payload: []byte(resp2)},
	}
	writePcapFile(t, pcapPath, packets)

	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(txs) != 2 {
		t.Fatalf("expected 2 transactions (keep-alive), got %d", len(txs))
	}

	// 第一事务
	if txs[0].Method != "GET" || txs[0].RequestURI != "/api/version" {
		t.Fatalf("tx1: method=%q URI=%q", txs[0].Method, txs[0].RequestURI)
	}
	if txs[0].TxSeq != 1 {
		t.Fatalf("tx1: expected TxSeq=1, got %d", txs[0].TxSeq)
	}
	if string(txs[0].ResponseBody) != "{}" {
		t.Fatalf("tx1: expected response body '{}', got %q", txs[0].ResponseBody)
	}

	// 第二事务
	if txs[1].Method != "GET" || txs[1].RequestURI != "/firmware.bin" {
		t.Fatalf("tx2: method=%q URI=%q", txs[1].Method, txs[1].RequestURI)
	}
	if txs[1].TxSeq != 2 {
		t.Fatalf("tx2: expected TxSeq=2, got %d", txs[1].TxSeq)
	}
	if string(txs[1].ResponseBody) != "FW!!" {
		t.Fatalf("tx2: expected response body 'FW!!', got %q", txs[1].ResponseBody)
	}
}

func TestReassembleHTTPTransactions_OutOfOrderAndGapArePartial(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "partial.pcap")
	request := []byte("GET /firmware.bin HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nFW!!")
	packets := []pcapPacket{
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 50001, dstPort: 80, payload: request},
		// 服务端故意从 seq+10 开始，模拟缺段。
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 50001, payload: response[10:], seq: 2010},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 50001, payload: response[:10], seq: 1000},
	}
	writePcapFile(t, pcapPath, packets)
	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(txs) != 1 || !txs[0].PartialPayload {
		t.Fatalf("expected one partial transaction, got %#v", txs)
	}
}

func TestReassembleHTTPTransactions_ChunkedResponse(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "chunked.pcap")

	req := "GET /data HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"4\r\nWiki\r\n" +
		"5\r\npedia\r\n" +
		"0\r\n\r\n"

	packets := []pcapPacket{
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 40000, dstPort: 80, payload: []byte(req)},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 40000, payload: []byte(resp)},
	}
	writePcapFile(t, pcapPath, packets)

	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
	if string(txs[0].ResponseBody) != "Wikipedia" {
		t.Fatalf("expected chunked body 'Wikipedia', got %q", txs[0].ResponseBody)
	}
}

func TestReassembleHTTPTransactions_EmptyBody(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "empty.pcap")

	req := "POST /notify HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	resp := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"

	packets := []pcapPacket{
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 33333, dstPort: 80, payload: []byte(req)},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 33333, payload: []byte(resp)},
	}
	writePcapFile(t, pcapPath, packets)

	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
	if len(txs[0].RequestBody) != 0 {
		t.Fatalf("expected empty request body, got %d bytes", len(txs[0].RequestBody))
	}
	if len(txs[0].ResponseBody) != 0 {
		t.Fatalf("expected empty response body, got %d bytes", len(txs[0].ResponseBody))
	}
	if txs[0].StatusCode != 204 {
		t.Fatalf("expected status 204, got %d", txs[0].StatusCode)
	}
}

func TestReassembleHTTPTransactions_MalformedHTTP(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "malformed.pcap")

	// 畸形 HTTP：不以合法 HTTP 请求行/状态行开头
	packets := []pcapPacket{
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 9999, dstPort: 80, payload: []byte("NOT HTTP\r\n\r\n")},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 9999, payload: []byte("ALSO NOT HTTP\r\n\r\n")},
	}
	writePcapFile(t, pcapPath, packets)

	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble should not error on malformed HTTP: %v", err)
	}
	// 畸形数据不应产生有效事务
	if len(txs) != 0 {
		t.Fatalf("expected 0 transactions for malformed HTTP, got %d", len(txs))
	}
}

func TestReassembleHTTPTransactions_GzipContentEncoding(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "gzip.pcap")

	// 响应是 gzip 编码的 JSON
	originalJSON := `{"version":"1.2.3","update_required":true}`
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	gw.Write([]byte(originalJSON))
	gw.Close()

	req := "GET /api/check HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " +
		itoa(compressed.Len()) + "\r\n\r\n" + compressed.String()

	packets := []pcapPacket{
		{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 44444, dstPort: 80, payload: []byte(req)},
		{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 80, dstPort: 44444, payload: []byte(resp)},
	}
	writePcapFile(t, pcapPath, packets)

	txs, err := reassembleHTTPTransactions(pcapPath)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
	// ResponseBody 是传输解码后的实体正文（含 gzip 编码，未做内容解码）
	// 内容解码由 behavior_analysis.go 负责
	if !bytes.Equal(txs[0].ResponseBody, compressed.Bytes()) {
		t.Fatalf("response body should be gzip-compressed data, got %d bytes", len(txs[0].ResponseBody))
	}
	if txs[0].ResponseHeaders["content-encoding"] != "gzip" {
		t.Fatalf("expected content-encoding=gzip, got %q", txs[0].ResponseHeaders["content-encoding"])
	}
}

func TestIsHTTPRequest(t *testing.T) {
	tests := []struct {
		data string
		want bool
	}{
		{"GET / HTTP/1.1\r\n", true},
		{"POST /api HTTP/1.1\r\n", true},
		{"PUT /data HTTP/1.1\r\n", true},
		{"HEAD / HTTP/1.1\r\n", true},
		{"DELETE / HTTP/1.1\r\n", true},
		{"HTTP/1.1 200 OK\r\n", false},
		{"GARBAGE", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isHTTPRequest([]byte(tc.data))
		if got != tc.want {
			t.Fatalf("isHTTPRequest(%q) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

func TestIsHTTPResponse(t *testing.T) {
	tests := []struct {
		data string
		want bool
	}{
		{"HTTP/1.1 200 OK\r\n", true},
		{"HTTP/1.0 404 Not Found\r\n", true},
		{"GET / HTTP/1.1\r\n", false},
		{"GARBAGE", false},
	}
	for _, tc := range tests {
		got := isHTTPResponse([]byte(tc.data))
		if got != tc.want {
			t.Fatalf("isHTTPResponse(%q) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

// --- 辅助函数 ---

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
