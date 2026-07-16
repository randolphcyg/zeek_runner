package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const urlObservedEventType = "url_observed"
const maxHTTPBodyURLScanBytes = 256 * 1024

var httpURLPattern = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)

type urlObservedEvent struct {
	EventType          string   `json:"eventType"`
	EventVersion       string   `json:"eventVersion"`
	EventTime          string   `json:"eventTime"`
	Producer           string   `json:"producer"`
	AnalysisMode       string   `json:"analysisMode"`
	TaskID             string   `json:"taskID"`
	UUID               string   `json:"uuid"`
	PcapID             string   `json:"pcapID"`
	PcapPath           string   `json:"pcapPath"`
	UID                string   `json:"uid"`
	TS                 string   `json:"ts"`
	Protocol           string   `json:"protocol"`
	Source             string   `json:"source"`
	SrcIP              string   `json:"srcIP"`
	SrcPort            int      `json:"srcPort"`
	DstIP              string   `json:"dstIP"`
	DstPort            int      `json:"dstPort"`
	Host               string   `json:"host"`
	URI                string   `json:"uri"`
	FullURL            string   `json:"fullURL"`
	Method             string   `json:"method"`
	StatusCode         int      `json:"statusCode"`
	ContentType        string   `json:"contentType"`
	ContentLength      int64    `json:"contentLength"`
	ContentDisposition string   `json:"contentDisposition"`
	HTTPTransDepth     int      `json:"httpTransDepth"`
	Filename           string   `json:"filename"`
	FUID               string   `json:"fuid"`
	MimeType           string   `json:"mimeType"`
	SNI                string   `json:"sni"`
	DNSQuery           string   `json:"dnsQuery"`
	DNSAnswers         []string `json:"dnsAnswers"`
	// Behavior 是采集侧行为识别结果（可选）。非空时消费侧直接持久化，不做本地 Classify。
	// 禁止将 requestBody、responseBody、解密正文或完整文件内容发送到 Kafka。
	Behavior *behaviorBlock `json:"behavior,omitempty"`
}

func makeFullURL(host, uri string) string {
	host = strings.TrimSpace(host)
	uri = strings.TrimSpace(uri)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return "http://" + host + uri
}

func parseInt64Field(value string) int64 {
	if value == "" || value == "-" {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parseIntField(value string) int {
	if value == "" || value == "-" {
		return 0
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

func parseZeekSet(value string) []string {
	if value == "" || value == "-" {
		return nil
	}
	value = strings.Trim(value, "[]")
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.Trim(part, `"`))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func filenameFromHTTPRecord(record zeekLogRecord) string {
	if value := recordValue(record, "filename"); value != "" {
		return filepath.Base(value)
	}
	uriValue := recordValue(record, "uri")
	if uriValue == "" {
		return ""
	}
	parsed, err := url.Parse(uriValue)
	if err != nil {
		return filepath.Base(strings.Split(uriValue, "?")[0])
	}
	return filepath.Base(parsed.Path)
}

func buildBaseURLEvent(opts zeekRunOptions, record zeekLogRecord, source string) urlObservedEvent {
	return urlObservedEvent{
		EventType:      urlObservedEventType,
		EventVersion:   eventVersion,
		EventTime:      time.Now().Format(time.RFC3339),
		Producer:       producerName,
		AnalysisMode:   "offline",
		TaskID:         opts.taskID,
		UUID:           opts.uuid,
		PcapID:         opts.pcapID,
		PcapPath:       opts.pcapPath,
		UID:            recordValue(record, "uid"),
		TS:             recordValue(record, "ts"),
		Source:         source,
		SrcIP:          recordValue(record, "id.orig_h"),
		SrcPort:        parseIntField(recordValue(record, "id.orig_p")),
		DstIP:          recordValue(record, "id.resp_h"),
		DstPort:        parseIntField(recordValue(record, "id.resp_p")),
		HTTPTransDepth: parseIntField(recordValue(record, "trans_depth")),
	}
}

func parseIPv4String(raw []byte) string {
	if len(raw) < 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3])
}

func firstHeaderValue(headers, name string) string {
	name = strings.ToLower(name) + ":"
	for _, line := range strings.Split(headers, "\r\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), name) {
			return strings.TrimSpace(line[len(name):])
		}
	}
	return ""
}

func collectHTTPResponseBodyURLEvents(opts zeekRunOptions) ([]urlObservedEvent, error) {
	file, err := os.Open(opts.pcapPath)
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

	type tcpStream struct {
		tsSec   uint32
		tsUsec  uint32
		srcIP   string
		dstIP   string
		srcPort int
		dstPort int
		data    []byte
	}
	streams := make(map[string]*tcpStream)
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
		key := fmt.Sprintf("%s:%d>%s:%d", srcIP, srcPort, dstIP, dstPort)
		stream := streams[key]
		if stream == nil {
			stream = &tcpStream{
				tsSec:   tsSec,
				tsUsec:  tsUsec,
				srcIP:   srcIP,
				dstIP:   dstIP,
				srcPort: srcPort,
				dstPort: dstPort,
			}
			streams[key] = stream
		}
		if len(stream.data) < maxHTTPBodyURLScanBytes+8192 {
			stream.data = append(stream.data, payload...)
		}
	}

	var events []urlObservedEvent
	seen := make(map[string]struct{})
	for _, stream := range streams {
		if !bytes.HasPrefix(stream.data, []byte("HTTP/")) {
			continue
		}
		headerEnd := bytes.Index(stream.data, []byte("\r\n\r\n"))
		if headerEnd < 0 {
			continue
		}
		headers := string(stream.data[:headerEnd])
		body := stream.data[headerEnd+4:]
		if len(body) > maxHTTPBodyURLScanBytes {
			body = body[:maxHTTPBodyURLScanBytes]
		}
		statusCode := 0
		statusParts := strings.SplitN(strings.SplitN(headers, "\r\n", 2)[0], " ", 3)
		if len(statusParts) > 1 {
			statusCode = parseIntField(statusParts[1])
		}
		for _, match := range httpURLPattern.FindAll(body, -1) {
			fullURL := strings.TrimRight(string(match), `"'<>),]}`)
			if fullURL == "" {
				continue
			}
			if _, ok := seen[fullURL]; ok {
				continue
			}
			seen[fullURL] = struct{}{}
			parsed, _ := url.Parse(fullURL)
			events = append(events, urlObservedEvent{
				EventType:     urlObservedEventType,
				EventVersion:  eventVersion,
				EventTime:     time.Now().Format(time.RFC3339),
				Producer:      producerName,
				AnalysisMode:  "offline",
				TaskID:        opts.taskID,
				UUID:          opts.uuid,
				PcapID:        opts.pcapID,
				PcapPath:      opts.pcapPath,
				TS:            fmt.Sprintf("%d.%06d", stream.tsSec, stream.tsUsec),
				Protocol:      "http",
				Source:        "http_response_body",
				SrcIP:         stream.srcIP,
				SrcPort:       stream.srcPort,
				DstIP:         stream.dstIP,
				DstPort:       stream.dstPort,
				Host:          parsed.Host,
				URI:           parsed.RequestURI(),
				FullURL:       fullURL,
				StatusCode:    statusCode,
				ContentType:   firstHeaderValue(headers, "Content-Type"),
				ContentLength: parseInt64Field(firstHeaderValue(headers, "Content-Length")),
			})
		}
	}
	return events, nil
}

func (s *Service) collectURLObservedEvents(opts zeekRunOptions, workDir string) ([]urlObservedEvent, error) {
	httpRecords, err := parseZeekTSVLog(filepath.Join(workDir, "http.log"))
	if err != nil {
		return nil, err
	}
	filesRecords, err := parseZeekTSVLog(filepath.Join(workDir, "files.log"))
	if err != nil {
		return nil, err
	}
	dnsRecords, err := parseZeekTSVLog(filepath.Join(workDir, "dns.log"))
	if err != nil {
		return nil, err
	}
	sslRecords, err := parseZeekTSVLog(filepath.Join(workDir, "ssl.log"))
	if err != nil {
		return nil, err
	}

	filesByUID := make(map[string][]zeekLogRecord)
	for _, record := range filesRecords {
		uid := recordValue(record, "uid")
		if uid != "" {
			filesByUID[uid] = append(filesByUID[uid], record)
		}
	}

	events := make([]urlObservedEvent, 0, len(httpRecords)+len(dnsRecords)+len(sslRecords))
	seen := make(map[string]struct{})
	add := func(event urlObservedEvent) {
		key := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s", event.PcapID, event.UID, event.HTTPTransDepth, event.Source, event.FullURL, event.SNI, event.DNSQuery)
		if event.FUID != "" {
			key += "|" + event.FUID
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		events = append(events, event)
	}

	// HTTP 请求/下载事件（来自 Zeek http.log）
	for _, record := range httpRecords {
		host := recordValue(record, "host")
		uri := recordValue(record, "uri")
		fullURL := makeFullURL(host, uri)
		if fullURL == "" {
			continue
		}

		requestEvent := buildBaseURLEvent(opts, record, "http_request")
		requestEvent.Protocol = "http"
		requestEvent.Host = host
		requestEvent.URI = uri
		requestEvent.FullURL = fullURL
		requestEvent.Method = recordValue(record, "method")
		requestEvent.StatusCode = parseIntField(recordValue(record, "status_code"))
		requestEvent.ContentType = strings.Join(parseZeekSet(recordValue(record, "resp_mime_types")), ",")
		requestEvent.ContentLength = parseInt64Field(recordValue(record, "response_body_len"))
		requestEvent.Filename = filenameFromHTTPRecord(record)
		if fuid := recordValue(record, "resp_fuids"); fuid != "" {
			requestEvent.FUID = strings.Split(fuid, ",")[0]
		}
		if filename := recordValue(record, "resp_filenames"); filename != "" {
			requestEvent.Filename = strings.Split(filename, ",")[0]
		}
		add(requestEvent)

		if requestEvent.ContentLength > 0 || requestEvent.ContentType != "" {
			downloadEvent := requestEvent
			downloadEvent.Source = "http_download"
			if fileRecords := filesByUID[requestEvent.UID]; len(fileRecords) > 0 {
				fileRecord := fileRecords[0]
				downloadEvent.FUID = recordValue(fileRecord, "fuid")
				downloadEvent.MimeType = recordValue(fileRecord, "mime_type")
				downloadEvent.Filename = recordValue(fileRecord, "filename")
				if downloadEvent.Filename == "" {
					downloadEvent.Filename = filenameFromHTTPRecord(record)
				}
				if size := parseInt64Field(recordValue(fileRecord, "total_bytes", "seen_bytes")); size > 0 {
					downloadEvent.ContentLength = size
				}
			}
			add(downloadEvent)
		}
	}

	// TLS SNI 事件（来自 Zeek ssl.log）
	for _, record := range sslRecords {
		sni := recordValue(record, "server_name")
		if sni == "" {
			continue
		}
		event := buildBaseURLEvent(opts, record, "tls_sni")
		event.Protocol = "tls"
		event.SNI = sni
		event.Host = sni
		add(event)
	}

	// DNS 事件（来自 Zeek dns.log）
	for _, record := range dnsRecords {
		query := recordValue(record, "query")
		if query == "" {
			continue
		}
		event := buildBaseURLEvent(opts, record, "dns_query")
		event.Protocol = "dns"
		event.DNSQuery = query
		event.Host = query
		event.DNSAnswers = parseZeekSet(recordValue(record, "answers"))
		add(event)
	}

	// HTTP 响应正文中内嵌的 URL 扫描事件
	bodyEvents, err := collectHTTPResponseBodyURLEvents(opts)
	if err != nil {
		return nil, err
	}
	for _, event := range bodyEvents {
		add(event)
	}

	// 行为识别：将行为块附加到 URL 事件
	s.attachBehaviorBlocks(events, opts)

	return events, nil
}

func (s *Service) publishURLObservedEvents(ctx context.Context, opts zeekRunOptions, workDir string) error {
	if s == nil {
		return nil
	}
	events, err := s.collectURLObservedEvents(opts, workDir)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := s.publishExtractEvent(ctx, opts.taskID, urlObservedEventType, event); err != nil {
			return err
		}
	}
	return nil
}
