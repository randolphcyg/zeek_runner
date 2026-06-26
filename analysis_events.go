package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

const analysisEventsTopic = "zeek_detection_events"

const (
	eventVersion = "1.0"
	producerName = "zeek_runner"
)

type zeekLogStats struct {
	NoticeCount int `json:"noticeCount"`
	IntelCount  int `json:"intelCount"`
}

type analysisSubtaskHitEvent struct {
	EventID      string `json:"eventID"`
	EventType    string `json:"eventType"`
	EventVersion string `json:"eventVersion"`
	EventTime    string `json:"eventTime"`
	Producer     string `json:"producer"`
	AnalysisMode string `json:"analysisMode"`
	TaskID       string `json:"taskID"`
	UUID         string `json:"uuid"`
	PcapID       string `json:"pcapID"`
	PcapPath     string `json:"pcapPath"`
	ScriptID     string `json:"scriptID"`
	ScriptPath   string `json:"scriptPath"`
	Verdict      string `json:"verdict"`
	SourceType   string `json:"sourceType"`
	RuleType     string `json:"ruleType"`
	RuleName     string `json:"ruleName"`
	Message      string `json:"message"`
	Indicator    string `json:"indicator"`
	SrcIp        string `json:"srcIp"`
	SrcPort      int    `json:"srcPort"`
	DstIp        string `json:"dstIp"`
	DstPort      int    `json:"dstPort"`
	Proto        string `json:"proto"`
	UID          string `json:"uid"`
}

type analysisSubtaskEvent struct {
	EventID      string `json:"eventID"`
	EventType    string `json:"eventType"`
	EventVersion string `json:"eventVersion"`
	EventTime    string `json:"eventTime"`
	Producer     string `json:"producer"`
	AnalysisMode string `json:"analysisMode"`
	TaskID       string `json:"taskID"`
	UUID         string `json:"uuid"`
	PcapID       string `json:"pcapID"`
	PcapPath     string `json:"pcapPath"`
	ScriptID     string `json:"scriptID"`
	ScriptPath   string `json:"scriptPath"`
	Status       string `json:"status"`
	Verdict      string `json:"verdict"`
	HitCount     int    `json:"hitCount"`
	NoticeCount  int    `json:"noticeCount"`
	IntelCount   int    `json:"intelCount"`
	DurationMs   int64  `json:"durationMs"`
	Error        string `json:"error,omitempty"`
}

type analysisParentEvent struct {
	EventID      string `json:"eventID"`
	EventType    string `json:"eventType"`
	EventVersion string `json:"eventVersion"`
	EventTime    string `json:"eventTime"`
	Producer     string `json:"producer"`
	AnalysisMode string `json:"analysisMode"`
	TaskID       string `json:"taskID"`
	UUID         string `json:"uuid"`
	PcapID       string `json:"pcapID"`
	PcapPath     string `json:"pcapPath"`
	ScriptID     string `json:"scriptID"`
	ScriptPath   string `json:"scriptPath"`
	Status       string `json:"status"`
	Verdict      string `json:"verdict"`
	TotalCount   int    `json:"totalCount"`
	SuccessCount int    `json:"successCount"`
	FailedCount  int    `json:"failedCount"`
	TimeoutCount int    `json:"timeoutCount"`
	HitCount     int    `json:"hitCount"`
	NoticeCount  int    `json:"noticeCount"`
	IntelCount   int    `json:"intelCount"`
}

type analysisEventPublisher struct {
	writer    *kafka.Writer
	brokers   string
	topic     string
	dialer    *kafka.Dialer
	publishFn func(context.Context, string, string, any) error
}

func newAnalysisEventPublisher(brokers string, dialer *kafka.Dialer) *analysisEventPublisher {
	writer := newKafkaJSONWriter(brokers, analysisEventsTopic, dialer)
	if writer == nil {
		return nil
	}

	return &analysisEventPublisher{
		writer:  writer,
		brokers: brokers,
		topic:   analysisEventsTopic,
		dialer:  dialer,
	}
}

func (p *analysisEventPublisher) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

func (p *analysisEventPublisher) Publish(ctx context.Context, key string, eventType string, payload any) error {
	if p == nil {
		return nil
	}
	if p.publishFn != nil {
		return p.publishFn(ctx, key, eventType, payload)
	}
	if p.writer == nil {
		return nil
	}

	value, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return writeKafkaMessage(ctx, p.writer, p.brokers, p.topic, kafka.Message{
		Key:   []byte(key),
		Value: value,
		Headers: []kafka.Header{
			{Key: "eventType", Value: []byte(eventType)},
			{Key: "eventVersion", Value: []byte(eventVersion)},
			{Key: "analysisMode", Value: []byte("offline")},
			{Key: "producer", Value: []byte(producerName)},
		},
	}, p.dialer)
}

func stableEventID(parts ...string) string {
	hasher := sha256.New()
	for _, part := range parts {
		_, _ = hasher.Write([]byte(part))
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func countZeekLogRows(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	return count
}

func collectZeekLogStats(workDir string) zeekLogStats {
	return zeekLogStats{
		NoticeCount: countZeekLogRows(filepath.Join(workDir, "notice.log")),
		IntelCount:  countZeekLogRows(filepath.Join(workDir, "intel.log")),
	}
}

func deriveSubtaskVerdict(stats zeekLogStats, err error) string {
	if err != nil {
		return "error"
	}
	if stats.NoticeCount+stats.IntelCount > 0 {
		return "malicious"
	}
	return "clean"
}

type zeekLogRecord map[string]string

func parseZeekTSVLog(path string) ([]zeekLogRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var fields []string
	var records []zeekLogRecord

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#fields\t") {
			fields = strings.Split(strings.TrimPrefix(line, "#fields\t"), "\t")
			continue
		}
		if strings.HasPrefix(line, "#") || len(fields) == 0 {
			continue
		}

		values := strings.Split(line, "\t")
		record := make(zeekLogRecord, len(fields))
		for i, field := range fields {
			if i < len(values) {
				record[field] = values[i]
			}
		}
		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func parsePort(value string) int {
	if value == "" || value == "-" {
		return 0
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return port
}

func recordValue(record zeekLogRecord, keys ...string) string {
	for _, key := range keys {
		if value := record[key]; value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func parseNoticeLog(path string) ([]analysisSubtaskHitEvent, error) {
	records, err := parseZeekTSVLog(path)
	if err != nil {
		return nil, err
	}

	hits := make([]analysisSubtaskHitEvent, 0, len(records))
	for _, record := range records {
		hits = append(hits, analysisSubtaskHitEvent{
			SourceType: "notice",
			RuleType:   recordValue(record, "note"),
			RuleName:   recordValue(record, "note"),
			Message:    recordValue(record, "msg"),
			Indicator:  recordValue(record, "sub"),
			SrcIp:      recordValue(record, "id.orig_h"),
			SrcPort:    parsePort(recordValue(record, "id.orig_p")),
			DstIp:      recordValue(record, "id.resp_h"),
			DstPort:    parsePort(recordValue(record, "id.resp_p")),
			Proto:      recordValue(record, "proto"),
			UID:        recordValue(record, "uid"),
		})
	}
	return hits, nil
}

func parseIntelLog(path string) ([]analysisSubtaskHitEvent, error) {
	records, err := parseZeekTSVLog(path)
	if err != nil {
		return nil, err
	}

	hits := make([]analysisSubtaskHitEvent, 0, len(records))
	for _, record := range records {
		indicator := recordValue(record, "indicator", "seen.indicator")
		where := recordValue(record, "where", "seen.where")
		hits = append(hits, analysisSubtaskHitEvent{
			SourceType: "intel",
			RuleType:   where,
			RuleName:   "intel",
			Message:    fmt.Sprintf("Intel hit on %s", indicator),
			Indicator:  indicator,
			SrcIp:      recordValue(record, "id.orig_h"),
			SrcPort:    parsePort(recordValue(record, "id.orig_p")),
			DstIp:      recordValue(record, "id.resp_h"),
			DstPort:    parsePort(recordValue(record, "id.resp_p")),
			Proto:      recordValue(record, "proto"),
		})
	}
	return hits, nil
}

func (s *Service) publishSubtaskHitEvents(ctx context.Context, opts zeekRunOptions, workDir string) error {
	if s == nil || s.analysisPublisher == nil || opts.taskType != string(offlineTaskScan) {
		return nil
	}

	noticeHits, err := parseNoticeLog(filepath.Join(workDir, "notice.log"))
	if err != nil {
		return err
	}
	intelHits, err := parseIntelLog(filepath.Join(workDir, "intel.log"))
	if err != nil {
		return err
	}

	// Collect all hits for Redis storage
	var redisHits []TaskHitEvent

	publish := func(hit analysisSubtaskHitEvent) error {
		hit.EventID = stableEventID(
			"subtask_hit",
			opts.taskID,
			opts.uuid,
			hit.SourceType,
			hit.RuleType,
			hit.Indicator,
			hit.UID,
			hit.SrcIp,
			strconv.Itoa(hit.SrcPort),
			hit.DstIp,
			strconv.Itoa(hit.DstPort),
			hit.Proto,
			hit.Message,
		)
		hit.EventType = "subtask_hit"
		hit.EventVersion = eventVersion
		hit.EventTime = time.Now().Format(time.RFC3339)
		hit.Producer = producerName
		hit.AnalysisMode = "offline"
		hit.TaskID = opts.taskID
		hit.UUID = opts.uuid
		hit.PcapID = opts.pcapID
		hit.PcapPath = opts.pcapPath
		hit.ScriptID = opts.scriptID
		hit.ScriptPath = opts.scriptPath
		hit.Verdict = "malicious"

		// Collect for Redis storage
		redisHits = append(redisHits, TaskHitEvent{
			EventID:    hit.EventID,
			EventType:  hit.EventType,
			EventTime:  hit.EventTime,
			TaskID:     hit.TaskID,
			UUID:       hit.UUID,
			PcapID:     hit.PcapID,
			PcapPath:   hit.PcapPath,
			ScriptID:   hit.ScriptID,
			ScriptPath: hit.ScriptPath,
			Verdict:    hit.Verdict,
			SourceType: hit.SourceType,
			RuleType:   hit.RuleType,
			RuleName:   hit.RuleName,
			Message:    hit.Message,
			Indicator:  hit.Indicator,
			SrcIp:      hit.SrcIp,
			SrcPort:    hit.SrcPort,
			DstIp:      hit.DstIp,
			DstPort:    hit.DstPort,
			Proto:      hit.Proto,
			UID:        hit.UID,
		})

		return s.publishAnalysisEvent(ctx, opts.taskID, "subtask_hit", hit)
	}

	for _, hit := range noticeHits {
		if err := publish(hit); err != nil {
			return err
		}
	}
	for _, hit := range intelHits {
		if err := publish(hit); err != nil {
			return err
		}
	}

	// Store hits in Redis for later querying via MCP
	if s.taskManager != nil && len(redisHits) > 0 {
		if err := s.taskManager.SaveTaskHits(ctx, opts.uuid, opts.taskID, redisHits); err != nil {
			slog.Warn("failed to save task hits to Redis", "uuid", opts.uuid, "err", err)
		}
	}

	return nil
}

func deriveParentVerdict(status *ParentTaskStatus) string {
	if status == nil {
		return "error"
	}
	if status.HitCount > 0 {
		return "malicious"
	}
	if status.FailedCount > 0 || status.TimeoutCount > 0 {
		return "error"
	}
	return "clean"
}

func (s *Service) publishSubtaskEvent(ctx context.Context, opts zeekRunOptions, stats zeekLogStats, duration time.Duration, runErr error) {
	if s == nil || s.analysisPublisher == nil || opts.taskType != string(offlineTaskScan) {
		return
	}

	status := "success"
	eventType := "subtask_completed"
	errText := ""
	if runErr != nil {
		status = "failed"
		eventType = "subtask_failed"
		errText = runErr.Error()
	}

	payload := analysisSubtaskEvent{
		EventID:      stableEventID(eventType, opts.taskID, opts.uuid),
		EventType:    eventType,
		EventVersion: eventVersion,
		EventTime:    time.Now().Format(time.RFC3339),
		Producer:     producerName,
		AnalysisMode: "offline",
		TaskID:       opts.taskID,
		UUID:         opts.uuid,
		PcapID:       opts.pcapID,
		PcapPath:     opts.pcapPath,
		ScriptID:     opts.scriptID,
		ScriptPath:   opts.scriptPath,
		Status:       status,
		Verdict:      deriveSubtaskVerdict(stats, runErr),
		HitCount:     stats.NoticeCount + stats.IntelCount,
		NoticeCount:  stats.NoticeCount,
		IntelCount:   stats.IntelCount,
		DurationMs:   duration.Milliseconds(),
		Error:        errText,
	}

	_ = s.publishAnalysisEvent(ctx, opts.taskID, eventType, payload)
}

func normalizeParentEventStatus(status *ParentTaskStatus) string {
	if status == nil {
		return "failed"
	}
	if status.TimeoutCount == status.TotalCount && status.TotalCount > 0 {
		return "timeout"
	}
	if status.FailedCount == status.TotalCount && status.TotalCount > 0 {
		return "failed"
	}
	if status.FailedCount > 0 || status.TimeoutCount > 0 {
		return "partial_failed"
	}
	return "success"
}

func shouldPublishParentAnalysisEvent(status *ParentTaskStatus) bool {
	if status == nil || len(status.SubTasks) == 0 {
		return true
	}

	hasTask := false
	for _, task := range status.SubTasks {
		if task == nil {
			continue
		}
		hasTask = true
		if task.OutputDir == "" && task.ScriptID != extractTaskScriptID {
			return true
		}
	}
	return !hasTask
}

func (s *Service) publishParentEventIfReady(ctx context.Context, taskID string) {
	if s == nil || s.analysisPublisher == nil || s.taskManager == nil || taskID == "" {
		return
	}

	status, err := s.GetParentTaskStatus(ctx, taskID)
	if err != nil {
		return
	}
	if status.PendingCount > 0 || status.RunningCount > 0 {
		return
	}

	if !shouldPublishParentAnalysisEvent(status) {
		_, _ = s.taskManager.MarkParentEventPublished(ctx, taskID)
		slog.Debug("skip parent analysis event for file extract task", "taskID", taskID)
		return
	}

	ok, err := s.taskManager.MarkParentEventPublished(ctx, taskID)
	if err != nil || !ok {
		return
	}

	eventType := "parent_completed"
	if status.FailedCount == status.TotalCount && status.TotalCount > 0 {
		eventType = "parent_failed"
	}

	payload := analysisParentEvent{
		EventID:      stableEventID(eventType, taskID),
		EventType:    eventType,
		EventVersion: eventVersion,
		EventTime:    time.Now().Format(time.RFC3339),
		Producer:     producerName,
		AnalysisMode: "offline",
		TaskID:       taskID,
		UUID:         "",
		PcapID:       status.PcapID,
		PcapPath:     status.PcapPath,
		ScriptID:     "",
		ScriptPath:   "",
		Status:       normalizeParentEventStatus(status),
		Verdict:      deriveParentVerdict(status),
		TotalCount:   status.TotalCount,
		SuccessCount: status.SuccessCount,
		FailedCount:  status.FailedCount,
		TimeoutCount: status.TimeoutCount,
		HitCount:     status.HitCount,
		NoticeCount:  status.NoticeCount,
		IntelCount:   status.IntelCount,
	}

	_ = s.publishAnalysisEvent(ctx, taskID, eventType, payload)
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}

	var errs []error
	if s.analysisPublisher != nil {
		errs = append(errs, s.analysisPublisher.Close())
	}
	if s.extractPublisher != nil {
		errs = append(errs, s.extractPublisher.Close())
	}
	if s.verificationPublisher != nil {
		errs = append(errs, s.verificationPublisher.Close())
	}

	return errors.Join(errs...)
}
