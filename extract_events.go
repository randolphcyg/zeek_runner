package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

const extractEventsTopic = "zeek_extract_events"

type extractTaskSummary struct {
	FileCount          int `json:"fileCount"`
	UniqueFileCount    int `json:"uniqueFileCount"`
	DuplicateFileCount int `json:"duplicateFileCount"`
}

type extractFileEvent struct {
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
	OutputDir    string `json:"outputDir"`
	FUID         string `json:"fuid"`
	FileName     string `json:"fileName"`
	OriginalFileName string `json:"originalFileName"`
	FilePath     string `json:"filePath"`
	FileSize     int64  `json:"fileSize"`
	SHA256       string `json:"sha256"`
	MimeType     string `json:"mimeType"`
	RefCount     int    `json:"refCount"`
}

type extractTaskEvent struct {
	EventType          string `json:"eventType"`
	EventVersion       string `json:"eventVersion"`
	EventTime          string `json:"eventTime"`
	Producer           string `json:"producer"`
	AnalysisMode       string `json:"analysisMode"`
	TaskID             string `json:"taskID"`
	UUID               string `json:"uuid"`
	PcapID             string `json:"pcapID"`
	PcapPath           string `json:"pcapPath"`
	ScriptID           string `json:"scriptID"`
	ScriptPath         string `json:"scriptPath"`
	OutputDir          string `json:"outputDir"`
	Status             string `json:"status"`
	FileCount          int    `json:"fileCount"`
	UniqueFileCount    int    `json:"uniqueFileCount"`
	DuplicateFileCount int    `json:"duplicateFileCount"`
	CompletedAt        string `json:"completedAt"`
	Error              string `json:"error,omitempty"`
}

type extractEventPublisher struct {
	writer    *kafka.Writer
	brokers   string
	topic     string
	publishFn func(context.Context, string, string, any) error
}

func newExtractEventPublisher(brokers string) *extractEventPublisher {
	writer := newKafkaJSONWriter(brokers, extractEventsTopic)
	if writer == nil {
		return nil
	}

	return &extractEventPublisher{
		writer:  writer,
		brokers: brokers,
		topic:   extractEventsTopic,
	}
}

func (p *extractEventPublisher) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

func (p *extractEventPublisher) Publish(ctx context.Context, key string, eventType string, payload any) error {
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
	})
}

func calculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func extractFUID(fileName string) string {
	idx := strings.Index(fileName, "-")
	if idx <= 0 {
		return ""
	}
	return fileName[:idx]
}

func extractOriginalFileName(fileName string) string {
	idx := strings.Index(fileName, "-")
	if idx <= 0 || idx+1 >= len(fileName) {
		return fileName
	}
	return fileName[idx+1:]
}

func newFallbackFileRecord(filePath string, pcapPath string, taskID string) (*FileRecord, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	hash, err := calculateFileSHA256(filePath)
	if err != nil {
		return nil, err
	}

	return &FileRecord{
		Hash:             hash,
		FilePath:         filePath,
		FileName:         filepath.Base(filePath),
		FUID:             extractFUID(filepath.Base(filePath)),
		OriginalFileName: extractOriginalFileName(filepath.Base(filePath)),
		FileSize:         fileInfo.Size(),
		FirstSeen:        time.Now(),
		RefCount:         1,
		SourceURL:        pcapPath,
		TaskID:           taskID,
	}, nil
}

func (s *Service) publishExtractFileEvent(ctx context.Context, opts zeekRunOptions, record *FileRecord) error {
	if s == nil || s.extractPublisher == nil || record == nil {
		return nil
	}

	eventType := "file_extracted"

	payload := extractFileEvent{
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
		OutputDir:    opts.outputDir,
		FUID:         record.FUID,
		FileName:     record.FileName,
		OriginalFileName: record.OriginalFileName,
		FilePath:     record.FilePath,
		FileSize:     record.FileSize,
		SHA256:       record.Hash,
		MimeType:     record.MimeType,
		RefCount:     record.RefCount,
	}

	return s.extractPublisher.Publish(ctx, opts.taskID, eventType, payload)
}

func (s *Service) publishExtractTaskEvent(ctx context.Context, opts zeekRunOptions, eventType string, status string, summary extractTaskSummary, eventErr error) error {
	if s == nil || s.extractPublisher == nil {
		return nil
	}

	payload := extractTaskEvent{
		EventType:          eventType,
		EventVersion:       eventVersion,
		EventTime:          time.Now().Format(time.RFC3339),
		Producer:           producerName,
		AnalysisMode:       "offline",
		TaskID:             opts.taskID,
		UUID:               opts.uuid,
		PcapID:             opts.pcapID,
		PcapPath:           opts.pcapPath,
		ScriptID:           opts.scriptID,
		ScriptPath:         opts.scriptPath,
		OutputDir:          opts.outputDir,
		Status:             status,
		FileCount:          summary.FileCount,
		UniqueFileCount:    summary.UniqueFileCount,
		DuplicateFileCount: summary.DuplicateFileCount,
		CompletedAt:        time.Now().Format(time.RFC3339),
	}
	if eventErr != nil {
		payload.Error = eventErr.Error()
	}

	return s.extractPublisher.Publish(ctx, opts.taskID, eventType, payload)
}

func (s *Service) processExtractedFiles(ctx context.Context, opts zeekRunOptions) (extractTaskSummary, error) {
	var summary extractTaskSummary

	entries, err := os.ReadDir(opts.outputDir)
	if err != nil {
		return summary, fmt.Errorf("read extracted dir: %w", err)
	}

	pcapBase := filepath.Base(opts.pcapPath)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if filename == pcapBase {
			continue
		}

		ext := strings.ToLower(filepath.Ext(filename))
		if ext == ".pcap" || ext == ".cap" || ext == ".pcapng" {
			continue
		}

		filePath := filepath.Join(opts.outputDir, filename)

		var (
			record      *FileRecord
			isDuplicate bool
		)

		if s.fileDedupMgr != nil {
			record, isDuplicate, err = s.fileDedupMgr.ProcessExtractedFile(ctx, filePath, opts.pcapPath, opts.taskID)
		} else {
			record, err = newFallbackFileRecord(filePath, opts.pcapPath, opts.taskID)
		}
		if err != nil {
			return summary, fmt.Errorf("process extracted file %s: %w", filename, err)
		}

		// 所有有效提取文件都计数
		summary.FileCount++

		if isDuplicate {
			// 重复文件：不发布事件，只记录日志和清理
			summary.DuplicateFileCount++
			LogTaskEvent("file_dedup", opts.taskID, opts.uuid,
				"file", filename,
				"hash", record.Hash[:16],
				"ref_count", record.RefCount,
			)
			// 如果文件路径不同，删除重复文件
			if filePath != record.FilePath {
				if rmErr := os.Remove(filePath); rmErr != nil {
					LogTaskError("cleanup_duplicate_failed", opts.taskID, opts.uuid, rmErr,
						"file_path", filePath,
					)
				}
			}
			continue
		}

		// 唯一文件：发布事件，更新统计
		summary.UniqueFileCount++

		if err := s.publishExtractFileEvent(ctx, opts, record); err != nil {
			return summary, fmt.Errorf("publish extracted file event %s: %w", filename, err)
		}

		LogTaskEvent("file_saved", opts.taskID, opts.uuid,
			"file", filename,
			"hash", record.Hash[:16],
			"size", record.FileSize,
		)
	}

	return summary, nil
}
