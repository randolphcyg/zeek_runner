package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

const verificationLogsTopic = "zeek_verification_logs"

type verificationLogEvent struct {
	EventID      string        `json:"eventID"`
	EventVersion string        `json:"eventVersion"`
	EventTime    string        `json:"eventTime"`
	Producer     string        `json:"producer"`
	TaskID       string        `json:"taskID"`
	UUID         string        `json:"uuid"`
	PcapID       string        `json:"pcapID"`
	PcapPath     string        `json:"pcapPath"`
	ScriptID     string        `json:"scriptID"`
	ScriptPath   string        `json:"scriptPath"`
	LogType      string        `json:"logType"`
	Content      zeekLogRecord `json:"content"`
}

type verificationLogPublisher struct {
	writer    *kafka.Writer
	brokers   string
	topic     string
	dialer    *kafka.Dialer
	publishFn func(context.Context, string, string, any) error
}

func newVerificationLogPublisher(brokers string, dialer *kafka.Dialer) *verificationLogPublisher {
	writer := newKafkaJSONWriter(brokers, verificationLogsTopic, dialer)
	if writer == nil {
		return nil
	}

	return &verificationLogPublisher{
		writer:  writer,
		brokers: brokers,
		topic:   verificationLogsTopic,
		dialer:  dialer,
	}
}

func (p *verificationLogPublisher) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

func (p *verificationLogPublisher) Publish(ctx context.Context, key string, eventType string, payload any) error {
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
			{Key: "producer", Value: []byte(producerName)},
		},
	}, p.dialer)
}

func (s *Service) publishVerificationLogEvents(ctx context.Context, opts zeekRunOptions, workDir string) error {
	if s == nil || s.verificationPublisher == nil || opts.taskType != string(offlineTaskScan) || opts.onlyNotice {
		return nil
	}

	entries, err := os.ReadDir(workDir)
	if err != nil {
		return fmt.Errorf("read zeek work dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") || entry.Name() == "task_status.log" {
			continue
		}

		logType := strings.TrimSuffix(entry.Name(), ".log")
		records, err := parseZeekTSVLog(filepath.Join(workDir, entry.Name()))
		if err != nil {
			return err
		}

		for index, record := range records {
			recordJSON, err := json.Marshal(record)
			if err != nil {
				return err
			}

			event := verificationLogEvent{
				EventID: stableEventID(
					"verification_log",
					opts.taskID,
					opts.uuid,
					logType,
					strconv.Itoa(index),
					string(recordJSON),
				),
				EventVersion: eventVersion,
				EventTime:    time.Now().Format(time.RFC3339),
				Producer:     producerName,
				TaskID:       opts.taskID,
				UUID:         opts.uuid,
				PcapID:       opts.pcapID,
				PcapPath:     opts.pcapPath,
				ScriptID:     opts.scriptID,
				ScriptPath:   opts.scriptPath,
				LogType:      logType,
				Content:      record,
			}

			if err := s.publishVerificationEvent(ctx, opts.uuid, "verification_log", event); err != nil {
				return err
			}
		}
	}

	return nil
}
