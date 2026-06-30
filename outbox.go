package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const kafkaOutboxKey = "zeek:kafka_outbox"

type kafkaOutboxEvent struct {
	ID        string          `json:"id"`
	Publisher string          `json:"publisher"`
	Key       string          `json:"key"`
	EventType string          `json:"eventType"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"createdAt"`
}

type kafkaEventPublisher interface {
	Publish(ctx context.Context, key string, eventType string, payload any) error
}

func (s *Service) publishAnalysisEvent(ctx context.Context, key, eventType string, payload any) error {
	return s.publishKafkaEvent(ctx, "analysis", s.analysisPublisher, key, eventType, payload)
}

func (s *Service) publishExtractEvent(ctx context.Context, key, eventType string, payload any) error {
	return s.publishKafkaEvent(ctx, "extract", s.extractPublisher, key, eventType, payload)
}

func (s *Service) publishVerificationEvent(ctx context.Context, key, eventType string, payload any) error {
	return s.publishKafkaEvent(ctx, "verification", s.verificationPublisher, key, eventType, payload)
}

func (s *Service) publishKafkaEvent(ctx context.Context, publisherName string, publisher kafkaEventPublisher, key, eventType string, payload any) error {
	if s == nil || publisher == nil {
		return nil
	}
	err := publisher.Publish(ctx, key, eventType, payload)
	if err == nil {
		return nil
	}
	if s.taskManager == nil || s.taskManager.redis == nil {
		return err
	}
	raw, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return err
	}
	event := kafkaOutboxEvent{
		ID:        stableEventID("outbox", publisherName, key, eventType, string(raw)),
		Publisher: publisherName,
		Key:       key,
		EventType: eventType,
		Payload:   raw,
		CreatedAt: time.Now(),
	}
	data, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		return err
	}
	if pushErr := s.taskManager.redis.RPush(ctx, kafkaOutboxKey, data).Err(); pushErr != nil {
		return err
	}
	return nil
}

func (s *Service) StartKafkaOutboxFlusher(ctx context.Context) {
	if s == nil || s.taskManager == nil || s.taskManager.redis == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.flushKafkaOutbox(ctx, 100)
			}
		}
	}()
}

func (s *Service) flushKafkaOutbox(ctx context.Context, limit int) {
	for i := 0; i < limit; i++ {
		data, err := s.taskManager.redis.LPop(ctx, kafkaOutboxKey).Bytes()
		if err == redis.Nil {
			return
		}
		if err != nil {
			slog.Warn("kafka outbox pop failed", "err", err)
			return
		}
		var event kafkaOutboxEvent
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		publisher := s.outboxPublisher(event.Publisher)
		if publisher == nil {
			slog.Warn("kafka outbox publisher unavailable", "event", event.ID, "publisher", event.Publisher)
			_ = s.taskManager.redis.LPush(ctx, kafkaOutboxKey, data).Err()
			return
		}
		if err := publisher.Publish(ctx, event.Key, event.EventType, event.Payload); err != nil {
			_ = s.taskManager.redis.LPush(ctx, kafkaOutboxKey, data).Err()
			slog.Warn("kafka outbox flush failed", "event", event.ID, "err", err)
			return
		}
	}
}

func (s *Service) outboxPublisher(name string) kafkaEventPublisher {
	switch name {
	case "", "analysis":
		return s.analysisPublisher
	case "extract":
		return s.extractPublisher
	case "verification":
		return s.verificationPublisher
	default:
		return nil
	}
}

func (tm *TaskManager) OutboxLength(ctx context.Context) int64 {
	if tm == nil || tm.redis == nil {
		return 0
	}
	n, err := tm.redis.LLen(ctx, kafkaOutboxKey).Result()
	if err != nil {
		return 0
	}
	return n
}
