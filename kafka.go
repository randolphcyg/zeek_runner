package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/segmentio/kafka-go"
)

type KafkaChecker struct {
	brokers string
}

func NewKafkaChecker(brokers string) *KafkaChecker {
	return &KafkaChecker{brokers: brokers}
}

func (k *KafkaChecker) Start(ctx context.Context, onStatusChange func(bool)) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	check := func() {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := kafka.DialContext(dialCtx, "tcp", k.brokers)
		if err != nil {
			onStatusChange(false)
			slog.Warn("Kafka unreachable", "err", err)
		} else {
			conn.Close()
			onStatusChange(true)
		}
	}

	check()
	for {
		select {
		case <-ticker.C:
			check()
		case <-ctx.Done():
			return
		}
	}
}
