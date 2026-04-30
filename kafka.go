package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

type KafkaChecker struct {
	brokers string
}

func NewKafkaChecker(brokers string) *KafkaChecker {
	return &KafkaChecker{brokers: brokers}
}

func splitKafkaBrokers(brokers string) []string {
	parts := make([]string, 0, 4)
	for _, broker := range strings.Split(brokers, ",") {
		broker = strings.TrimSpace(broker)
		if broker != "" {
			parts = append(parts, broker)
		}
	}
	return parts
}

func newKafkaJSONWriter(brokers string, topic string) *kafka.Writer {
	parts := splitKafkaBrokers(brokers)
	if len(parts) == 0 {
		return nil
	}

	return &kafka.Writer{
		Addr:         kafka.TCP(parts...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireOne,
		BatchTimeout: 10 * time.Millisecond,
	}
}

func isUnknownTopicOrPartition(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "Unknown Topic Or Partition")
}

func ensureKafkaTopic(ctx context.Context, brokers string, topic string) error {
	parts := splitKafkaBrokers(brokers)
	if len(parts) == 0 {
		return nil
	}

	conn, err := kafka.DialContext(ctx, "tcp", parts[0])
	if err != nil {
		return err
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		return err
	}

	controllerAddr := net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port))
	controllerConn, err := kafka.DialContext(ctx, "tcp", controllerAddr)
	if err != nil {
		return err
	}
	defer controllerConn.Close()

	err = controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

func writeKafkaMessage(ctx context.Context, writer *kafka.Writer, brokers string, topic string, msg kafka.Message) error {
	if writer == nil {
		return nil
	}

	err := writer.WriteMessages(ctx, msg)
	if !isUnknownTopicOrPartition(err) {
		return err
	}

	if ensureErr := ensureKafkaTopic(ctx, brokers, topic); ensureErr != nil {
		return errors.Join(err, ensureErr)
	}

	lastErr := err
	for range 5 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}

		lastErr = writer.WriteMessages(ctx, msg)
		if !isUnknownTopicOrPartition(lastErr) {
			return lastErr
		}
	}

	return lastErr
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
