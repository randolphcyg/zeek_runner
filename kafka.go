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
	"github.com/segmentio/kafka-go/sasl/plain"
)

// newKafkaDialer 根据认证配置创建 Kafka Dialer；mechanism 为空则返回默认 Dialer（无认证）
func newKafkaDialer(mechanism, username, password string) *kafka.Dialer {
	dialer := &kafka.Dialer{
		Timeout:   5 * time.Second,
		DualStack: true,
	}
	if mechanism != "" {
		switch strings.ToUpper(mechanism) {
		case "PLAIN":
			dialer.SASLMechanism = plain.Mechanism{
				Username: username,
				Password: password,
			}
			slog.Info("Kafka SASL/PLAIN 认证已启用", "username", username)
		default:
			slog.Error("不支持的 Kafka SASL 机制，忽略认证配置", "mechanism", mechanism)
		}
	}
	return dialer
}

type KafkaChecker struct {
	brokers string
	dialer  *kafka.Dialer
}

func NewKafkaChecker(brokers string, dialer *kafka.Dialer) *KafkaChecker {
	return &KafkaChecker{brokers: brokers, dialer: dialer}
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

func newKafkaJSONWriter(brokers string, topic string, dialer *kafka.Dialer) *kafka.Writer {
	parts := splitKafkaBrokers(brokers)
	if len(parts) == 0 {
		return nil
	}

	return &kafka.Writer{
		Addr:         kafka.TCP(parts...),
		Topic:        topic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
		BatchTimeout: 10 * time.Millisecond,
		Transport:    &kafka.Transport{SASL: dialer.SASLMechanism},
	}
}

func isUnknownTopicOrPartition(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "Unknown Topic Or Partition")
}

func ensureKafkaTopic(ctx context.Context, brokers string, topic string, dialer *kafka.Dialer) error {
	parts := splitKafkaBrokers(brokers)
	if len(parts) == 0 {
		return nil
	}

	conn, err := dialer.DialContext(ctx, "tcp", parts[0])
	if err != nil {
		return err
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		return err
	}

	controllerAddr := net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port))
	controllerConn, err := dialer.DialContext(ctx, "tcp", controllerAddr)
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

func writeKafkaMessage(ctx context.Context, writer *kafka.Writer, brokers string, topic string, msg kafka.Message, dialer *kafka.Dialer) error {
	if writer == nil {
		return nil
	}

	var lastErr error
	for attempt := 1; attempt <= 12; attempt++ {
		err := writer.WriteMessages(ctx, msg)
		if err == nil {
			return nil
		}

		if isUnknownTopicOrPartition(err) {
			if ensureErr := ensureKafkaTopic(ctx, brokers, topic, dialer); ensureErr != nil {
				lastErr = errors.Join(err, ensureErr)
			} else {
				lastErr = err
			}

			for range 5 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(300 * time.Millisecond):
				}

				lastErr = writer.WriteMessages(ctx, msg)
				if lastErr == nil {
					return nil
				}
				if !isUnknownTopicOrPartition(lastErr) {
					break
				}
			}
		} else {
			lastErr = err
		}

		if attempt == 12 {
			return lastErr
		}

		delay := time.Duration(attempt) * 500 * time.Millisecond
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
		slog.Warn("Kafka write failed, retrying",
			"topic", topic,
			"attempt", attempt,
			"delay", delay.String(),
			"err", lastErr,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
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

		var lastErr error
		for _, broker := range splitKafkaBrokers(k.brokers) {
			conn, err := k.dialer.DialContext(dialCtx, "tcp", broker)
			if err != nil {
				lastErr = err
				continue
			}
			conn.Close()
			onStatusChange(true)
			return
		}

		onStatusChange(false)
		slog.Warn("Kafka unreachable", "err", lastErr)
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
