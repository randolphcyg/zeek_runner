package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type instanceKey struct{}

func InitLogger(instanceID string) {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	logger := slog.New(handler).With("instance", instanceID)
	slog.SetDefault(logger)
}

func GetInstanceIDFromTaskManager(tm *TaskManager) string {
	if tm == nil {
		return generateInstanceID()
	}
	return tm.GetInstanceID()
}

func LogTaskEvent(event, taskID, uuid string, fields ...any) {
	args := []any{"event", event, "taskID", taskID}
	if uuid != "" {
		args = append(args, "uuid", uuid)
	}
	args = append(args, fields...)
	slog.Info("task", args...)
}

func LogTaskError(event, taskID, uuid string, err error, fields ...any) {
	args := []any{"event", event, "taskID", taskID}
	if uuid != "" {
		args = append(args, "uuid", uuid)
	}
	args = append(args, "err", err)
	args = append(args, fields...)
	slog.Error("task", args...)
}

func LogServiceEvent(event string, fields ...any) {
	args := []any{"event", event}
	args = append(args, fields...)
	slog.Info("service", args...)
}

func LogServiceError(event string, err error, fields ...any) {
	args := []any{"event", event, "err", err}
	args = append(args, fields...)
	slog.Error("service", args...)
}

func LogHTTPRequest(method, path, clientIP string, statusCode int, duration time.Duration, requestID string) {
	slog.Info("http_request",
		"event", "http_request",
		"method", method,
		"path", path,
		"client_ip", clientIP,
		"status", statusCode,
		"duration_ms", duration.Milliseconds(),
		"request_id", requestID,
	)
}

func LogHTTPError(method, path, clientIP string, statusCode int, duration time.Duration, requestID string, err error) {
	slog.Error("http_request",
		"event", "http_request",
		"method", method,
		"path", path,
		"client_ip", clientIP,
		"status", statusCode,
		"duration_ms", duration.Milliseconds(),
		"request_id", requestID,
		"err", err,
	)
}

func LogRedisOperation(op, key string, err error) {
	if err != nil && err != redis.Nil {
		slog.Error("redis",
			"event", "redis_op",
			"op", op,
			"key", key,
			"err", err,
		)
	} else {
		slog.Debug("redis",
			"event", "redis_op",
			"op", op,
			"key", key,
		)
	}
}

func LogConfigEvent(event string, fields ...any) {
	args := []any{"event", event}
	args = append(args, fields...)
	slog.Info("config", args...)
}

func LogStartupInfo(instanceID string, cfg *Config) {
	slog.Info("service_started",
		"event", "startup",
		"instance", instanceID,
		"pool_size", cfg.PoolSize,
		"zeek_timeout", cfg.ZeekTimeout,
		"rate_limit", cfg.RateLimit,
		"rate_limit_window", cfg.RateLimitWindow,
		"redis_addr", cfg.RedisAddr,
		"kafka_brokers", cfg.KafkaBrokers,
		"http_addr", cfg.ListenHTTP,
		"http_timeout", cfg.HTTPTimeout.String(),
		"grpc_addr", cfg.ListenGRPC,
		"grpc_timeout", cfg.GRPCTimeout.String(),
		"grpc_max_recv_msg_size", cfg.GRPCMaxRecvMsgSize,
		"grpc_max_send_msg_size", cfg.GRPCMaxSendMsgSize,
		"grpc_enable_reflection", cfg.GRPCEnableReflection,
		"grpc_enable_health_check", cfg.GRPCEnableHealthCheck,
		"auth_tokens_count", len(cfg.AuthTokens),
	)
}

func LogShutdownInfo(instanceID string, activeTasks int, reason string) {
	slog.Info("service_shutdown",
		"event", "shutdown",
		"instance", instanceID,
		"active_tasks", activeTasks,
		"reason", reason,
	)
}

func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%.2fm", d.Minutes())
}

func ContextWithInstance(ctx context.Context, instanceID string) context.Context {
	return context.WithValue(ctx, instanceKey{}, instanceID)
}

func InstanceFromContext(ctx context.Context) string {
	if v := ctx.Value(instanceKey{}); v != nil {
		return v.(string)
	}
	return "unknown"
}
