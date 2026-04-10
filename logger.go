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
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
				return slog.String("time", a.Value.Time().Format("2006-01-02 15:04:05.000"))
			}
			return a
		},
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
		"pool_size", cfg.Pool.Size,
		"zeek_timeout", cfg.Pool.TimeoutMinutes,
		"rate_limit", cfg.RateLimit.Limit,
		"rate_limit_window", cfg.RateLimit.Window,
		"redis_addr", cfg.Redis.Addr,
		"kafka_brokers", cfg.Kafka.Brokers,
		"http_addr", fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		"http_timeout", cfg.HTTP.Timeout,
		"grpc_addr", fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port),
		"grpc_timeout", cfg.GRPC.Timeout,
		"grpc_max_recv_msg_size", cfg.GRPC.MaxRecvMsgSize,
		"grpc_max_send_msg_size", cfg.GRPC.MaxSendMsgSize,
		"grpc_enable_reflection", cfg.GRPC.EnableReflection,
		"grpc_enable_health_check", cfg.GRPC.EnableHealthCheck,
		"auth_tokens_count", len(cfg.HTTP.AuthTokens),
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
