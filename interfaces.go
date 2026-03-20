package main

import (
	"context"
	"time"

	"github.com/panjf2000/ants/v2"
)

type TaskExecutor interface {
	ExecuteTaskInPool(ctx context.Context, req AnalyzeReq) (*AnalyzeResp, error)
}

type ConfigProvider interface {
	Get() *Config
	Reload() *Config
}

type PoolProvider interface {
	Submit(task func()) error
	Running() int
	Release()
}

type RateLimitProvider interface {
	Allow(ip string) bool
	Stop()
	UpdateLimit(maxRequests int, window time.Duration)
}

type KafkaCheckerProvider interface {
	Start(ctx context.Context, onStatusChange func(bool))
}

var (
	_ TaskExecutor      = (*Service)(nil)
	_ ConfigProvider    = (*ConfigManager)(nil)
	_ PoolProvider      = (*ants.Pool)(nil)
	_ RateLimitProvider = (*RateLimiter)(nil)
	_ KafkaCheckerProvider = (*KafkaChecker)(nil)
)
