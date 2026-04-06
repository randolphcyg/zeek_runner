package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

type App struct {
	ConfigManager *ConfigManager
	Config        *Config
	TaskPool      *ants.Pool
	RateLimiter   *RateLimiter
	KafkaChecker  *KafkaChecker
	TaskManager   *TaskManager
	FileDedupMgr  *FileDedupManager
	Service       *Service

	kafkaReady    bool
	kafkaReadyMux sync.RWMutex
}

func NewApp() (*App, error) {
	cm := NewConfigManager()
	cfg := cm.Get()

	pool, err := ants.NewPool(cfg.Pool.Size,
		ants.WithMaxBlockingTasks(10000),
		ants.WithNonblocking(false),
	)
	if err != nil {
		return nil, err
	}

	rl := NewRateLimiter(cfg.RateLimit.Limit, time.Duration(cfg.RateLimit.Window)*time.Second)
	slog.Info("rate limiter initialized", "limit", cfg.RateLimit.Limit, "window_seconds", cfg.RateLimit.Window)

	var taskManager *TaskManager
	var fileDedupMgr *FileDedupManager
	if cfg.Redis.Addr != "" {
		poolCfg := &RedisPoolConfig{
			PoolSize:     cfg.Redis.PoolSize,
			MinIdleConns: cfg.Redis.MinIdleConns,
			MaxRetries:   cfg.Redis.MaxRetries,
			DialTimeout:  parseTimeout(cfg.Redis.DialTimeout),
			ReadTimeout:  parseTimeout(cfg.Redis.ReadTimeout),
			WriteTimeout: parseTimeout(cfg.Redis.WriteTimeout),
			PoolTimeout:  parseTimeout(cfg.Redis.PoolTimeout),
			MaxLifetime:  parseTimeout(cfg.Redis.ConnMaxLifetime),
			MaxIdleTime:  parseTimeout(cfg.Redis.ConnMaxIdleTime),
		}
		taskManager = NewTaskManager(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB, poolCfg)
		if err := taskManager.HealthCheck(context.Background()); err != nil {
			slog.Warn("Redis connection failed, task persistence disabled", "err", err)
			taskManager = nil
		} else {
			slog.Info("Task manager initialized", "redis_addr", cfg.Redis.Addr, "pool_size", cfg.Redis.PoolSize)

			fileDedupMgr = NewFileDedupManager(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB+1, poolCfg)
			if err := fileDedupMgr.HealthCheck(context.Background()); err != nil {
				slog.Warn("File dedup manager health check failed", "err", err)
				fileDedupMgr = nil
			} else {
				slog.Info("File dedup manager initialized")
			}
		}
	}

	app := &App{
		ConfigManager: cm,
		Config:        cfg,
		TaskPool:      pool,
		RateLimiter:   rl,
		TaskManager:   taskManager,
		FileDedupMgr:  fileDedupMgr,
		Service:       NewService(pool, cm, taskManager, fileDedupMgr),
	}

	if cfg.Kafka.Brokers != "" {
		app.KafkaChecker = NewKafkaChecker(cfg.Kafka.Brokers)
	} else {
		slog.Warn("KAFKA_BROKERS not set")
	}

	cleanOldTempFiles()

	cm.WatchSignals(app.ReloadConfig)

	return app, nil
}

func (a *App) SetKafkaReady(status bool) {
	a.kafkaReadyMux.Lock()
	a.kafkaReady = status
	a.kafkaReadyMux.Unlock()
}

func (a *App) IsKafkaReady() bool {
	a.kafkaReadyMux.RLock()
	defer a.kafkaReadyMux.RUnlock()
	return a.kafkaReady
}

func (a *App) Start(ctx context.Context) {
	if a.KafkaChecker != nil {
		go a.KafkaChecker.Start(ctx, a.SetKafkaReady)
	}

	if a.Service != nil {
		a.Service.StartTaskConsumer(ctx)
	}
}

func (a *App) Shutdown(ctx context.Context) error {
	slog.Info("Shutting down...", "active_tasks", a.TaskPool.Running())

	a.RateLimiter.Stop()
	a.TaskPool.Release()

	if a.TaskManager != nil {
		a.TaskManager.Close()
	}

	if a.FileDedupMgr != nil {
		a.FileDedupMgr.Close()
	}

	slog.Info("Bye")
	return nil
}

func (a *App) ReloadConfig() {
	oldCfg := a.Config
	a.Config = a.ConfigManager.Reload()

	if oldCfg.RateLimit.Limit != a.Config.RateLimit.Limit || oldCfg.RateLimit.Window != a.Config.RateLimit.Window {
		a.RateLimiter.UpdateLimit(a.Config.RateLimit.Limit, time.Duration(a.Config.RateLimit.Window)*time.Second)
	}

	slog.Info("App config reloaded",
		"rate_limit", a.Config.RateLimit.Limit,
		"rate_limit_window", a.Config.RateLimit.Window,
		"tokens_count", len(a.Config.HTTP.AuthTokens),
	)
}
