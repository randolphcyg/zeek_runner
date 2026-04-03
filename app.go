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

	kafkaReady    bool
	kafkaReadyMux sync.RWMutex
}

func NewApp() (*App, error) {
	cm := NewConfigManager()
	cfg := cm.Get()

	pool, err := ants.NewPool(cfg.PoolSize,
		ants.WithMaxBlockingTasks(10000),
		ants.WithNonblocking(false),
	)
	if err != nil {
		return nil, err
	}

	rl := NewRateLimiter(cfg.RateLimit, time.Duration(cfg.RateLimitWindow)*time.Second)
	slog.Info("rate limiter initialized", "limit", cfg.RateLimit, "window_seconds", cfg.RateLimitWindow)

	var taskManager *TaskManager
	var fileDedupMgr *FileDedupManager
	if cfg.RedisAddr != "" {
		taskManager = NewTaskManager(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
		if err := taskManager.HealthCheck(context.Background()); err != nil {
			slog.Warn("Redis connection failed, task persistence disabled", "err", err)
			taskManager = nil
		} else {
			slog.Info("Task manager initialized", "redis_addr", cfg.RedisAddr)

			fileDedupMgr = NewFileDedupManager(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB+1)
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
	}

	if cfg.KafkaBrokers != "" {
		app.KafkaChecker = NewKafkaChecker(cfg.KafkaBrokers)
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

	if oldCfg.RateLimit != a.Config.RateLimit || oldCfg.RateLimitWindow != a.Config.RateLimitWindow {
		a.RateLimiter.UpdateLimit(a.Config.RateLimit, time.Duration(a.Config.RateLimitWindow)*time.Second)
	}

	slog.Info("App config reloaded",
		"rate_limit", a.Config.RateLimit,
		"rate_limit_window", a.Config.RateLimitWindow,
		"tokens_count", len(a.Config.AuthTokens),
	)
}
