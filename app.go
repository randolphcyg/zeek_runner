package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

type App struct {
	ConfigManager  *ConfigManager
	Config         *Config
	TaskPool       *ants.Pool
	RateLimiter    *RateLimiter
	KafkaChecker   *KafkaChecker
	TaskManager    *TaskManager
	FileDedupMgr   *FileDedupManager
	Service        *Service
	HealthServer   *HealthServer
	BehaviorEngine *behaviorEngine

	kafkaReady    bool
	kafkaReadyMux sync.RWMutex

	redisReady    bool
	redisReadyMux sync.RWMutex

	behaviorReady    bool
	behaviorReadyMux sync.RWMutex

	appCtx                 context.Context
	scriptAutoReloadCancel context.CancelFunc
	scriptAutoReloadMux    sync.Mutex
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
	var redisReady bool
	if cfg.Redis.Addr != "" {
		taskManager, fileDedupMgr, redisReady = initRedisManagers(cfg)
	}

	kafkaDialer := newKafkaDialer(cfg.Kafka.SaslMechanism, cfg.Kafka.SaslUsername, cfg.Kafka.SaslPassword)

	app := &App{
		ConfigManager: cm,
		Config:        cfg,
		TaskPool:      pool,
		RateLimiter:   rl,
		TaskManager:   taskManager,
		FileDedupMgr:  fileDedupMgr,
		redisReady:    redisReady,
		Service:       NewService(pool, cm, taskManager, fileDedupMgr, kafkaDialer),
	}

	if cfg.Kafka.Brokers != "" {
		app.KafkaChecker = NewKafkaChecker(cfg.Kafka.Brokers, kafkaDialer)
	} else {
		slog.Warn("KAFKA_BROKERS not set")
	}

	// 初始化行为识别引擎：规则加载失败必须拒绝就绪，不可静默使用空规则。
	if cfg.Behavior.RulesPath != "" {
		eng, err := newBehaviorEngine(behaviorEngineConfig{
			RulesPath:        cfg.Behavior.RulesPath,
			ArchiveDir:       cfg.Behavior.ArchiveDir,
			ArchiveKeyHex:    cfg.Behavior.ArchiveKeyHex,
			ArchiveEnabled:   cfg.Behavior.ArchiveEnabled,
			ArchiveRetention: cfg.Behavior.ArchiveRetention,
		})
		if err != nil {
			slog.Error("behavior engine init failed: refusing to start with empty rules", "err", err)
			return nil, fmt.Errorf("behavior engine init: %w", err)
		}
		app.BehaviorEngine = eng
		app.behaviorReady = true
		app.Service.SetBehaviorEngine(eng)
	} else {
		if cfg.Behavior.Required {
			return nil, fmt.Errorf("BEHAVIOR_RULES_PATH is required for production behavior detection")
		}
		slog.Warn("BEHAVIOR_RULES_PATH not set, behavior analysis disabled by explicit non-production configuration")
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

func (a *App) IsRedisReady() bool {
	a.redisReadyMux.RLock()
	defer a.redisReadyMux.RUnlock()
	return a.redisReady
}

func (a *App) IsBehaviorReady() bool {
	a.behaviorReadyMux.RLock()
	defer a.behaviorReadyMux.RUnlock()
	return a.behaviorReady && a.BehaviorEngine != nil
}

func (a *App) SetRedisReady(status bool) {
	a.redisReadyMux.Lock()
	a.redisReady = status
	a.redisReadyMux.Unlock()
}

func initRedisManagers(cfg *Config) (*TaskManager, *FileDedupManager, bool) {
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
	taskManager := NewTaskManager(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB, poolCfg)
	if err := taskManager.HealthCheck(context.Background()); err != nil {
		slog.Warn("Redis connection failed, will retry in background", "err", err)
		return nil, nil, false
	}
	slog.Info("Task manager initialized", "redis_addr", cfg.Redis.Addr, "pool_size", cfg.Redis.PoolSize)

	fileDedupMgr := NewFileDedupManager(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB+1, poolCfg)
	if err := fileDedupMgr.HealthCheck(context.Background()); err != nil {
		slog.Warn("File dedup manager health check failed", "err", err)
		fileDedupMgr = nil
	} else {
		slog.Info("File dedup manager initialized")
	}

	return taskManager, fileDedupMgr, true
}

func (a *App) Start(ctx context.Context) {
	if a.KafkaChecker != nil {
		go a.KafkaChecker.Start(ctx, a.SetKafkaReady)
	}

	if a.Service != nil {
		a.Service.StartTaskConsumer(ctx)
		a.Service.StartKafkaOutboxFlusher(ctx)
		a.startScriptAutoReload(ctx)
	}

	if a.Config.Redis.Addr != "" && !a.IsRedisReady() {
		go a.redisReconnectLoop(ctx)
	}

	// 命中载荷归档过期清理：定时删除过期对象；删除失败保留审计记录并可重试。
	if a.BehaviorEngine != nil && a.BehaviorEngine.archiver != nil {
		go a.archiveCleanupLoop(ctx)
	}

	// 就绪探测：周期性 ping Redis 并更新标准 Health 服务的就绪状态。
	// 覆盖启动期 Redis 未就绪、运行期 Redis 临时失联两种场景。
	if a.HealthServer != nil {
		go a.readinessProbeLoop(ctx)
	}
}

// archiveCleanupLoop 定时删除过期的归档对象。每天执行一次。
// 删除失败保留审计记录并可重试。
func (a *App) archiveCleanupLoop(ctx context.Context) {
	if a.BehaviorEngine == nil || a.BehaviorEngine.archiver == nil {
		return
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// 启动后先执行一次
	a.runArchiveCleanup()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runArchiveCleanup()
		}
	}
}

func (a *App) runArchiveCleanup() {
	deleted, err := a.BehaviorEngine.archiver.cleanupExpiredArchives()
	if err != nil {
		slog.Warn("archive cleanup completed with errors", "deleted", deleted, "err", err)
	} else if deleted > 0 {
		slog.Info("archive cleanup completed", "deleted", deleted)
	}
}

// readinessProbeLoop 周期性检查 Redis/TaskManager 连通性并刷新就绪状态。
// TaskManager 为 nil（尚未重连成功）时保持 NOT_SERVING；ping 失败时置为 NOT_SERVING。
func (a *App) readinessProbeLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	a.refreshReadiness(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.refreshReadiness(ctx)
		}
	}
}

func (a *App) refreshReadiness(ctx context.Context) {
	if a.HealthServer == nil {
		return
	}
	if a.TaskManager == nil {
		a.HealthServer.SetReadiness(false)
		return
	}
	if err := a.TaskManager.HealthCheck(ctx); err != nil {
		a.HealthServer.SetReadiness(false)
		return
	}
	if a.Config.Behavior.Required && !a.IsBehaviorReady() {
		a.HealthServer.SetReadiness(false)
		return
	}
	a.HealthServer.SetReadiness(true)
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

	a.stopScriptAutoReload()

	if a.Service != nil {
		_ = a.Service.Close()
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
	if a.Service != nil && oldCfg.Zeek.ScriptRoot != a.Config.Zeek.ScriptRoot {
		if _, err := a.Service.ReloadScripts(); err != nil {
			slog.Warn("script registry reload failed after config reload", "err", err)
		}
	}
	if a.Service != nil && scriptAutoReloadConfigChanged(oldCfg.Zeek, a.Config.Zeek) {
		a.restartScriptAutoReload()
	}

	slog.Info("App config reloaded",
		"rate_limit", a.Config.RateLimit.Limit,
		"rate_limit_window", a.Config.RateLimit.Window,
		"tokens_count", len(a.Config.HTTP.AuthTokens),
	)
}

func (a *App) startScriptAutoReload(ctx context.Context) {
	a.scriptAutoReloadMux.Lock()
	defer a.scriptAutoReloadMux.Unlock()

	a.appCtx = ctx
	a.startScriptAutoReloadLocked(ctx)
}

func (a *App) restartScriptAutoReload() {
	a.scriptAutoReloadMux.Lock()
	defer a.scriptAutoReloadMux.Unlock()

	if a.scriptAutoReloadCancel != nil {
		a.scriptAutoReloadCancel()
		a.scriptAutoReloadCancel = nil
	}
	if a.appCtx != nil {
		a.startScriptAutoReloadLocked(a.appCtx)
	}
}

func (a *App) stopScriptAutoReload() {
	a.scriptAutoReloadMux.Lock()
	defer a.scriptAutoReloadMux.Unlock()

	if a.scriptAutoReloadCancel != nil {
		a.scriptAutoReloadCancel()
		a.scriptAutoReloadCancel = nil
	}
}

func (a *App) startScriptAutoReloadLocked(parent context.Context) {
	if a.Service == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	a.scriptAutoReloadCancel = cancel
	a.Service.StartScriptAutoReload(ctx)
}

func scriptAutoReloadConfigChanged(oldCfg, newCfg ZeekConfig) bool {
	return oldCfg.ScriptRoot != newCfg.ScriptRoot ||
		oldCfg.AutoReloadScripts != newCfg.AutoReloadScripts ||
		oldCfg.ScriptReloadDebounce != newCfg.ScriptReloadDebounce ||
		oldCfg.ScriptReloadInterval != newCfg.ScriptReloadInterval
}

func (a *App) redisReconnectLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := a.ConfigManager.Get()
			tm, fdm, ok := initRedisManagers(cfg)
			if !ok {
				slog.Warn("Redis reconnect attempt failed, will retry", "interval", "5s")
				continue
			}

			a.TaskManager = tm
			a.FileDedupMgr = fdm
			a.SetRedisReady(true)
			a.Service.SetTaskManager(tm)
			a.Service.SetFileDedupMgr(fdm)
			slog.Info("Redis reconnected successfully, task persistence enabled")
			return
		}
	}
}
