package main

import (
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

type Config struct {
	PoolSize        int
	ZeekTimeout     int
	KafkaBrokers    string
	RedisAddr       string
	ListenHTTP      string
	ListenGRPC      string
	RateLimit       int
	RateLimitWindow int
	AuthTokens      []string
	AuthTokenMap    map[string]bool
}

type ConfigManager struct {
	config atomic.Value
}

func NewConfigManager() *ConfigManager {
	cm := &ConfigManager{}
	cm.config.Store(loadConfig())
	return cm
}

func (cm *ConfigManager) Get() *Config {
	return cm.config.Load().(*Config)
}

func (cm *ConfigManager) Reload() *Config {
	oldCfg := cm.Get()
	newCfg := loadConfig()

	slog.Info("Config reloaded",
		"old_pool_size", oldCfg.PoolSize,
		"new_pool_size", newCfg.PoolSize,
		"old_rate_limit", oldCfg.RateLimit,
		"new_rate_limit", newCfg.RateLimit,
		"tokens_count", len(newCfg.AuthTokens),
	)

	cm.config.Store(newCfg)
	return newCfg
}

func (cm *ConfigManager) WatchSignals(onReload func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for range sigChan {
			slog.Info("Received SIGHUP, reloading config...")
			cm.Reload()
			if onReload != nil {
				onReload()
			}
		}
	}()
}

func loadConfig() *Config {
	authTokens := []string{}
	authTokenMap := make(map[string]bool)
	if tokens := os.Getenv("AUTH_TOKENS"); tokens != "" {
		authTokens = strings.Split(tokens, ",")
		for i, t := range authTokens {
			authTokens[i] = strings.TrimSpace(t)
			authTokenMap[strings.TrimSpace(t)] = true
		}
	}

	return &Config{
		PoolSize:        getEnvInt("ZEEK_CONCURRENT_TASKS", 8),
		ZeekTimeout:     getEnvInt("ZEEK_TIMEOUT_MINUTES", 5),
		KafkaBrokers:    os.Getenv("KAFKA_BROKERS"),
		RedisAddr:       getEnvString("REDIS_ADDR", "localhost:6379"),
		ListenHTTP:      ":8000",
		ListenGRPC:      ":50051",
		RateLimit:       getEnvInt("RATE_LIMIT", 1000),
		RateLimitWindow: getEnvInt("RATE_LIMIT_WINDOW", 60),
		AuthTokens:      authTokens,
		AuthTokenMap:    authTokenMap,
	}
}

func getEnvInt(key string, defaultVal int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return defaultVal
}

func getEnvString(key string, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
