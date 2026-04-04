package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	PoolSize        int
	ZeekTimeout     int
	KafkaBrokers    string
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	ListenHTTP      string
	ListenGRPC      string
	HTTPHost        string
	GRPCHost        string
	HTTPTimeout     time.Duration
	GRPCTimeout     time.Duration
	RateLimit       int
	RateLimitWindow int
	AuthTokens      []string
	AuthTokenMap    map[string]bool

	GRPCMaxRecvMsgSize    int
	GRPCMaxSendMsgSize    int
	GRPCEnableReflection  bool
	GRPCEnableHealthCheck bool
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
		"pool_size", fmt.Sprintf("%d->%d", oldCfg.PoolSize, newCfg.PoolSize),
		"zeek_timeout", fmt.Sprintf("%d->%d", oldCfg.ZeekTimeout, newCfg.ZeekTimeout),
		"rate_limit", fmt.Sprintf("%d->%d", oldCfg.RateLimit, newCfg.RateLimit),
		"rate_limit_window", fmt.Sprintf("%d->%d", oldCfg.RateLimitWindow, newCfg.RateLimitWindow),
		"tokens_count", len(newCfg.AuthTokens),
		"redis_addr", newCfg.RedisAddr,
		"kafka_brokers", newCfg.KafkaBrokers,
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

	cfg := &Config{
		PoolSize:              getEnvInt("ZEEK_CONCURRENT_TASKS", 8),
		ZeekTimeout:           getEnvInt("ZEEK_TIMEOUT_MINUTES", 5),
		KafkaBrokers:          os.Getenv("KAFKA_BROKERS"),
		RedisAddr:             getEnvString("REDIS_ADDR", ""),
		RedisPassword:         os.Getenv("REDIS_PASSWORD"),
		RedisDB:               getEnvInt("REDIS_DB", 0),
		ListenHTTP:            getEnvString("LISTEN_HTTP", ":8000"),
		ListenGRPC:            getEnvString("LISTEN_GRPC", ":50051"),
		HTTPHost:              getEnvString("HTTP_HOST", "0.0.0.0"),
		GRPCHost:              getEnvString("GRPC_HOST", "0.0.0.0"),
		HTTPTimeout:           getEnvDuration("HTTP_TIMEOUT", 60*time.Second),
		GRPCTimeout:           getEnvDuration("GRPC_TIMEOUT", 300*time.Second),
		RateLimit:             getEnvInt("RATE_LIMIT", 1000),
		RateLimitWindow:       getEnvInt("RATE_LIMIT_WINDOW", 60),
		AuthTokens:            authTokens,
		AuthTokenMap:          authTokenMap,
		GRPCMaxRecvMsgSize:    getEnvInt("GRPC_MAX_RECV_MSG_SIZE", 16*1024*1024),
		GRPCMaxSendMsgSize:    getEnvInt("GRPC_MAX_SEND_MSG_SIZE", 16*1024*1024),
		GRPCEnableReflection:  getEnvBool("GRPC_ENABLE_REFLECTION", true),
		GRPCEnableHealthCheck: getEnvBool("GRPC_ENABLE_HEALTH_CHECK", true),
	}

	configPath := GetConfigPath()
	if configPath != "" {
		if fileCfg, err := LoadConfigFile(configPath); err == nil && fileCfg != nil {
			cfg = MergeConfigWithEnv(fileCfg, cfg)
			slog.Info("Config merged with file", "path", configPath)
		} else if err != nil {
			slog.Warn("Failed to load config file", "path", configPath, "err", err)
		}
	}

	if err := ValidateConfig(cfg); err != nil {
		slog.Error("Invalid config", "err", err)
	}

	return cfg
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

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if v := os.Getenv(key); v != "" {
		return strings.ToLower(v) == "true" || v == "1"
	}
	return defaultVal
}
