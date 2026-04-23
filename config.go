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

type RedisConfig struct {
	Addr            string `yaml:"addr"`
	Password        string `yaml:"password"`
	DB              int    `yaml:"db"`
	PoolSize        int    `yaml:"poolSize"`
	MinIdleConns    int    `yaml:"minIdleConns"`
	MaxRetries      int    `yaml:"maxRetries"`
	DialTimeout     string `yaml:"dialTimeout"`
	ReadTimeout     string `yaml:"readTimeout"`
	WriteTimeout    string `yaml:"writeTimeout"`
	PoolTimeout     string `yaml:"poolTimeout"`
	ConnMaxLifetime string `yaml:"connMaxLifetime"`
	ConnMaxIdleTime string `yaml:"connMaxIdleTime"`
}

type KafkaConfig struct {
	Brokers string `yaml:"brokers"`
	Topic   string `yaml:"topic"`
}

type PoolConfig struct {
	Size           int `yaml:"size"`
	MaxBlocking    int `yaml:"maxBlocking"`
	TimeoutMinutes int `yaml:"timeoutMinutes"`
}

type HTTPConfig struct {
	Host         string          `yaml:"host"`
	Port         int             `yaml:"port"`
	Timeout      string          `yaml:"timeout"`
	AuthTokens   []string        `yaml:"authTokens"`
	AuthTokenMap map[string]bool `yaml:"-"`
}

type GRPCConfig struct {
	Host              string          `yaml:"host"`
	Port              int             `yaml:"port"`
	Timeout           string          `yaml:"timeout"`
	MaxRecvMsgSize    int             `yaml:"maxRecvMsgSize"`
	MaxSendMsgSize    int             `yaml:"maxSendMsgSize"`
	EnableReflection  bool            `yaml:"enableReflection"`
	EnableHealthCheck bool            `yaml:"enableHealthCheck"`
	AuthTokens        []string        `yaml:"authTokens"`
	AuthTokenMap      map[string]bool `yaml:"-"`
}

type RateLimitConfig struct {
	Limit  int `yaml:"limit"`
	Window int `yaml:"window"`
}

type OTelConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

type ZeekConfig struct {
	BaseWaitTimeMs int    `yaml:"baseWaitTimeMs"`
	ExtractPath    string `yaml:"extractPath"`
	MinSizeKB      int    `yaml:"minSizeKB"`
	MaxSizeMB      int    `yaml:"maxSizeMB"`
}

type Config struct {
	Redis     RedisConfig     `yaml:"redis"`
	Kafka     KafkaConfig     `yaml:"kafka"`
	Pool      PoolConfig      `yaml:"pool"`
	RateLimit RateLimitConfig `yaml:"rateLimit"`
	HTTP      HTTPConfig      `yaml:"http"`
	GRPC      GRPCConfig      `yaml:"grpc"`
	Zeek      ZeekConfig      `yaml:"zeek"`
	OTel      OTelConfig      `yaml:"otel"`
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
		"pool_size", fmt.Sprintf("%d->%d", oldCfg.Pool.Size, newCfg.Pool.Size),
		"zeek_timeout", fmt.Sprintf("%d->%d", oldCfg.Pool.TimeoutMinutes, newCfg.Pool.TimeoutMinutes),
		"rate_limit", fmt.Sprintf("%d->%d", oldCfg.RateLimit.Limit, newCfg.RateLimit.Limit),
		"rate_limit_window", fmt.Sprintf("%d->%d", oldCfg.RateLimit.Window, newCfg.RateLimit.Window),
		"tokens_count", len(newCfg.HTTP.AuthTokens),
		"redis_addr", newCfg.Redis.Addr,
		"kafka_brokers", newCfg.Kafka.Brokers,
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
		Redis: RedisConfig{
			Addr:       getEnvString("REDIS_ADDR", ""),
			Password:   os.Getenv("REDIS_PASSWORD"),
			DB:         getEnvInt("REDIS_DB", 0),
			PoolSize:   10,
			MaxRetries: 3,
		},
		Kafka: KafkaConfig{
			Brokers: os.Getenv("KAFKA_BROKERS"),
		},
		Pool: PoolConfig{
			Size:           getEnvInt("ZEEK_CONCURRENT_TASKS", 8),
			TimeoutMinutes: getEnvInt("ZEEK_TIMEOUT_MINUTES", 5),
		},
		RateLimit: RateLimitConfig{
			Limit:  getEnvInt("RATE_LIMIT", 1000),
			Window: getEnvInt("RATE_LIMIT_WINDOW", 60),
		},
		HTTP: HTTPConfig{
			Host:         getEnvString("HTTP_HOST", "0.0.0.0"),
			Port:         getEnvInt("HTTP_PORT", 8000),
			Timeout:      "60s",
			AuthTokens:   authTokens,
			AuthTokenMap: authTokenMap,
		},
		GRPC: GRPCConfig{
			Host:              getEnvString("GRPC_HOST", "0.0.0.0"),
			Port:              getEnvInt("GRPC_PORT", 50051),
			Timeout:           "300s",
			MaxRecvMsgSize:    getEnvInt("GRPC_MAX_RECV_MSG_SIZE", 16*1024*1024),
			MaxSendMsgSize:    getEnvInt("GRPC_MAX_SEND_MSG_SIZE", 16*1024*1024),
			EnableReflection:  getEnvBool("GRPC_ENABLE_REFLECTION", true),
			EnableHealthCheck: getEnvBool("GRPC_ENABLE_HEALTH_CHECK", true),
		},
		OTel: OTelConfig{
			Enabled:  getEnvBool("OTEL_ENABLED", false),
			Endpoint: getEnvString("OTEL_ENDPOINT", ""),
		},
		Zeek: ZeekConfig{
			BaseWaitTimeMs: getEnvInt("ZEEK_BASE_WAIT_TIME_MS", 10000),
			ExtractPath:    getEnvString("ZEEK_EXTRACT_PATH", "/opt/zeek_runner/extracted"),
			MinSizeKB:      getEnvInt("ZEEK_MIN_SIZE_KB", 20),
			MaxSizeMB:      getEnvInt("ZEEK_MAX_SIZE_MB", 200),
		},
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
