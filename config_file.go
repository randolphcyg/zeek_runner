package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
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

type RateLimitConfig struct {
	Limit  int `yaml:"limit"`
	Window int `yaml:"window"`
}

type HTTPConfig struct {
	Host       string   `yaml:"host"`
	Port       int      `yaml:"port"`
	Timeout    string   `yaml:"timeout"`
	AuthTokens []string `yaml:"authTokens"`
}

type GRPCConfig struct {
	Host              string   `yaml:"host"`
	Port              int      `yaml:"port"`
	Timeout           string   `yaml:"timeout"`
	MaxRecvMsgSize    int      `yaml:"maxRecvMsgSize"`
	MaxSendMsgSize    int      `yaml:"maxSendMsgSize"`
	EnableReflection  bool     `yaml:"enableReflection"`
	EnableHealthCheck bool     `yaml:"enableHealthCheck"`
	AuthTokens        []string `yaml:"authTokens"`
}

type FileConfig struct {
	ExtractPath string `yaml:"extractPath"`
	MinSizeKB   int    `yaml:"minSizeKB"`
}

type ConfigFile struct {
	Redis     RedisConfig     `yaml:"redis"`
	Kafka     KafkaConfig     `yaml:"kafka"`
	Pool      PoolConfig      `yaml:"pool"`
	RateLimit RateLimitConfig `yaml:"rateLimit"`
	HTTP      HTTPConfig      `yaml:"http"`
	GRPC      GRPCConfig      `yaml:"grpc"`
	File      FileConfig      `yaml:"file"`
}

func LoadConfigFile(path string) (*ConfigFile, error) {
	if path == "" {
		return nil, nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	slog.Info("config file loaded", "path", absPath)
	return &cfg, nil
}

func parseTimeout(timeoutStr string) time.Duration {
	if timeoutStr == "" {
		return 60 * time.Second
	}
	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return 60 * time.Second
	}
	return d
}

func MergeConfigWithEnv(cfg *ConfigFile, envCfg *Config) *Config {
	if cfg == nil {
		return envCfg
	}

	result := *envCfg

	if cfg.Redis.Addr != "" && os.Getenv("REDIS_ADDR") == "" {
		result.RedisAddr = cfg.Redis.Addr
	}
	if cfg.Redis.Password != "" && os.Getenv("REDIS_PASSWORD") == "" {
		result.RedisPassword = cfg.Redis.Password
	}
	if os.Getenv("REDIS_DB") == "" {
		result.RedisDB = cfg.Redis.DB
	}

	if cfg.Kafka.Brokers != "" && os.Getenv("KAFKA_BROKERS") == "" {
		result.KafkaBrokers = cfg.Kafka.Brokers
	}

	if cfg.Pool.Size > 0 && os.Getenv("ZEEK_CONCURRENT_TASKS") == "" {
		result.PoolSize = cfg.Pool.Size
	}
	if cfg.Pool.TimeoutMinutes > 0 && os.Getenv("ZEEK_TIMEOUT_MINUTES") == "" {
		result.ZeekTimeout = cfg.Pool.TimeoutMinutes
	}

	if cfg.RateLimit.Limit > 0 && os.Getenv("RATE_LIMIT") == "" {
		result.RateLimit = cfg.RateLimit.Limit
	}
	if cfg.RateLimit.Window > 0 && os.Getenv("RATE_LIMIT_WINDOW") == "" {
		result.RateLimitWindow = cfg.RateLimit.Window
	}

	if cfg.HTTP.Port > 0 && os.Getenv("LISTEN_HTTP") == "" {
		result.ListenHTTP = fmt.Sprintf(":%d", cfg.HTTP.Port)
	}
	if cfg.HTTP.Host != "" {
		result.HTTPHost = cfg.HTTP.Host
	}
	if cfg.HTTP.Timeout != "" {
		result.HTTPTimeout = parseTimeout(cfg.HTTP.Timeout)
	}
	if len(cfg.HTTP.AuthTokens) > 0 && os.Getenv("AUTH_TOKENS") == "" {
		result.AuthTokens = cfg.HTTP.AuthTokens
		result.AuthTokenMap = make(map[string]bool)
		for _, token := range cfg.HTTP.AuthTokens {
			result.AuthTokenMap[token] = true
		}
	}

	if cfg.GRPC.Port > 0 && os.Getenv("LISTEN_GRPC") == "" {
		result.ListenGRPC = fmt.Sprintf(":%d", cfg.GRPC.Port)
	}
	if cfg.GRPC.Host != "" {
		result.GRPCHost = cfg.GRPC.Host
	}
	if cfg.GRPC.Timeout != "" {
		result.GRPCTimeout = parseTimeout(cfg.GRPC.Timeout)
	}
	if cfg.GRPC.MaxRecvMsgSize > 0 && os.Getenv("GRPC_MAX_RECV_MSG_SIZE") == "" {
		result.GRPCMaxRecvMsgSize = cfg.GRPC.MaxRecvMsgSize
	}
	if cfg.GRPC.MaxSendMsgSize > 0 && os.Getenv("GRPC_MAX_SEND_MSG_SIZE") == "" {
		result.GRPCMaxSendMsgSize = cfg.GRPC.MaxSendMsgSize
	}
	if cfg.GRPC.EnableReflection {
		result.GRPCEnableReflection = true
	}
	if cfg.GRPC.EnableHealthCheck {
		result.GRPCEnableHealthCheck = true
	}

	return &result
}

func GetConfigPath() string {
	if path := os.Getenv("CONFIG_FILE"); path != "" {
		return path
	}

	candidates := []string{
		"/etc/zeek_runner/config.yaml",
		"/opt/zeek_runner/config.yaml",
		"./config.yaml",
		"./config/config.yaml",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func ValidateConfig(cfg *Config) error {
	if cfg.PoolSize <= 0 {
		return fmt.Errorf("pool size must be positive, got %d", cfg.PoolSize)
	}
	if cfg.ZeekTimeout <= 0 {
		return fmt.Errorf("zeek timeout must be positive, got %d", cfg.ZeekTimeout)
	}
	if cfg.RateLimit <= 0 {
		return fmt.Errorf("rate limit must be positive, got %d", cfg.RateLimit)
	}
	if cfg.RateLimitWindow <= 0 {
		return fmt.Errorf("rate limit window must be positive, got %d", cfg.RateLimitWindow)
	}

	if cfg.RedisAddr != "" {
		if cfg.RedisDB < 0 {
			return fmt.Errorf("redis db must be non-negative, got %d", cfg.RedisDB)
		}
	}

	return nil
}
