package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

func LoadConfigFile(path string) (*Config, error) {
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

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err == nil {
		cfg.Zeek.AutoReloadScriptsSet = yamlHasPath(&node, "zeek", "autoReloadScripts")
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

func MergeConfigWithEnv(fileCfg *Config, envCfg *Config) *Config {
	if fileCfg == nil {
		return envCfg
	}

	result := *envCfg

	if fileCfg.Redis.Addr != "" && os.Getenv("REDIS_ADDR") == "" {
		result.Redis.Addr = fileCfg.Redis.Addr
	}
	if fileCfg.Redis.Password != "" && os.Getenv("REDIS_PASSWORD") == "" {
		result.Redis.Password = fileCfg.Redis.Password
	}
	if os.Getenv("REDIS_DB") == "" {
		result.Redis.DB = fileCfg.Redis.DB
	}
	if fileCfg.Redis.PoolSize > 0 {
		result.Redis.PoolSize = fileCfg.Redis.PoolSize
	}
	if fileCfg.Redis.MinIdleConns > 0 {
		result.Redis.MinIdleConns = fileCfg.Redis.MinIdleConns
	}
	if fileCfg.Redis.MaxRetries > 0 {
		result.Redis.MaxRetries = fileCfg.Redis.MaxRetries
	}
	if fileCfg.Redis.DialTimeout != "" {
		result.Redis.DialTimeout = fileCfg.Redis.DialTimeout
	}
	if fileCfg.Redis.ReadTimeout != "" {
		result.Redis.ReadTimeout = fileCfg.Redis.ReadTimeout
	}
	if fileCfg.Redis.WriteTimeout != "" {
		result.Redis.WriteTimeout = fileCfg.Redis.WriteTimeout
	}
	if fileCfg.Redis.PoolTimeout != "" {
		result.Redis.PoolTimeout = fileCfg.Redis.PoolTimeout
	}
	if fileCfg.Redis.ConnMaxLifetime != "" {
		result.Redis.ConnMaxLifetime = fileCfg.Redis.ConnMaxLifetime
	}
	if fileCfg.Redis.ConnMaxIdleTime != "" {
		result.Redis.ConnMaxIdleTime = fileCfg.Redis.ConnMaxIdleTime
	}

	if fileCfg.Kafka.Brokers != "" && os.Getenv("KAFKA_BROKERS") == "" {
		result.Kafka.Brokers = fileCfg.Kafka.Brokers
	}

	if fileCfg.Pool.Size > 0 && os.Getenv("ZEEK_CONCURRENT_TASKS") == "" {
		result.Pool.Size = fileCfg.Pool.Size
	}
	if fileCfg.Pool.TimeoutMinutes > 0 && os.Getenv("ZEEK_TIMEOUT_MINUTES") == "" {
		result.Pool.TimeoutMinutes = fileCfg.Pool.TimeoutMinutes
	}
	if fileCfg.Scheduler.WeightedCapacity > 0 && os.Getenv("ZEEK_WEIGHTED_CAPACITY") == "" {
		result.Scheduler.WeightedCapacity = fileCfg.Scheduler.WeightedCapacity
	}
	if fileCfg.Scheduler.MaxClaimBatch > 0 && os.Getenv("ZEEK_MAX_CLAIM_BATCH") == "" {
		result.Scheduler.MaxClaimBatch = fileCfg.Scheduler.MaxClaimBatch
	}
	if fileCfg.Scheduler.LeaseTimeout != "" && os.Getenv("ZEEK_LEASE_TIMEOUT") == "" {
		result.Scheduler.LeaseTimeout = fileCfg.Scheduler.LeaseTimeout
	}
	if fileCfg.Scheduler.KafkaLagHighWatermark > 0 && os.Getenv("ZEEK_KAFKA_LAG_HIGH_WATERMARK") == "" {
		result.Scheduler.KafkaLagHighWatermark = fileCfg.Scheduler.KafkaLagHighWatermark
	}
	if fileCfg.Scheduler.MinFreeDiskPercent > 0 && os.Getenv("ZEEK_MIN_FREE_DISK_PERCENT") == "" {
		result.Scheduler.MinFreeDiskPercent = fileCfg.Scheduler.MinFreeDiskPercent
	}
	if fileCfg.Batch.Enabled && os.Getenv("ZEEK_BATCH_ENABLED") == "" {
		result.Batch.Enabled = fileCfg.Batch.Enabled
	}
	if fileCfg.Batch.MaxScriptsPerZeekRun > 0 && os.Getenv("ZEEK_BATCH_MAX_SCRIPTS_PER_RUN") == "" {
		result.Batch.MaxScriptsPerZeekRun = fileCfg.Batch.MaxScriptsPerZeekRun
	}

	if fileCfg.RateLimit.Limit > 0 && os.Getenv("RATE_LIMIT") == "" {
		result.RateLimit.Limit = fileCfg.RateLimit.Limit
	}
	if fileCfg.RateLimit.Window > 0 && os.Getenv("RATE_LIMIT_WINDOW") == "" {
		result.RateLimit.Window = fileCfg.RateLimit.Window
	}

	if fileCfg.HTTP.Port > 0 && os.Getenv("LISTEN_HTTP") == "" {
		result.HTTP.Port = fileCfg.HTTP.Port
	}
	if fileCfg.HTTP.Host != "" {
		result.HTTP.Host = fileCfg.HTTP.Host
	}
	if fileCfg.HTTP.Timeout != "" {
		result.HTTP.Timeout = fileCfg.HTTP.Timeout
	}
	if len(fileCfg.HTTP.AuthTokens) > 0 && os.Getenv("AUTH_TOKENS") == "" {
		result.HTTP.AuthTokens = fileCfg.HTTP.AuthTokens
		result.HTTP.AuthTokenMap = make(map[string]bool)
		for _, token := range fileCfg.HTTP.AuthTokens {
			result.HTTP.AuthTokenMap[token] = true
		}
	}

	if fileCfg.GRPC.Port > 0 && os.Getenv("LISTEN_GRPC") == "" {
		result.GRPC.Port = fileCfg.GRPC.Port
	}
	if fileCfg.GRPC.Host != "" {
		result.GRPC.Host = fileCfg.GRPC.Host
	}
	if fileCfg.GRPC.Timeout != "" {
		result.GRPC.Timeout = fileCfg.GRPC.Timeout
	}
	if fileCfg.GRPC.MaxRecvMsgSize > 0 && os.Getenv("GRPC_MAX_RECV_MSG_SIZE") == "" {
		result.GRPC.MaxRecvMsgSize = fileCfg.GRPC.MaxRecvMsgSize
	}
	if fileCfg.GRPC.MaxSendMsgSize > 0 && os.Getenv("GRPC_MAX_SEND_MSG_SIZE") == "" {
		result.GRPC.MaxSendMsgSize = fileCfg.GRPC.MaxSendMsgSize
	}
	if fileCfg.GRPC.EnableReflection {
		result.GRPC.EnableReflection = true
	}
	if fileCfg.GRPC.EnableHealthCheck {
		result.GRPC.EnableHealthCheck = true
	}
	if len(fileCfg.GRPC.AuthTokens) > 0 && os.Getenv("AUTH_TOKENS") == "" {
		result.GRPC.AuthTokens = fileCfg.GRPC.AuthTokens
		result.GRPC.AuthTokenMap = make(map[string]bool)
		for _, token := range fileCfg.GRPC.AuthTokens {
			result.GRPC.AuthTokenMap[token] = true
		}
	}

	if fileCfg.OTel.Enabled && os.Getenv("OTEL_ENABLED") == "" {
		result.OTel.Enabled = true
	}
	if fileCfg.OTel.Endpoint != "" && os.Getenv("OTEL_ENDPOINT") == "" {
		result.OTel.Endpoint = fileCfg.OTel.Endpoint
	}

	if fileCfg.Zeek.BaseWaitTimeMs > 0 && os.Getenv("ZEEK_BASE_WAIT_TIME_MS") == "" {
		result.Zeek.BaseWaitTimeMs = fileCfg.Zeek.BaseWaitTimeMs
	}
	if fileCfg.Zeek.ExtractPath != "" && os.Getenv("ZEEK_EXTRACT_PATH") == "" {
		result.Zeek.ExtractPath = fileCfg.Zeek.ExtractPath
	}
	if fileCfg.Zeek.MinSizeKB > 0 && os.Getenv("ZEEK_MIN_SIZE_KB") == "" {
		result.Zeek.MinSizeKB = fileCfg.Zeek.MinSizeKB
	}
	if fileCfg.Zeek.MaxSizeMB > 0 && os.Getenv("ZEEK_MAX_SIZE_MB") == "" {
		result.Zeek.MaxSizeMB = fileCfg.Zeek.MaxSizeMB
	}
	if fileCfg.Zeek.ScriptRoot != "" && os.Getenv("ZEEK_SCRIPT_ROOT") == "" {
		result.Zeek.ScriptRoot = fileCfg.Zeek.ScriptRoot
	}
	if fileCfg.Zeek.AutoReloadScriptsSet && os.Getenv("ZEEK_AUTO_RELOAD_SCRIPTS") == "" {
		result.Zeek.AutoReloadScripts = fileCfg.Zeek.AutoReloadScripts
	}
	if fileCfg.Zeek.ScriptReloadDebounce != "" && os.Getenv("ZEEK_SCRIPT_RELOAD_DEBOUNCE") == "" {
		result.Zeek.ScriptReloadDebounce = fileCfg.Zeek.ScriptReloadDebounce
	}
	if fileCfg.Zeek.ScriptReloadInterval != "" && os.Getenv("ZEEK_SCRIPT_RELOAD_INTERVAL") == "" {
		result.Zeek.ScriptReloadInterval = fileCfg.Zeek.ScriptReloadInterval
	}

	return &result
}

func yamlHasPath(node *yaml.Node, path ...string) bool {
	if node == nil {
		return false
	}
	current := node
	if current.Kind == yaml.DocumentNode && len(current.Content) > 0 {
		current = current.Content[0]
	}
	for _, key := range path {
		if current.Kind != yaml.MappingNode {
			return false
		}
		found := false
		for i := 0; i+1 < len(current.Content); i += 2 {
			if current.Content[i].Value == key {
				current = current.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
	if cfg.Pool.Size <= 0 {
		return fmt.Errorf("pool size must be positive, got %d", cfg.Pool.Size)
	}
	if cfg.Pool.TimeoutMinutes <= 0 {
		return fmt.Errorf("zeek timeout must be positive, got %d", cfg.Pool.TimeoutMinutes)
	}
	if cfg.RateLimit.Limit <= 0 {
		return fmt.Errorf("rate limit must be positive, got %d", cfg.RateLimit.Limit)
	}
	if cfg.RateLimit.Window <= 0 {
		return fmt.Errorf("rate limit window must be positive, got %d", cfg.RateLimit.Window)
	}

	if cfg.Redis.Addr != "" {
		if cfg.Redis.DB < 0 {
			return fmt.Errorf("redis db must be non-negative, got %d", cfg.Redis.DB)
		}
	}
	if cfg.Zeek.ScriptRoot == "" {
		return fmt.Errorf("zeek scriptRoot must not be empty")
	}
	if _, err := parsePositiveDuration(cfg.Zeek.ScriptReloadDebounce, "zeek scriptReloadDebounce"); err != nil {
		return err
	}
	if _, err := parsePositiveDuration(cfg.Zeek.ScriptReloadInterval, "zeek scriptReloadInterval"); err != nil {
		return err
	}

	return nil
}

func parsePositiveDuration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", name, value)
	}
	return d, nil
}
