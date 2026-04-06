package main

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

func TestConfigManager_Get(t *testing.T) {
	os.Setenv("ZEEK_CONCURRENT_TASKS", "16")
	os.Setenv("RATE_LIMIT", "2000")
	defer func() {
		os.Unsetenv("ZEEK_CONCURRENT_TASKS")
		os.Unsetenv("RATE_LIMIT")
	}()

	cm := NewConfigManager()
	cfg := cm.Get()

	if cfg.Pool.Size != 16 {
		t.Errorf("expected Pool.Size 16, got %d", cfg.Pool.Size)
	}
	if cfg.RateLimit.Limit != 2000 {
		t.Errorf("expected RateLimit.Limit 2000, got %d", cfg.RateLimit.Limit)
	}
}

func TestConfigManager_Reload(t *testing.T) {
	os.Setenv("RATE_LIMIT", "1000")
	defer os.Unsetenv("RATE_LIMIT")

	cm := NewConfigManager()
	oldCfg := cm.Get()

	if oldCfg.RateLimit.Limit != 1000 {
		t.Errorf("expected initial RateLimit.Limit 1000, got %d", oldCfg.RateLimit.Limit)
	}

	os.Setenv("RATE_LIMIT", "3000")
	newCfg := cm.Reload()

	if newCfg.RateLimit.Limit != 3000 {
		t.Errorf("expected reloaded RateLimit.Limit 3000, got %d", newCfg.RateLimit.Limit)
	}
}

func TestConfigManager_AuthTokens(t *testing.T) {
	os.Setenv("AUTH_TOKENS", "token1, token2, token3")
	defer os.Unsetenv("AUTH_TOKENS")

	cm := NewConfigManager()
	cfg := cm.Get()

	if len(cfg.HTTP.AuthTokens) != 3 {
		t.Errorf("expected 3 auth tokens, got %d", len(cfg.HTTP.AuthTokens))
	}

	if !cfg.HTTP.AuthTokenMap["token1"] {
		t.Error("token1 should be in HTTP.AuthTokenMap")
	}
	if !cfg.HTTP.AuthTokenMap["token2"] {
		t.Error("token2 should be in HTTP.AuthTokenMap")
	}
	if !cfg.HTTP.AuthTokenMap["token3"] {
		t.Error("token3 should be in HTTP.AuthTokenMap")
	}
}

func TestConfig_Defaults(t *testing.T) {
	os.Clearenv()
	os.Setenv("CONFIG_FILE", "/nonexistent/config.yaml")

	cm := NewConfigManager()
	cfg := cm.Get()

	if cfg.Pool.Size != 8 {
		t.Errorf("expected default Pool.Size 8, got %d", cfg.Pool.Size)
	}
	if cfg.Pool.TimeoutMinutes != 5 {
		t.Errorf("expected default Pool.TimeoutMinutes 5, got %d", cfg.Pool.TimeoutMinutes)
	}
	if cfg.RateLimit.Limit != 1000 {
		t.Errorf("expected default RateLimit.Limit 1000, got %d", cfg.RateLimit.Limit)
	}
	if cfg.RateLimit.Window != 60 {
		t.Errorf("expected default RateLimit.Window 60, got %d", cfg.RateLimit.Window)
	}
	httpAddr := fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port)
	if httpAddr != "0.0.0.0:8000" {
		t.Errorf("expected default HTTP addr 0.0.0.0:8000, got %s", httpAddr)
	}
	grpcAddr := fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port)
	if grpcAddr != "0.0.0.0:50051" {
		t.Errorf("expected default GRPC addr 0.0.0.0:50051, got %s", grpcAddr)
	}
}

func TestConfigManager_ConcurrentAccess(t *testing.T) {
	cm := NewConfigManager()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := cm.Get()
			_ = cfg.Pool.Size
		}()
	}
	wg.Wait()
}
