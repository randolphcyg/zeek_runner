package main

import (
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

	if cfg.PoolSize != 16 {
		t.Errorf("expected PoolSize 16, got %d", cfg.PoolSize)
	}
	if cfg.RateLimit != 2000 {
		t.Errorf("expected RateLimit 2000, got %d", cfg.RateLimit)
	}
}

func TestConfigManager_Reload(t *testing.T) {
	os.Setenv("RATE_LIMIT", "1000")
	defer os.Unsetenv("RATE_LIMIT")

	cm := NewConfigManager()
	oldCfg := cm.Get()

	if oldCfg.RateLimit != 1000 {
		t.Errorf("expected initial RateLimit 1000, got %d", oldCfg.RateLimit)
	}

	os.Setenv("RATE_LIMIT", "3000")
	newCfg := cm.Reload()

	if newCfg.RateLimit != 3000 {
		t.Errorf("expected reloaded RateLimit 3000, got %d", newCfg.RateLimit)
	}
}

func TestConfigManager_AuthTokens(t *testing.T) {
	os.Setenv("AUTH_TOKENS", "token1, token2, token3")
	defer os.Unsetenv("AUTH_TOKENS")

	cm := NewConfigManager()
	cfg := cm.Get()

	if len(cfg.AuthTokens) != 3 {
		t.Errorf("expected 3 auth tokens, got %d", len(cfg.AuthTokens))
	}

	if !cfg.AuthTokenMap["token1"] {
		t.Error("token1 should be in AuthTokenMap")
	}
	if !cfg.AuthTokenMap["token2"] {
		t.Error("token2 should be in AuthTokenMap")
	}
	if !cfg.AuthTokenMap["token3"] {
		t.Error("token3 should be in AuthTokenMap")
	}
}

func TestConfig_Defaults(t *testing.T) {
	os.Clearenv()
	os.Setenv("CONFIG_FILE", "/nonexistent/config.yaml")

	cm := NewConfigManager()
	cfg := cm.Get()

	if cfg.PoolSize != 8 {
		t.Errorf("expected default PoolSize 8, got %d", cfg.PoolSize)
	}
	if cfg.ZeekTimeout != 5 {
		t.Errorf("expected default ZeekTimeout 5, got %d", cfg.ZeekTimeout)
	}
	if cfg.RateLimit != 1000 {
		t.Errorf("expected default RateLimit 1000, got %d", cfg.RateLimit)
	}
	if cfg.RateLimitWindow != 60 {
		t.Errorf("expected default RateLimitWindow 60, got %d", cfg.RateLimitWindow)
	}
	if cfg.ListenHTTP != ":8000" {
		t.Errorf("expected default ListenHTTP :8000, got %s", cfg.ListenHTTP)
	}
	if cfg.ListenGRPC != ":50051" {
		t.Errorf("expected default ListenGRPC :50051, got %s", cfg.ListenGRPC)
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
			_ = cfg.PoolSize
		}()
	}
	wg.Wait()
}
