package main

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	if !rl.Allow("192.168.1.1") {
		t.Error("first request should be allowed")
	}
	if !rl.Allow("192.168.1.1") {
		t.Error("second request should be allowed")
	}
	if rl.Allow("192.168.1.1") {
		t.Error("third request should be blocked")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	if !rl.Allow("192.168.1.1") {
		t.Error("first IP first request should be allowed")
	}
	if !rl.Allow("192.168.1.2") {
		t.Error("second IP first request should be allowed")
	}
	if !rl.Allow("192.168.1.1") {
		t.Error("first IP second request should be allowed")
	}
	if !rl.Allow("192.168.1.2") {
		t.Error("second IP second request should be allowed")
	}
	if rl.Allow("192.168.1.1") {
		t.Error("first IP third request should be blocked")
	}
	if rl.Allow("192.168.1.2") {
		t.Error("second IP third request should be blocked")
	}
}

func TestRateLimiter_UpdateLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.1")
	if rl.Allow("192.168.1.1") {
		t.Error("should be blocked with limit 2")
	}

	rl.UpdateLimit(5, time.Minute)

	if !rl.Allow("192.168.1.1") {
		t.Error("should be allowed after limit increased")
	}
}

func TestRateLimiter_TimeWindowExpiry(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond)

	if !rl.Allow("192.168.1.1") {
		t.Error("first request should be allowed")
	}
	if rl.Allow("192.168.1.1") {
		t.Error("second request should be blocked")
	}

	time.Sleep(150 * time.Millisecond)

	if !rl.Allow("192.168.1.1") {
		t.Error("request after window expiry should be allowed")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(1000, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0

	for i := 0; i < 2000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("192.168.1.1") {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount != 1000 {
		t.Errorf("expected exactly 1000 allowed requests, got %d", allowedCount)
	}
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.Stop()
	time.Sleep(10 * time.Millisecond)
}
