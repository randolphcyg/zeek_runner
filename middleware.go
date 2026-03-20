package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type RateLimiter struct {
	mu          sync.Mutex
	reqs        map[string][]time.Time
	maxRequests int
	timeWindow  time.Duration
	stopChan    chan struct{}
}

func NewRateLimiter(maxRequests int, timeWindow time.Duration) *RateLimiter {
	rl := &RateLimiter{
		reqs:        make(map[string][]time.Time),
		maxRequests: maxRequests,
		timeWindow:  timeWindow,
		stopChan:    make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, times := range rl.reqs {
				var validTimes []time.Time
				for _, t := range times {
					if now.Sub(t) < rl.timeWindow {
						validTimes = append(validTimes, t)
					}
				}
				if len(validTimes) == 0 {
					delete(rl.reqs, ip)
				} else {
					rl.reqs[ip] = validTimes
				}
			}
			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
}

func (rl *RateLimiter) UpdateLimit(maxRequests int, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxRequests = maxRequests
	rl.timeWindow = window
	slog.Info("rate limiter updated", "limit", maxRequests, "window", window)
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if times, exists := rl.reqs[ip]; exists {
		var validTimes []time.Time
		for _, t := range times {
			if now.Sub(t) < rl.timeWindow {
				validTimes = append(validTimes, t)
			}
		}
		rl.reqs[ip] = validTimes
	}

	if len(rl.reqs[ip]) >= rl.maxRequests {
		return false
	}

	rl.reqs[ip] = append(rl.reqs[ip], now)
	return true
}

func rateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.Allow(ip) {
			c.JSON(429, gin.H{"code": 429, "msg": "too many requests"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func grpcRateLimitInterceptor(rl *RateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ip := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			ip = p.Addr.String()
		}
		if !rl.Allow(ip) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", ip)
		}
		return handler(ctx, req)
	}
}

func grpcAuthInterceptorWithManager(cm *ConfigManager) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		cfg := cm.Get()
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata is missing")
		}
		userAgent := md.Get("user-agent")
		if len(userAgent) == 0 || userAgent[0] == "" {
			return nil, status.Error(codes.Unauthenticated, "user-agent is required")
		}
		if len(cfg.AuthTokens) > 0 {
			token := md.Get("authorization")
			if len(token) == 0 || !cfg.AuthTokenMap[token[0]] {
				return nil, status.Error(codes.Unauthenticated, "invalid or missing token")
			}
		}
		return handler(ctx, req)
	}
}

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("requestID", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

func generateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return time.Now().Format("150405.999999")
	}
	return hex.EncodeToString(b)[:n]
}

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		RecordRequest(c.Request.Method, path, strconv.Itoa(statusCode))

		if statusCode >= 400 {
			slog.Error("HTTP request",
				"method", c.Request.Method,
				"path", path,
				"query", query,
				"status", statusCode,
				"latency", latency,
				"client_ip", c.ClientIP(),
				"request_id", c.GetString("requestID"),
			)
		} else {
			slog.Info("HTTP request",
				"method", c.Request.Method,
				"path", path,
				"status", statusCode,
				"latency", latency,
				"client_ip", c.ClientIP(),
			)
		}
	}
}
