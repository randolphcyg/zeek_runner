package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zeek_runner/api/pb"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	app, err := NewApp()
	if err != nil {
		slog.Error("Failed to create app", "err", err)
		os.Exit(1)
	}

	metricsCollector := NewMetricsCollector(app)
	metricsCollector.Register()

	ctx, cancel := context.WithCancel(context.Background())
	app.Start(ctx)

	service := NewService(app.TaskPool, app.ConfigManager, app.TaskManager, app.FileDedupMgr)
	httpHandler := NewHTTPHandler(service, app)
	grpcServer := NewGRPCServer(service, app)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestIDMiddleware())
	r.Use(loggingMiddleware())
	r.Use(rateLimitMiddleware(app.RateLimiter))

	r.GET("/metrics", prometheusHandler())
	r.GET("/api/v1/healthz", httpHandler.Healthz)

	auth := r.Group("/api/v1")
	auth.Use(func(c *gin.Context) {
		if c.GetHeader("User-Agent") == "" {
			c.AbortWithStatusJSON(403, gin.H{"code": 403, "msg": "UA required"})
		}
	})
	auth.Use(func(c *gin.Context) {
		cfg := app.ConfigManager.Get()
		if len(cfg.AuthTokens) > 0 {
			token := c.GetHeader("Authorization")
			if !cfg.AuthTokenMap[token] {
				c.AbortWithStatusJSON(401, gin.H{"code": 401, "msg": "unauthorized: invalid or missing token"})
				return
			}
		}
		c.Next()
	})
	{
		auth.POST("/analyze", httpHandler.HandleAnalysis)
		auth.POST("/analyze/async", httpHandler.HandleAsyncAnalysis)
		auth.GET("/task/:taskID", httpHandler.HandleTaskStatus)
		auth.GET("/version/zeek", httpHandler.CmdHandler("zeek", "--version"))
		auth.GET("/version/zeek-kafka", httpHandler.CmdHandler("zeek", "-N", "Seiso::Kafka"))
		auth.POST("/syntax-check", httpHandler.HandleSyntaxCheck)
	}

	srv := &http.Server{Addr: app.Config.ListenHTTP, Handler: r}

	go func() {
		slog.Info("HTTP started", "addr", app.Config.ListenHTTP)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP error", "err", err)
		}
	}()

	grpcSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcRateLimitInterceptor(app.RateLimiter),
			grpcAuthInterceptorWithManager(app.ConfigManager),
		),
	)
	go func() {
		lis, err := net.Listen("tcp", app.Config.ListenGRPC)
		if err != nil {
			slog.Error("gRPC listen failed", "err", err)
			return
		}
		pb.RegisterZeekAnalysisServiceServer(grpcSrv, grpcServer)
		reflection.Register(grpcSrv)
		slog.Info("gRPC started", "addr", app.Config.ListenGRPC)
		if err := grpcSrv.Serve(lis); err != nil {
			slog.Error("gRPC error", "err", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down...", "active_tasks", app.TaskPool.Running())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		slog.Info("Stopping HTTP server...")
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP shutdown error", "err", err)
		}
		slog.Info("Stopping gRPC server...")
		grpcSrv.GracefulStop()
		slog.Info("Stopping background tasks...")
		cancel()
		slog.Info("Releasing resources...")
		app.Shutdown(shutdownCtx)
		close(done)
	}()

	select {
	case <-done:
		slog.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		slog.Warn("Shutdown timeout, forcing exit")
		grpcSrv.Stop()
	}
	slog.Info("Bye")
}
