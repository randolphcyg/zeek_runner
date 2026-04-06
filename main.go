package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zeek_runner/api/pb"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"google.golang.org/grpc/reflection"
)

func main() {
	app, err := NewApp()
	if err != nil {
		slog.Error("Failed to create app", "err", err)
		os.Exit(1)
	}

	instanceID := GetInstanceIDFromTaskManager(app.TaskManager)
	InitLogger(instanceID)

	LogStartupInfo(instanceID, app.Config)

	shutdownTracer := InitTracer(app.Config)
	defer shutdownTracer()

	metricsCollector := NewMetricsCollector(app)
	metricsCollector.Register()

	ctx, cancel := context.WithCancel(context.Background())
	ctx = ContextWithInstance(ctx, instanceID)
	app.Start(ctx)

	service := NewService(app.TaskPool, app.ConfigManager, app.TaskManager, app.FileDedupMgr)
	httpHandler := NewHTTPHandler(service, app)
	grpcServer := NewGRPCServer(service, app)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(otelgin.Middleware("zeek_runner"))
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
		if len(cfg.HTTP.AuthTokens) > 0 {
			token := c.GetHeader("Authorization")
			if !cfg.HTTP.AuthTokenMap[token] {
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

	srv := &http.Server{Addr: fmt.Sprintf("%s:%d", app.Config.HTTP.Host, app.Config.HTTP.Port), Handler: r}

	go func() {
		slog.Info("HTTP started", "addr", fmt.Sprintf("%s:%d", app.Config.HTTP.Host, app.Config.HTTP.Port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP error", "err", err)
		}
	}()

	grpcSrv := NewGRPCServerWithOptions(
		app.Config.GRPC.MaxRecvMsgSize,
		app.Config.GRPC.MaxSendMsgSize,
		app.Config.GRPC.EnableReflection,
		grpcRecoveryInterceptor(),
		grpcRateLimitInterceptor(app.RateLimiter),
		grpcTimeoutInterceptor(parseTimeout(app.Config.GRPC.Timeout)),
		grpcAuthInterceptorWithManager(app.ConfigManager),
		grpcLoggingInterceptor(),
	)
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", app.Config.GRPC.Host, app.Config.GRPC.Port))
		if err != nil {
			slog.Error("gRPC listen failed", "err", err)
			return
		}
		pb.RegisterZeekAnalysisServiceServer(grpcSrv, grpcServer)
		if app.Config.GRPC.EnableReflection {
			reflection.Register(grpcSrv)
		}
		slog.Info("gRPC started", "addr", fmt.Sprintf("%s:%d", app.Config.GRPC.Host, app.Config.GRPC.Port))
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
