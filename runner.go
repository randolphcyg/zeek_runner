package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"zeek_runner/api/pb"

	"github.com/gin-gonic/gin"
	"github.com/panjf2000/ants/v2"
	"github.com/segmentio/kafka-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ===========================
// 全局配置与状态
// ===========================

type Config struct {
	PoolSize     int
	ZeekTimeout  int
	KafkaBrokers string
	ListenHTTP   string
	ListenGRPC   string
}

var (
	config        Config
	taskPool      *ants.Pool
	kafkaReady    bool
	kafkaReadyMux sync.RWMutex
)

func loadConfig() {
	config = Config{
		PoolSize:     getEnvInt("ZEEK_CONCURRENT_TASKS", 8),
		ZeekTimeout:  getEnvInt("ZEEK_TIMEOUT_MINUTES", 5),
		KafkaBrokers: os.Getenv("KAFKA_BROKERS"),
		ListenHTTP:   ":8000",
		ListenGRPC:   ":50051",
	}
}

// ===========================
// 工具类：LimitWriter & Env
// ===========================

// LimitWriter 限制写入量，防止日志过大 OOM
type LimitWriter struct {
	w io.Writer
	n int64
}

func (l *LimitWriter) Write(p []byte) (n int, err error) {
	if l.n <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err = l.w.Write(p)
	l.n -= int64(n)
	return
}

func getEnvInt(key string, defaultVal int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return defaultVal
}

// ===========================
// 核心业务逻辑
// ===========================

type AnalyzeReq struct {
	TaskID               string `json:"taskID"`
	UUID                 string `json:"uuid"`
	OnlyNotice           bool   `json:"onlyNotice"`
	PcapID               string `json:"pcapID"`
	PcapPath             string `json:"pcapPath"`
	ScriptID             string `json:"scriptID"`
	ScriptPath           string `json:"scriptPath"`
	ExtractedFilePath    string `json:"extractedFilePath"`
	ExtractedFileMinSize int    `json:"extractedFileMinSize"`
}

type AnalyzeResp struct {
	TaskID     string `json:"taskID"`
	UUID       string `json:"uuid"`
	PcapPath   string `json:"pcapPath"`
	ScriptPath string `json:"scriptPath"`
	StartTime  string `json:"startTime"`
}

// 统一任务提交入口：处理并发控制和上下文传递
func executeTaskInPool(ctx context.Context, req AnalyzeReq) (*AnalyzeResp, error) {
	type result struct {
		output []byte
		err    error
	}
	// 缓冲设为1，防止协程超时后写入阻塞
	resultChan := make(chan result, 1)

	// 提交任务 (ctx 闭包传递)
	err := taskPool.Submit(func() {
		// 传递父级 context，确保请求断开时能终止 Zeek
		out, e := runZeekAnalysis(ctx, req)
		select {
		case resultChan <- result{output: out, err: e}:
		case <-ctx.Done():
			// 接收端已放弃，直接丢弃结果
		}
	})

	if err != nil {
		if errors.Is(err, ants.ErrPoolOverload) {
			return nil, status.Errorf(codes.ResourceExhausted, "task pool full (cap: %d)", config.PoolSize)
		}
		return nil, status.Errorf(codes.Internal, "submit failed: %v", err)
	}

	// 等待结果或取消
	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, fmt.Errorf("%w | output: %s", res.err, string(res.output))
		}
		return &AnalyzeResp{
			TaskID: req.TaskID, UUID: req.UUID,
			PcapPath: req.PcapPath, ScriptPath: req.ScriptPath,
			StartTime: time.Now().Format(time.RFC3339),
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func runZeekAnalysis(parentCtx context.Context, req AnalyzeReq) ([]byte, error) {
	// 基于请求 Context 派生超时 Context
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(config.ZeekTimeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zeek", "-Cr", req.PcapPath, req.ScriptPath)
	// 设置进程组，确保超时 Kill 能清理子进程
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// 注入环境变量
	env := os.Environ()
	envMap := map[string]string{
		"TASK_ID": req.TaskID, "UUID": req.UUID,
		"ONLY_NOTICE": strconv.FormatBool(req.OnlyNotice),
		"PCAP_PATH":   req.PcapPath, "SCRIPT_PATH": req.ScriptPath,
		"EXTRACTED_FILE_PATH":     req.ExtractedFilePath,
		"EXTRACTED_FILE_MIN_SIZE": strconv.Itoa(req.ExtractedFileMinSize),
	}
	for k, v := range envMap {
		if v != "" && v != "0" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env

	// 内存保护：只保留 stderr 前 4KB，丢弃 stdout
	var errBuf bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &LimitWriter{w: &errBuf, n: 4096}

	startTime := time.Now()
	err := cmd.Run()
	output := errBuf.Bytes()

	if err != nil {
		// 区分是超时还是执行错误
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return output, fmt.Errorf("timeout after %dm", config.ZeekTimeout)
		}
		// 若是上层 Cancel (如客户端断开)
		if errors.Is(ctx.Err(), context.Canceled) {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return output, errors.New("request canceled by client")
		}

		slog.Error("Zeek failed", "taskID", req.TaskID, "err", err, "stderr", string(output))
		return output, err
	}

	slog.Info("Zeek finished", "taskID", req.TaskID, "duration", time.Since(startTime))
	return output, nil
}

func validateReq(req AnalyzeReq) error {
	if req.TaskID == "" || req.UUID == "" {
		return errors.New("missing taskID or uuid")
	}
	if req.PcapPath == "" || req.ScriptPath == "" {
		return errors.New("missing paths")
	}
	// 简单的目录穿越防护
	cleanPcap := filepath.Clean(req.PcapPath)
	if strings.Contains(cleanPcap, "..") {
		return errors.New("invalid pcap path")
	}
	if !isFileExist(req.PcapPath) {
		return fmt.Errorf("file not found: %s", req.PcapPath)
	}
	return nil
}

// ===========================
// HTTP & gRPC Handlers
// ===========================

func handleAnalysis(c *gin.Context) {
	var req AnalyzeReq
	if err := c.BindJSON(&req); err != nil {
		response(c, 400, "invalid params", err)
		return
	}
	if err := validateReq(req); err != nil {
		response(c, 400, err.Error(), nil)
		return
	}

	// c.Request.Context() 用于传递客户端断开信号
	resp, err := executeTaskInPool(c.Request.Context(), req)
	if err != nil {
		code := 500
		if strings.Contains(err.Error(), "pool full") {
			code = 503
		}
		response(c, code, err.Error(), err)
		return
	}
	success(c, resp)
}

type GRPCServer struct {
	pb.UnimplementedZeekAnalysisServiceServer
}

func (s *GRPCServer) Analyze(ctx context.Context, req *pb.AnalyzeRequest) (*pb.AnalyzeResponse, error) {
	// gRPC 请求转换
	ar := AnalyzeReq{
		TaskID: req.TaskID, UUID: req.Uuid, OnlyNotice: req.OnlyNotice,
		PcapPath: req.PcapPath, ScriptPath: req.ScriptPath,
		ExtractedFilePath: req.ExtractedFilePath, ExtractedFileMinSize: int(req.ExtractedFileMinSize),
	}

	if err := validateReq(ar); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := executeTaskInPool(ctx, ar)
	if err != nil {
		if strings.Contains(err.Error(), "pool full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.AnalyzeResponse{
		TaskID: resp.TaskID, Uuid: resp.UUID,
		PcapPath: resp.PcapPath, ScriptPath: resp.ScriptPath, StartTime: resp.StartTime,
	}, nil
}

// ===========================
// Kafka & Main
// ===========================

func startKafkaCheck(ctx context.Context) {
	if config.KafkaBrokers == "" {
		slog.Warn("KAFKA_BROKERS not set")
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		check := func() {
			dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			conn, err := kafka.DialContext(dialCtx, "tcp", config.KafkaBrokers)
			if err != nil {
				setKafkaReady(false)
				slog.Warn("Kafka unreachable", "err", err)
			} else {
				conn.Close()
				setKafkaReady(true)
			}
		}

		check() // 立即检查一次
		for {
			select {
			case <-ticker.C:
				check()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func setKafkaReady(status bool) {
	kafkaReadyMux.Lock()
	kafkaReady = status
	kafkaReadyMux.Unlock()
}
func isKafkaReady() bool {
	kafkaReadyMux.RLock()
	defer kafkaReadyMux.RUnlock()
	return kafkaReady
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	loadConfig()

	// 1. 初始化协程池
	var err error
	taskPool, err = ants.NewPool(config.PoolSize, ants.WithNonblocking(true))
	if err != nil {
		slog.Error("Pool init failed", "err", err)
		os.Exit(1)
	}

	// 2. 启动后台服务
	ctx, cancel := context.WithCancel(context.Background())
	startKafkaCheck(ctx)

	// 3. 配置 HTTP 服务
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/api/v1/healthz", func(c *gin.Context) {
		msg := "ok"
		if !isKafkaReady() {
			msg = "kafka_down"
		}
		c.JSON(200, gin.H{"status": msg, "pool_running": taskPool.Running()})
	})

	auth := r.Group("/api/v1")
	auth.Use(func(c *gin.Context) {
		if c.GetHeader("User-Agent") == "" {
			c.AbortWithStatusJSON(403, gin.H{"code": 403, "msg": "UA required"})
		}
	})
	{
		auth.POST("/analyze", handleAnalysis)
		auth.GET("/version/zeek", cmdHandler("zeek", "--version"))
		auth.GET("/version/zeek-kafka", cmdHandler("zeek", "-N", "Seiso::Kafka"))
	}

	srv := &http.Server{Addr: config.ListenHTTP, Handler: r}

	// 4. 启动 HTTP (异步)
	go func() {
		slog.Info("HTTP started", "addr", config.ListenHTTP)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP error", "err", err)
		}
	}()

	// 5. 启动 gRPC (异步)
	grpcSrv := grpc.NewServer()
	go func() {
		lis, err := net.Listen("tcp", config.ListenGRPC)
		if err != nil {
			slog.Error("gRPC listen failed", "err", err)
			return
		}
		pb.RegisterZeekAnalysisServiceServer(grpcSrv, &GRPCServer{})
		slog.Info("gRPC started", "addr", config.ListenGRPC)
		if err := grpcSrv.Serve(lis); err != nil {
			slog.Error("gRPC error", "err", err)
		}
	}()

	// 6. 优雅退出等待
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down...")

	// 7. 执行清理
	// 停止接收请求 -> 停止 Kafka 检查 -> 释放协程池
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP force shutdown", "err", err)
	}
	grpcSrv.GracefulStop()
	cancel()           // 停止 Kafka 检查
	taskPool.Release() // 等待所有 Zeek 任务完成
	slog.Info("Bye")
}

// 辅助函数
func response(c *gin.Context, code int, msg string, err error) {
	if err != nil {
		slog.Error(msg, "err", err)
	}
	c.JSON(http.StatusOK, gin.H{"code": code, "msg": msg})
}

func success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "data": data})
}

func cmdHandler(name string, args ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			response(c, 500, "cmd failed", err)
			return
		}
		success(c, gin.H{"output": strings.TrimSpace(string(out))})
	}
}

func isFileExist(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
