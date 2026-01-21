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
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// 全局配置与状态
var (
	taskPool      *ants.Pool
	kafkaReady    bool
	kafkaReadyMux sync.RWMutex
)

// LimitWriter 用于限制日志捕获大小，防止内存爆炸
type LimitWriter struct {
	w io.Writer
	n int64
}

func (l *LimitWriter) Write(p []byte) (n int, err error) {
	if l.n <= 0 {
		return len(p), nil // 超过限制后直接丢弃，返回成功欺骗调用者
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err = l.w.Write(p)
	l.n -= int64(n)
	return
}

func initTaskPool(size int) error {
	var err error
	// 启用阻塞模式：当池满时，调用者会阻塞等待，而不是直接报错（根据业务需求也可设为非阻塞）
	// 这里保持原意使用 Nonblocking(true)
	taskPool, err = ants.NewPool(size, ants.WithNonblocking(true))
	return err
}

type GRPCServer struct {
	pb.UnimplementedZeekAnalysisServiceServer
}

// 统一的任务执行包装器
func executeTaskInPool(ctx context.Context, req AnalyzeReq) (*AnalyzeResp, error) {
	// 创建结果通道
	type result struct {
		output []byte
		err    error
	}
	resultChan := make(chan result, 1)

	// 提交任务到协程池
	err := taskPool.Submit(func() {
		out, e := runZeekAnalysis(req)
		select {
		case resultChan <- result{output: out, err: e}:
		case <-ctx.Done():
			// 如果外部已经取消，就不发送了
		}
	})

	if err != nil {
		if errors.Is(err, ants.ErrPoolOverload) {
			return nil, status.Errorf(codes.ResourceExhausted, "task pool is full (capacity: %d)", taskPool.Cap())
		}
		return nil, status.Errorf(codes.Internal, "failed to submit task: %v", err)
	}

	// 等待结果或超时/取消
	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, fmt.Errorf("%w. Output: %s", res.err, string(res.output))
		}
		return &AnalyzeResp{
			TaskID:     req.TaskID,
			UUID:       req.UUID,
			PcapPath:   req.PcapPath,
			ScriptPath: req.ScriptPath,
			StartTime:  time.Now().Format(time.RFC3339),
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *GRPCServer) Analyze(ctx context.Context, req *pb.AnalyzeRequest) (*pb.AnalyzeResponse, error) {
	analyzeReq := AnalyzeReq{
		TaskID:               req.TaskID,
		UUID:                 req.Uuid,
		OnlyNotice:           req.OnlyNotice,
		PcapID:               req.PcapID,
		PcapPath:             req.PcapPath,
		ScriptID:             req.ScriptID,
		ScriptPath:           req.ScriptPath,
		ExtractedFilePath:    req.ExtractedFilePath,
		ExtractedFileMinSize: int(req.ExtractedFileMinSize),
	}

	if err := validateAnalyzeReq(analyzeReq); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	resp, err := executeTaskInPool(ctx, analyzeReq)
	if err != nil {
		// 简单的错误映射逻辑
		if strings.Contains(err.Error(), "pool is full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		slog.Error("gRPC Analysis failed", "err", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	slog.Info("gRPC Analysis succeeded", "taskID", analyzeReq.TaskID)
	return &pb.AnalyzeResponse{
		TaskID:     resp.TaskID,
		Uuid:       resp.UUID,
		PcapPath:   resp.PcapPath,
		ScriptPath: resp.ScriptPath,
		StartTime:  resp.StartTime,
	}, nil
}

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

func validateAnalyzeReq(req AnalyzeReq) error {
	if req.ExtractedFilePath != "" {
		if req.ExtractedFileMinSize <= 0 {
			req.ExtractedFileMinSize = 1
		}
	}
	if req.TaskID == "" {
		return errors.New("TaskID is required")
	}
	if req.UUID == "" {
		return errors.New("UUID is required")
	}
	if req.PcapPath == "" {
		return errors.New("PCAP file path is required")
	}
	// 注意：Docker环境下，检查文件存在性可能因为挂载延迟有误判，
	// 但做基本的检查是好的。
	if !isFileExist(req.PcapPath) {
		return fmt.Errorf("PCAP file does not exist: %s", req.PcapPath)
	}
	if req.ScriptPath == "" {
		return errors.New("zeek script path is required")
	}
	if !isFileExist(req.ScriptPath) {
		return fmt.Errorf("zeek script file does not exist: %s", req.ScriptPath)
	}
	return nil
}

func runZeekAnalysis(req AnalyzeReq) ([]byte, error) {
	timeoutStr := os.Getenv("ZEEK_TIMEOUT_MINUTES")
	timeoutMinutes := 5
	if val, err := strconv.Atoi(timeoutStr); err == nil && val > 0 {
		timeoutMinutes = val
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMinutes)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zeek", "-Cr", req.PcapPath, req.ScriptPath)

	// 设置进程组，确保超时能杀死所有子进程
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// 环境变量设置
	env := os.Environ()
	envMap := map[string]string{
		"TASK_ID":                 req.TaskID,
		"UUID":                    req.UUID,
		"ONLY_NOTICE":             strconv.FormatBool(req.OnlyNotice),
		"PCAP_ID":                 req.PcapID,
		"PCAP_PATH":               req.PcapPath,
		"SCRIPT_ID":               req.ScriptID,
		"SCRIPT_PATH":             req.ScriptPath,
		"EXTRACTED_FILE_PATH":     req.ExtractedFilePath,
		"EXTRACTED_FILE_MIN_SIZE": strconv.Itoa(req.ExtractedFileMinSize),
	}
	for k, v := range envMap {
		if v != "" && v != "0" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env

	// 内存安全保护
	// 只捕获 stderr 的前 4KB，丢弃 stdout（通常日志去 Kafka 或文件了）
	// 防止日志过大导致 OOM
	var errBuf bytes.Buffer
	cmd.Stdout = io.Discard // 丢弃标准输出
	cmd.Stderr = &LimitWriter{w: &errBuf, n: 4096}

	startTime := time.Now()
	err := cmd.Run()

	output := errBuf.Bytes()

	if err != nil {
		// 检查超时
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// 尝试杀死进程组
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return output, fmt.Errorf("zeek analysis timed out after %d minutes", timeoutMinutes)
		}

		slog.Error("Zeek command failed",
			"error", err,
			"stderr_tail", string(output),
			"taskID", req.TaskID,
		)
		return output, err
	}

	slog.Info("Zeek analysis completed",
		"taskID", req.TaskID,
		"duration", time.Since(startTime))

	return output, nil
}

func handleZeekAnalysis(c *gin.Context) {
	var req AnalyzeReq
	if err := c.BindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param: "+err.Error(), err)
		return
	}

	// 这里的 ctx 是 HTTP 请求的 ctx，如果客户端断开，context 会取消
	// executeTaskInPool 会处理这个 ctx
	resp, err := executeTaskInPool(c.Request.Context(), req)
	if err != nil {
		// 如果是资源耗尽，返回特定错误
		if strings.Contains(err.Error(), "pool is full") {
			HandleError(c, http.StatusServiceUnavailable, "server is busy, please try again later", err)
			return
		}
		// 内部错误
		HandleError(c, http.StatusInternalServerError, err.Error(), err)
		return
	}

	Success(c, resp)
}

func checkKafka() {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		slog.Warn("KAFKA_BROKERS not set, skipping Kafka check")
		return
	}

	// 后台持续检查 Kafka 连接
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := kafka.DialContext(ctx, "tcp", brokers)
			if err != nil {
				setKafkaStatus(false)
				slog.Warn("Kafka connection failed (retrying in 30s)", "error", err)
			} else {
				conn.Close() // 仅仅是探测，立即关闭
				if !getKafkaStatus() {
					slog.Info("Kafka connection established")
				}
				setKafkaStatus(true)
			}
			cancel()

			// 30秒检查一次
			time.Sleep(30 * time.Second)
		}
	}()
}

func setKafkaStatus(status bool) {
	kafkaReadyMux.Lock()
	defer kafkaReadyMux.Unlock()
	kafkaReady = status
}

func getKafkaStatus() bool {
	kafkaReadyMux.RLock()
	defer kafkaReadyMux.RUnlock()
	return kafkaReady
}

// 移除硬编码路径，改用 Gin 的 Group
func securityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("User-Agent") == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "msg": "User-Agent is required"})
			return
		}
		c.Next()
	}
}

func main() {
	// Logger 配置 (JSON格式更适合生产环境)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	poolSize, err := strconv.Atoi(os.Getenv("ZEEK_CONCURRENT_TASKS"))
	if err != nil || poolSize <= 0 {
		poolSize = 8
	}

	if err := initTaskPool(poolSize); err != nil {
		slog.Error("Failed to initialize task pool", "error", err)
		os.Exit(1)
	}
	defer taskPool.Release()

	// 启动 Kafka 检查 (不再阻塞主线程，也不再退出程序)
	checkKafka()

	// 启动 HTTP 服务
	go func() {
		r := gin.New() // 使用 New 而不是 Default，避免重复日志
		r.Use(gin.Recovery())

		// 定义公开路由（如健康检查）
		r.GET("/api/v1/healthz", func(c *gin.Context) {
			status := "ok"
			if !getKafkaStatus() {
				status = "warning: kafka disconnected"
			}
			c.JSON(http.StatusOK, gin.H{"status": status, "pool_running": taskPool.Running()})
		})

		// 定义受保护路由
		api := r.Group("/api/v1")
		api.Use(securityMiddleware())
		{
			api.POST("/analyze", handleZeekAnalysis)
			api.GET("/version/zeek", getZeekVersion)
			api.GET("/version/zeek-kafka", getZeekKafkaVersion)
		}

		slog.Info("HTTP server listening on :8000")
		if err := r.Run(":8000"); err != nil {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	// 启动 gRPC 服务
	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			slog.Error("Failed to listen for gRPC", "error", err)
			os.Exit(1)
		}
		grpcServer := grpc.NewServer()
		pb.RegisterZeekAnalysisServiceServer(grpcServer, &GRPCServer{})
		reflection.Register(grpcServer)

		slog.Info("gRPC server starting on :50051")
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC server error", "error", err)
		}
	}()

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down server...")

	// 这里可以添加等待 taskPool 关闭的逻辑，如果 ants 支持的话
}

// 辅助函数保持原样，略微清理
func getZeekVersion(c *gin.Context) {
	cmd := exec.Command("zeek", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "failed to get Zeek version", err)
		return
	}
	Success(c, gin.H{"version": strings.TrimSpace(string(output))})
}

func getZeekKafkaVersion(c *gin.Context) {
	cmd := exec.Command("zeek", "-N", "Seiso::Kafka")
	output, err := cmd.CombinedOutput()
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "failed to check zeek-kafka", err)
		return
	}
	Success(c, gin.H{"version": strings.TrimSpace(string(output))})
}

func HandleError(ctx *gin.Context, code int, message string, err error) {
	if err != nil {
		slog.Error(message, "error", err)
	}
	// 保持原有的业务逻辑：HTTP 状态码也是 200，通过 JSON 中的 code 区分
	ctx.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  message,
	})
}

func Success(ctx *gin.Context, data any) {
	ctx.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func isFileExist(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
