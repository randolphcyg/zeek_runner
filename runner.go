package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// 定义全局任务池
var (
	taskPool *ants.Pool
	poolOnce sync.Once
)

// 初始化任务池
func initTaskPool(size int) error {
	var err error
	poolOnce.Do(func() {
		taskPool, err = ants.NewPool(size, ants.WithNonblocking(true))
	})
	return err
}

type GRPCServer struct {
	pb.UnimplementedZeekAnalysisServiceServer
}

// 定义可重试的错误类型
var retryableErrors = map[string]bool{
	"cannot create hub": true,
	"signal: killed":    true,
	"signal: aborted":   true,
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

	// 验证请求
	if err := validateAnalyzeReq(analyzeReq); err != nil {
		slog.Error("Call Zeek err", "InvalidArgument", err.Error())
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	// 创建结果通道
	resultChan := make(chan error, 1)

	// 提交任务到任务池
	err := taskPool.Submit(func() {
		_, err := runZeekAnalysis(analyzeReq)
		resultChan <- err
	})

	if err != nil {
		if errors.Is(err, ants.ErrPoolOverload) {
			return nil, status.Errorf(codes.ResourceExhausted, "task pool is full, please try again later")
		}
		return nil, status.Errorf(codes.Internal, "failed to submit task: %v", err)
	}

	// 等待任务完成
	select {
	case err := <-resultChan:
		if err != nil {
			// 检查是否是可重试的错误
			errorMsg := err.Error()
			isRetryable := false
			for retryableErr := range retryableErrors {
				if strings.Contains(errorMsg, retryableErr) {
					isRetryable = true
					break
				}
			}

			if isRetryable {
				return nil, status.Errorf(codes.Unavailable, "temporary error, please retry: %v", err)
			}

			slog.Error("Zeek analysis err", "Internal", err.Error())
			return nil, status.Errorf(codes.Internal, "analysis failed: %v", err)
		}
	case <-ctx.Done():
		return nil, status.Errorf(codes.Canceled, "request canceled")
	}

	// 构造响应
	resp := &pb.AnalyzeResponse{
		TaskID:     analyzeReq.TaskID,
		Uuid:       analyzeReq.UUID,
		PcapPath:   analyzeReq.PcapPath,
		ScriptPath: analyzeReq.ScriptPath,
		StartTime:  time.Now().Format(time.RFC3339),
	}

	slog.Info("Zeek analysis succeeded",
		"taskID", req.TaskID,
		"uuid", req.Uuid,
		"pcapPath", req.PcapPath,
		"script", req.ScriptPath,
		"StartTime", time.Now().Format(time.RFC3339),
	)
	return resp, nil
}

// AnalyzeReq 分析接口请求体
type AnalyzeReq struct {
	TaskID               string `json:"taskID"`
	UUID                 string `json:"uuid"`
	OnlyNotice           bool   `json:"onlyNotice"`           // 区分是否只生成notice日志
	PcapID               string `json:"pcapID"`               // pcap文件ID
	PcapPath             string `json:"pcapPath"`             // pcap文件路径
	ScriptID             string `json:"scriptID"`             // 脚本ID
	ScriptPath           string `json:"scriptPath"`           // 脚本路径
	ExtractedFilePath    string `json:"extractedFilePath"`    // 提取文件存储路径 若存在则证明文件提取模式 >> 不要 onlyNotice 给true
	ExtractedFileMinSize int    `json:"extractedFileMinSize"` // 提取文件最小大小(KB)
}

// AnalyzeResp 分析接口响应体
type AnalyzeResp struct {
	TaskID     string `json:"taskID"`
	UUID       string `json:"uuid"`
	PcapPath   string `json:"pcapPath"`
	ScriptPath string `json:"scriptPath"`
	StartTime  string `json:"startTime"` // 任务开始时间
}

func validateAnalyzeReq(req AnalyzeReq) error {
	if req.ExtractedFilePath != "" {
		if req.ExtractedFileMinSize <= 0 {
			req.ExtractedFileMinSize = 1 // 默认1KB
		}
		slog.Info("文件提取模式", "提取文件存储路径", req.ExtractedFilePath,
			"提取文件最小限制", req.ExtractedFileMinSize)
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
	if !isFileExist(req.PcapPath) {
		return errors.New("PCAP file does not exist")
	}
	if req.ScriptPath == "" {
		return errors.New("zeek script path is required")
	}
	if !isFileExist(req.ScriptPath) {
		return errors.New("zeek script file does not exist")
	}
	return nil
}

func runZeekAnalysis(req AnalyzeReq) ([]byte, error) {
	timeoutMinutes, err := strconv.Atoi(os.Getenv("ZEEK_TIMEOUT_MINUTES"))
	if err != nil || timeoutMinutes <= 0 {
		timeoutMinutes = 5
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMinutes)*time.Minute)
	defer cancel()

	// 使用 Zeek 命令
	cmd := exec.CommandContext(ctx, "zeek", "-Cr", req.PcapPath, req.ScriptPath)

	// 设置环境变量
	env := os.Environ()
	if req.TaskID != "" {
		env = append(env, "TASK_ID="+req.TaskID)
	}
	if req.UUID != "" {
		env = append(env, "UUID="+req.UUID)
	}
	if req.OnlyNotice {
		env = append(env, "ONLY_NOTICE="+strconv.FormatBool(req.OnlyNotice))
	}
	if req.PcapID != "" {
		env = append(env, "PCAP_ID="+req.PcapID)
	}
	if req.PcapPath != "" {
		env = append(env, "PCAP_PATH="+req.PcapPath)
	}
	if req.ScriptID != "" {
		env = append(env, "SCRIPT_ID="+req.ScriptID)
	}
	if req.ScriptPath != "" {
		env = append(env, "SCRIPT_PATH="+req.ScriptPath)
	}
	if req.ExtractedFilePath != "" {
		env = append(env, "EXTRACTED_FILE_PATH="+req.ExtractedFilePath)
	}
	if req.ExtractedFileMinSize > 0 {
		env = append(env, "EXTRACTED_FILE_MIN_SIZE="+strconv.Itoa(req.ExtractedFileMinSize))
	}

	cmd.Env = env

	// 捕获标准输出和标准错误
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	// 记录开始时间
	startTime := time.Now()

	err = cmd.Run()
	output := append(outb.Bytes(), errb.Bytes()...) // 合并标准输出和标准错误

	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return output, errors.New("zeek analysis timed out after " + strconv.Itoa(timeoutMinutes) + " minutes")
		}

		// 记录完整的错误输出
		fullErrorOutput := string(output)
		slog.Error("Zeek command failed",
			"error", err,
			"output", fullErrorOutput,
			"taskID", req.TaskID,
			"uuid", req.UUID,
			"processing_time", time.Since(startTime))
		return output, fmt.Errorf("zeek execution failed: %w. Output: %s", err, fullErrorOutput)
	}

	// 记录成功信息
	slog.Info("Zeek analysis completed",
		"taskID", req.TaskID,
		"uuid", req.UUID,
		"processing_time", time.Since(startTime))

	return output, nil
}

func handleZeekAnalysis(c *gin.Context) {
	var req AnalyzeReq
	if err := c.BindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param:"+err.Error(), err)
		return
	}
	if err := validateAnalyzeReq(req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid request:"+err.Error(), err)
		return
	}

	output, err := runZeekAnalysis(req)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, string(output), err)
		return
	}

	var resp AnalyzeResp
	resp = AnalyzeResp{
		TaskID:     req.TaskID,
		UUID:       req.UUID,
		PcapPath:   req.PcapPath,
		ScriptPath: req.ScriptPath,
		StartTime:  time.Now().Format(time.RFC3339),
	}
	slog.Info("Zeek analysis succeeded",
		"taskID", req.TaskID,
		"uuid", req.UUID,
		"pcapPath", req.PcapPath,
		"script", req.ScriptPath,
		"StartTime", time.Now().Format(time.RFC3339),
	)
	Success(c, resp)
}

func checkKafka() error {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		return fmt.Errorf("KAFKA_BROKERS environment variable not set")
	}

	// 创建可取消的上下文（设置超时）
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 连接任意一个 Broker 并获取集群元数据
	conn, err := kafka.DialContext(ctx, "tcp", brokers)
	if err != nil {
		return fmt.Errorf("failed to dial Kafka: %w", err)
	}
	defer conn.Close()

	// 获取 Broker 列表
	if _, err := conn.Brokers(); err != nil {
		return fmt.Errorf("failed to get brokers: %w", err)
	}

	return nil
}

// 在 Gin 中添加中间件
func addSecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 禁止空 User-Agent
		if c.GetHeader("User-Agent") == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User-Agent is required"})
			return
		}

		allowedPaths := map[string]bool{
			"/api/v1/analyze":            true,
			"/api/v1/version/zeek":       true,
			"/api/v1/version/zeek-kafka": true,
			"/api/v1/healthz":            true,
		}
		if !allowedPaths[c.Request.URL.Path] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "path not allowed"})
			return
		}

		c.Next()
	}
}

func main() {
	// 从环境变量获取并发数，默认为 8
	poolSize, err := strconv.Atoi(os.Getenv("ZEEK_CONCURRENT_TASKS"))
	if err != nil || poolSize <= 0 {
		poolSize = 8
	}

	// 初始化任务池
	if err := initTaskPool(poolSize); err != nil {
		slog.Error("Failed to initialize task pool", "error", err)
		os.Exit(1)
	}
	defer taskPool.Release()

	// 启动 Kafka 连接检查（带重试）
	go func() {
		maxRetries := 3
		retryDelay := 5 * time.Second
		var kafkaErr error

		for i := 0; i < maxRetries; i++ {
			kafkaErr = checkKafka()
			if kafkaErr == nil {
				slog.Info("Kafka connection successful!")
				return
			}

			slog.Error("Kafka check failed",
				"attempt", i+1,
				"max_retries", maxRetries,
				"error", kafkaErr,
			)
			if i == maxRetries-1 {
				slog.Error("All Kafka connection attempts failed",
					"final_error", kafkaErr,
					"action", "service_will_not_start",
				)
				os.Exit(1)
			}
			time.Sleep(retryDelay)
		}
	}()

	// 启动 HTTP 服务（异步）
	go func() {
		r := gin.Default()
		api := r.Group("/api/v1")
		api.Use(addSecurityMiddleware())
		{
			api.POST("/analyze", handleZeekAnalysis)
			api.GET("/version/zeek", getZeekVersion)
			api.GET("/version/zeek-kafka", getZeekKafkaVersion)
			// 健康检查接口
			api.GET("/healthz", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
		}

		if err := r.Run(":8000"); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server stopped", "error", err)
		}
	}()

	// 启动 gRPC 服务（异步）
	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			panic(err)
		}
		grpcServer := grpc.NewServer()
		pb.RegisterZeekAnalysisServiceServer(grpcServer, &GRPCServer{})
		reflection.Register(grpcServer)

		slog.Info("gRPC server starting on :50051")
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			slog.Error("gRPC server stopped", "error", err)
		}
	}()

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down server...")
}

type zeekVersionResp struct {
	Version string `json:"version"`
}

func getZeekVersion(c *gin.Context) {
	cmd := exec.Command("zeek", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		HandleError(c, http.StatusInternalServerError, string(output), errors.New("failed to get Zeek version"))
		return
	}

	var resp zeekVersionResp
	resp.Version = string(output)
	Success(c, resp)
}

type zeekKafkaVersionResp struct {
	Version string `json:"version"`
}

func getZeekKafkaVersion(c *gin.Context) {
	cmd := exec.Command("zeek", "-N", "Seiso::Kafka")
	output, err := cmd.CombinedOutput()
	if err != nil {
		HandleError(c, http.StatusInternalServerError, string(output), errors.New("failed to check zeek-kafka installation"))
		return
	}

	var resp zeekKafkaVersionResp
	resp.Version = string(output)
	Success(c, resp)
}

func HandleError(ctx *gin.Context, code int, message string, err error) {
	if err != nil {
		slog.Error(message, slog.Any("error", err))
	}
	ctx.JSON(200, gin.H{
		"code": code,
		"msg":  message,
	})
}

func Success(ctx *gin.Context, data any) {
	ctx.JSON(200, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func isFileExist(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
