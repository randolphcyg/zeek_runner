package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/kafka-go"
)

// AnalyzeReq 分析接口请求体
type AnalyzeReq struct {
	ExtractedFilePath    string `json:"extracted_file_path"`     // 提取文件存储路径 若存在则证明文件提取模式 >> 不要 only_notice 给true
	ExtractedFileMinSize int    `json:"extracted_file_min_size"` //提取文件最小大小(KB)
	OnlyNotice           bool   `json:"only_notice"`             // 区分是否只生成notice日志
	TaskID               string `json:"task_id"`
	UUID                 string `json:"uuid"`
	PCAPFilePath         string `json:"pcap_file_path"`
	ZeekScriptPath       string `json:"zeek_script_path"`
}

// AnalyzeResp 分析接口响应体
type AnalyzeResp struct {
	TaskID         string `json:"task_id"`
	UUID           string `json:"uuid"`
	PCAPFilePath   string `json:"pcap_file_path"`
	ZeekScriptPath string `json:"zeek_script_path"`
	StartTime      string `json:"start_time"` // 任务开始时间
}

func validateAnalyzeReq(req AnalyzeReq) error {
	if req.ExtractedFilePath != "" {
		if req.ExtractedFileMinSize <= 0 {
			req.ExtractedFileMinSize = 1 // 默认1KB
		}
		slog.Info("文件提取模式", "提取文件存储路径", req.ExtractedFilePath,
			"提取文件最小限制", req.ExtractedFileMinSize)
	}
	if req.PCAPFilePath == "" {
		return errors.New("PCAP file path is required")
	}
	if req.ZeekScriptPath == "" {
		return errors.New("zeek script path is required")
	}
	if req.UUID == "" {
		return errors.New("UUID is required")
	}
	if req.TaskID == "" {
		return errors.New("TaskID is required")
	}
	if !isFileExist(req.PCAPFilePath) {
		return errors.New("PCAP file does not exist")
	}
	if !isFileExist(req.ZeekScriptPath) {
		return errors.New("zeek script file does not exist")
	}
	return nil
}

// 执行 Zeek 分析
func runZeekAnalysis(req AnalyzeReq) ([]byte, error) {
	timeoutMinutes, err := strconv.Atoi(os.Getenv("ZEEK_TIMEOUT_MINUTES"))
	if err != nil || timeoutMinutes <= 0 {
		timeoutMinutes = 5
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMinutes)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zeek", "-Cr", req.PCAPFilePath, req.ZeekScriptPath)

	// 设置独立环境变量
	cmd.Env = append(os.Environ(),
		"EXTRACTED_FILE_PATH="+req.ExtractedFilePath,
		"EXTRACTED_FILE_MIN_SIZE="+strconv.Itoa(req.ExtractedFileMinSize),
		"PCAP_FILE_PATH="+req.PCAPFilePath,
		"ZEEK_SCRIPT_PATH="+req.ZeekScriptPath,
		"ONLY_NOTICE="+strconv.FormatBool(req.OnlyNotice),
		"UUID="+req.UUID,
		"TASK_ID="+req.TaskID,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return output, errors.New("zeek analysis timed out after " + strconv.Itoa(timeoutMinutes) + " minutes")
		}
		return output, err
	}
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
		TaskID:         req.TaskID,
		UUID:           req.UUID,
		PCAPFilePath:   req.PCAPFilePath,
		ZeekScriptPath: req.ZeekScriptPath,
		StartTime:      time.Now().Format(time.RFC3339),
	}
	slog.Info("Zeek analysis succeeded",
		"pcap_file", req.PCAPFilePath,
		"zeek_script", req.ZeekScriptPath,
		"uuid", req.UUID,
		"task_id", req.TaskID,
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

func main() {
	// Kafka 连接检查（带重试）
	maxRetries := 3
	retryDelay := 5 * time.Second
	var kafkaErr error

	for i := 0; i < maxRetries; i++ {
		kafkaErr = checkKafka()
		if kafkaErr == nil {
			slog.Info("Kafka connection successful!")
			break
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
			os.Exit(1) // 非零退出码表示失败
		}
		time.Sleep(retryDelay)
	}

	r := gin.Default()

	api := r.Group("/api/v1")
	{
		api.POST("/analyze", handleZeekAnalysis)            // 分析接口
		api.GET("/version/zeek", getZeekVersion)            // zeek版本接口
		api.GET("/version/zeek-kafka", getZeekKafkaVersion) // 检查 zeek-kafka 版本接口
	}

	// 启动服务
	if err := r.Run(":8000"); err != nil {
		slog.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
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
