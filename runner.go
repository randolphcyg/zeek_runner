package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"

	"github.com/gin-gonic/gin"
)

const customScriptPath = "/app/init.zeek" // copy到容器中的init.zeek脚本位置

// AnalyzeReq 分析接口请求体
type AnalyzeReq struct {
	PCAPFilePath   string `json:"pcap_file_path"`
	ZeekScriptPath string `json:"zeek_script_path"`
	OnlyNotice     bool   `json:"only_notice"`
	UUID           string `json:"uuid"`
}

// AnalyzeError 自定义错误类型
type AnalyzeError struct {
	StatusCode int
	Message    string
}

func (e *AnalyzeError) Error() string {
	return e.Message
}

// 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// 执行 Zeek 分析
func runZeekAnalysis(pcapFilePath, zeekScriptPath, customScriptPath string) ([]byte, error) {
	cmd := exec.Command("zeek", "-Cr", pcapFilePath, customScriptPath, zeekScriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, &AnalyzeError{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("Zeek analysis failed: %v, output: %s", err, string(output)),
		}
	}
	return output, nil
}

func main() {
	r := gin.Default()

	// 分析接口
	r.POST("/analyze", func(c *gin.Context) {
		var req AnalyzeReq
		if err := c.BindJSON(&req); err != nil {
			slog.Warn("解析 JSON 数据失败", "error", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
			return
		}

		// 验证请求参数
		if req.PCAPFilePath == "" {
			slog.Warn("未设置 PCAP file path")
			c.JSON(http.StatusBadRequest, gin.H{"error": "PCAP file path is required"})
			return
		}
		if req.ZeekScriptPath == "" {
			slog.Warn("未设置 Zeek script path")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Zeek script path is required"})
			return
		}
		if req.UUID == "" {
			slog.Warn("未设置UUID")
			c.JSON(http.StatusBadRequest, gin.H{"error": "UUID is required"})
			return
		}

		// 设置环境变量
		os.Setenv("PCAP_FILE_PATH", req.PCAPFilePath)
		os.Setenv("ZEEK_SCRIPT_PATH", req.ZeekScriptPath)
		os.Setenv("ONLY_NOTICE", strconv.FormatBool(req.OnlyNotice))
		os.Setenv("UUID", req.UUID)

		// 检查文件是否存在
		if !fileExists(req.PCAPFilePath) {
			slog.Warn("PCAP file does not exist", "path", req.PCAPFilePath)
			c.JSON(http.StatusBadRequest, gin.H{"error": "PCAP file path does not exist"})
			return
		}
		if !fileExists(req.ZeekScriptPath) {
			slog.Warn("Zeek script file does not exist", "path", req.ZeekScriptPath)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Zeek script path does not exist"})
			return
		}

		// 执行 Zeek 分析
		output, err := runZeekAnalysis(req.PCAPFilePath, req.ZeekScriptPath, customScriptPath)
		if err != nil {
			if analyzeErr, ok := err.(*AnalyzeError); ok {
				slog.Error(analyzeErr.Message)
				c.JSON(analyzeErr.StatusCode, gin.H{
					"error":  analyzeErr.Message,
					"output": string(output),
				})
			} else {
				slog.Error("Zeek analysis failed", "error", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":  "Zeek analysis failed",
					"output": string(output),
				})
			}
			return
		}

		// 返回分析结果
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"uuid":   req.UUID,
		})
		slog.Info("Zeek analysis succeeded",
			"pcap_file", req.PCAPFilePath,
			"zeek_script", req.ZeekScriptPath,
			"uuid", req.UUID)
	})

	// zeek版本接口
	r.GET("/version", func(c *gin.Context) {
		cmd := exec.Command("zeek", "--version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Failed to get Zeek version",
				"output": string(output),
			})
			slog.Error("Failed to get Zeek version", "error", err, "output", string(output))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"version": string(output),
		})
		slog.Info("Successfully retrieved Zeek version", "version", string(output))
	})

	// 检查 zeek-kafka 版本接口
	r.GET("/check-zeek-kafka", func(c *gin.Context) {
		cmd := exec.Command("zeek", "-N", "Seiso::Kafka")
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Failed to check zeek-kafka installation",
				"output": string(output),
			})
			slog.Error("Failed to check zeek-kafka installation", "error", err, "output", string(output))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"output": string(output),
		})
		slog.Info("Zeek-kafka installation check succeeded", "output", string(output))
	})

	// 启动服务
	if err := r.Run(":8000"); err != nil {
		slog.Error("Failed to start server", "error", err)
	}
}
