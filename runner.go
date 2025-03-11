package main

import (
	"log/slog"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

const customScriptPath = "/app/init.zeek" // copy到容器中的init.zeek脚本位置

func main() {
	// 创建 Gin 路由
	r := gin.Default()

	// 分析接口
	r.POST("/analyze", func(c *gin.Context) {
		pcapFilePath := c.PostForm("pcap_file_path")
		zeekScriptPath := c.PostForm("zeek_script_path")
		onlyNotice := c.PostForm("only_notice")
		uuid := c.PostForm("uuid")
		slog.Info("Received pcap and script path",
			"pcap_file_path", pcapFilePath,
			"zeek_script_path", zeekScriptPath,
			"only_notice", onlyNotice)
		if pcapFilePath == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "PCAP file path is required"})
			slog.Warn("未设置 PCAP file path")
			return
		}

		if zeekScriptPath == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Zeek script path is required"})
			slog.Warn("未设置 Zeek script path")
			return
		}

		if onlyNotice == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Only notice flag is required"})
			slog.Warn("未设置 Only notice flag")
			return
		}

		if uuid == "" {
			c.JSON(400, gin.H{"error": "UUID is required"})
			slog.Warn("未设置UUID")
			return
		}

		// 设置 zeek 脚本须用的环境变量并调用 zeek 分析 PCAP 文件
		os.Setenv("PCAP_FILE_PATH", pcapFilePath)
		os.Setenv("ZEEK_SCRIPT_PATH", zeekScriptPath)
		os.Setenv("ONLY_NOTICE", onlyNotice)
		os.Setenv("UUID", uuid)

		// 检查文件是否存在
		if _, err := os.Stat(pcapFilePath); os.IsNotExist(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "PCAP file path does not exist"})
			slog.Warn("PCAP file does not exist", "path", pcapFilePath)
			return
		}

		if _, err := os.Stat(zeekScriptPath); os.IsNotExist(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Zeek script path does not exist"})
			slog.Warn("Zeek script file does not exist", "path", zeekScriptPath)
			return
		}

		cmd := exec.Command("zeek", "-Cr", pcapFilePath, customScriptPath, zeekScriptPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Zeek analysis failed",
				"output": string(output),
			})
			slog.Error("Zeek analysis failed", "error", err, "output", string(output))
			return
		}

		// 返回分析结果
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"uuid":   uuid,
		})
		slog.Info("Zeek analysis succeeded",
			"pcap_file", pcapFilePath,
			"zeek_script", zeekScriptPath,
			"uuid", uuid)
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
