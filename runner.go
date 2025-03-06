package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	// 创建 Gin 路由
	r := gin.Default()

	// 分析接口
	r.POST("/analyze", func(c *gin.Context) {
		// 获取文件名
		pcapFilepath := c.PostForm("pcap_file_path")
		zeekScriptPath := c.PostForm("zeek_script_path")
		fmt.Println("@@@ pcapFilepath:", pcapFilepath)
		fmt.Println("@@@ zeekScriptPath:", zeekScriptPath)
		if pcapFilepath == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "pcapFilepath is required"})
			return
		}

		if zeekScriptPath == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "zeekScriptPath is required"})
			return
		}

		// 设置环境变量并调用 Zeek 分析 PCAP 文件
		os.Setenv("ZEEK_PCAP_FILE_PATH", pcapFilepath)
		os.Setenv("ZEEK_SCRIPT_PATH", zeekScriptPath)

		// 检查文件是否存在
		if _, err := os.Stat(pcapFilepath); os.IsNotExist(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ZEEK_PCAP_FILE_PATH does not exist"})
			return
		}

		if _, err := os.Stat(zeekScriptPath); os.IsNotExist(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ZEEK_SCRIPT_PATH does not exist"})
			return
		}

		cmd := exec.Command("zeek", "-Cr", pcapFilepath, zeekScriptPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Zeek analysis failed",
				"output": string(output),
			})
			return
		}

		// 返回分析结果
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
		})
	})

	r.GET("/version", func(c *gin.Context) {
		cmd := exec.Command("zeek", "--version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Failed to get Zeek version",
				"output": string(output),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"version": string(output),
		})
	})

	// 新增检查 zeek-kafka 安装的接口
	r.GET("/check-zeek-kafka", func(c *gin.Context) {
		cmd := exec.Command("zeek", "-N", "Seiso::Kafka")
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Failed to check zeek-kafka installation",
				"output": string(output),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"output": string(output),
		})
	})

	// 启动服务
	if err := r.Run(":8000"); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}
