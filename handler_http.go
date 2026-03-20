package main

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type HTTPHandler struct {
	service *Service
	app     *App
}

func NewHTTPHandler(service *Service, app *App) *HTTPHandler {
	return &HTTPHandler{service: service, app: app}
}

func (h *HTTPHandler) HandleAnalysis(c *gin.Context) {
	var req AnalyzeReq
	if err := c.BindJSON(&req); err != nil {
		response(c, http.StatusBadRequest, "invalid params", err)
		return
	}

	if req.ExtractedFilePath != "" && req.ScriptID == "" {
		req.ScriptID = "EXTRACT_TASK"
	}

	if err := validateReq(req); err != nil {
		response(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	resp, err := h.service.ExecuteTaskInPool(c.Request.Context(), req)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "pool full") {
			code = http.StatusServiceUnavailable
		}
		response(c, code, err.Error(), err)
		return
	}
	success(c, resp)
}

type SyntaxCheckReq struct {
	ScriptPath    string `json:"scriptPath"`
	ScriptContent string `json:"scriptContent"`
}

type SyntaxCheckResult struct {
	Valid bool
	Error string
}

func doSyntaxCheck(scriptPath, scriptContent string) (*SyntaxCheckResult, error) {
	if scriptPath == "" && scriptContent == "" {
		return nil, errors.New("script_path or script_content is required")
	}

	var inputPath string
	var cleanup func()
	isTempFile := false

	if scriptContent != "" {
		tmpFile, err := os.CreateTemp("", "zeek_syntax_*.zeek")
		if err != nil {
			return nil, err
		}
		if _, err := tmpFile.WriteString(scriptContent); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, err
		}
		tmpFile.Close()
		inputPath = tmpFile.Name()
		cleanup = func() { os.Remove(inputPath) }
		isTempFile = true
	} else {
		inputPath = scriptPath
		if !isFileExist(inputPath) {
			return nil, errors.New("script file not found: " + inputPath)
		}
	}

	if cleanup != nil {
		defer cleanup()
	}

	cmd := exec.Command("zeek", "--parse-only", inputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := strings.TrimSpace(string(output))
		if isTempFile {
			errMsg = regexp.MustCompile(`error in /tmp/zeek_syntax_\d+\.zeek, `).ReplaceAllString(errMsg, "error in ")
		}
		return &SyntaxCheckResult{Valid: false, Error: errMsg}, nil
	}

	return &SyntaxCheckResult{Valid: true}, nil
}

func (h *HTTPHandler) HandleSyntaxCheck(c *gin.Context) {
	var req SyntaxCheckReq
	if err := c.BindJSON(&req); err != nil {
		response(c, http.StatusBadRequest, "invalid params", err)
		return
	}

	result, err := doSyntaxCheck(req.ScriptPath, req.ScriptContent)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			response(c, http.StatusNotFound, err.Error(), nil)
		} else {
			response(c, http.StatusBadRequest, err.Error(), nil)
		}
		return
	}

	success(c, gin.H{
		"valid": result.Valid,
		"error": result.Error,
	})
}

func (h *HTTPHandler) CmdHandler(name string, args ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			response(c, http.StatusInternalServerError, "command failed", err)
			return
		}
		success(c, gin.H{"version": strings.TrimSpace(string(out))})
	}
}

func (h *HTTPHandler) Healthz(c *gin.Context) {
	msg := "ok"
	if !h.app.IsKafkaReady() {
		msg = "kafka_down"
	}
	cfg := h.app.ConfigManager.Get()
	c.JSON(http.StatusOK, gin.H{
		"status":        msg,
		"pool_running":  h.app.TaskPool.Running(),
		"pool_capacity": cfg.PoolSize,
		"kafka_ready":   h.app.IsKafkaReady(),
		"timestamp":     time.Now().Format(time.RFC3339),
		"version":       "1.0.0",
		"os":            "linux",
		"arch":          "amd64",
	})
}

func response(c *gin.Context, code int, msg string, err error) {
	if err != nil {
		c.JSON(code, gin.H{"code": code, "msg": msg, "error": err.Error()})
	} else {
		c.JSON(code, gin.H{"code": code, "msg": msg})
	}
}

func success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "data": data})
}

func cleanOldTempFiles() {
	files, err := filepath.Glob("/tmp/zeek_syntax_*.zeek")
	if err != nil {
		return
	}
	for _, f := range files {
		os.Remove(f)
	}
}
