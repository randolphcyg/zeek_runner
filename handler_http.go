package main

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	if err := validateReq(req); err != nil {
		response(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	resp, err := h.service.ExecuteTaskInPool(c.Request.Context(), req)
	if err != nil {
		response(c, httpCodeFromError(err), err.Error(), err)
		return
	}

	success(c, resp)
}

// HandleExtract 处理文件提取请求
func (h *HTTPHandler) HandleExtract(c *gin.Context) {
	var req ExtractReq
	if err := c.BindJSON(&req); err != nil {
		response(c, http.StatusBadRequest, "invalid params", err)
		return
	}
	if err := validateExtractReq(req); err != nil {
		response(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	resp, err := h.service.ExecuteExtractTask(c.Request.Context(), req)
	if err != nil {
		response(c, httpCodeFromError(err), err.Error(), err)
		return
	}

	success(c, resp)
}

func (h *HTTPHandler) HandleAsyncAnalysis(c *gin.Context) {
	var req AnalyzeReq
	if err := c.BindJSON(&req); err != nil {
		response(c, http.StatusBadRequest, "invalid params", err)
		return
	}

	if err := validateReq(req); err != nil {
		response(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	task, err := h.service.SubmitAsyncTask(c.Request.Context(), req)
	if err != nil {
		response(c, httpCodeFromError(err), err.Error(), err)
		return
	}

	success(c, gin.H{
		"taskID":     task.TaskID,
		"uuid":       task.UUID,
		"status":     task.Status,
		"createTime": task.CreateTime.Format(time.RFC3339),
	})
}

// HandleExtractAsync 处理异步文件提取请求
func (h *HTTPHandler) HandleExtractAsync(c *gin.Context) {
	var req ExtractReq
	if err := c.BindJSON(&req); err != nil {
		response(c, http.StatusBadRequest, "invalid params", err)
		return
	}
	if err := validateExtractReq(req); err != nil {
		response(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	task, err := h.service.SubmitExtractAsyncTask(c.Request.Context(), req)
	if err != nil {
		// 容量满与依赖故障均映射为 503，但通过 err.Error() 保留明确错误文案以便调用方区分。
		response(c, httpCodeFromError(err), err.Error(), err)
		return
	}

	success(c, gin.H{
		"taskID":     task.TaskID,
		"uuid":       task.UUID,
		"status":     task.Status,
		"createTime": task.CreateTime.Format(time.RFC3339),
	})
}

func (h *HTTPHandler) HandleTaskStatus(c *gin.Context) {
	taskID := c.Param("taskID")
	if taskID == "" {
		response(c, http.StatusBadRequest, "taskID required", nil)
		return
	}

	task, err := h.service.GetTaskStatus(c.Request.Context(), taskID)
	if err != nil {
		response(c, http.StatusNotFound, "task not found", err)
		return
	}

	success(c, task)
}

type SyntaxCheckReq struct {
	ScriptID      string `json:"scriptID"`
	ScriptPath    string `json:"scriptPath"`
	ScriptContent string `json:"scriptContent"`
}

type SyntaxCheckResult struct {
	Valid bool
	Error string
}

func doSyntaxCheck(scriptPath, scriptContent string) (*SyntaxCheckResult, error) {
	if scriptPath == "" && scriptContent == "" {
		return nil, errors.New("scriptID, scriptPath, or scriptContent is required")
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

	cmd := exec.Command("zeek", "--parse-only", inputPath, customConfigPath)
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

	scriptPath, err := h.resolveSyntaxCheckPath(req)
	if err != nil {
		response(c, httpCodeFromError(err), err.Error(), nil)
		return
	}

	result, err := doSyntaxCheck(scriptPath, req.ScriptContent)
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

func (h *HTTPHandler) resolveSyntaxCheckPath(req SyntaxCheckReq) (string, error) {
	if req.ScriptContent != "" {
		return "", nil
	}
	if req.ScriptID != "" {
		script, err := h.service.ResolveManagedScript(req.ScriptID, "")
		if err != nil {
			return "", err
		}
		return script.ScriptPath, nil
	}
	if req.ScriptPath != "" {
		return req.ScriptPath, nil
	}
	return "", errors.New("scriptID, scriptPath, or scriptContent is required")
}

func (h *HTTPHandler) HandleListScripts(c *gin.Context) {
	enabledOnly, _ := strconv.ParseBool(c.Query("enabledOnly"))
	success(c, gin.H{
		"scripts": h.service.ListScripts(ListScriptsRequest{
			Name:        c.Query("name"),
			EnabledOnly: enabledOnly,
		}),
	})
}

func (h *HTTPHandler) HandleGetScript(c *gin.Context) {
	script, err := h.service.GetScript(c.Param("scriptID"))
	if err != nil {
		response(c, httpCodeFromError(err), err.Error(), nil)
		return
	}
	success(c, script)
}

func (h *HTTPHandler) HandleReloadScripts(c *gin.Context) {
	resp, err := h.service.ReloadScripts()
	if err != nil {
		response(c, http.StatusInternalServerError, err.Error(), err)
		return
	}
	success(c, resp)
}

func httpCodeFromError(err error) int {
	switch {
	// 容量满（异步准入 sentinel 或同步 pool 返回的 ResourceExhausted 状态码）-> 503
	case errors.Is(err, ErrCapacityExhausted), status.Code(err) == codes.ResourceExhausted:
		return http.StatusServiceUnavailable
	// 依赖故障（Redis 不可用等）-> 503，不得误报为容量满
	case errors.Is(err, ErrDependencyUnavailable), status.Code(err) == codes.Unavailable:
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrScriptNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrScriptInvalid):
		return http.StatusBadRequest
	case strings.Contains(err.Error(), "scriptPath mismatch"),
		strings.Contains(err.Error(), "required"),
		strings.Contains(err.Error(), "missing"),
		strings.Contains(err.Error(), "invalid"):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
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

	redisReady := h.app.TaskManager != nil
	if redisReady {
		if err := h.app.TaskManager.HealthCheck(c.Request.Context()); err != nil {
			redisReady = false
		}
	}
	snapshot := h.service.resourceSnapshot(c.Request.Context())
	behaviorReady := h.app.IsBehaviorReady()
	rulesetSHA := ""
	rulesVersion := ""
	if h.app.BehaviorEngine != nil {
		rulesetSHA = h.app.BehaviorEngine.rulesetSHA
		rulesVersion = h.app.BehaviorEngine.ruleSet.Version
	}

	c.JSON(http.StatusOK, gin.H{
		"status":            msg,
		"pool_running":      h.app.TaskPool.Running(),
		"pool_capacity":     cfg.Pool.Size,
		"kafka_ready":       h.app.IsKafkaReady(),
		"behavior_ready":    behaviorReady,
		"ruleset_sha256":    rulesetSHA,
		"rules_version":     rulesVersion,
		"redis_ready":       redisReady,
		"timestamp":         time.Now().Format(time.RFC3339),
		"version":           "1.0.0",
		"os":                "linux",
		"arch":              "amd64",
		"queue_pending":     snapshot.QueuePending,
		"weighted_running":  snapshot.WeightedRunning,
		"weighted_capacity": snapshot.WeightedCapacity,
		"cpu_usage":         snapshot.CPUUsage,
		"mem_usage":         snapshot.MemUsage,
		"disk_io_busy":      snapshot.DiskIOBusy,
		"kafka_lag":         snapshot.KafkaLag,
		"accepting_jobs":    snapshot.AcceptingJobs,
	})
}

func response(c *gin.Context, code int, msg string, err error) {
	if err != nil {
		clientIP := c.ClientIP()
		requestID, exists := c.Get("requestID")
		requestIDStr := ""
		if exists {
			requestIDStr = requestID.(string)
		}
		LogHTTPError(c.Request.Method, c.Request.URL.Path, clientIP, code, 0, requestIDStr, err)
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
