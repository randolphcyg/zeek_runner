package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/panjf2000/ants/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	customConfigPath         = "/usr/local/zeek/share/zeek/base/custom/config.zeek"
	defaultExtractScriptPath = "/opt/zeek_runner/file_extract_script/extract_file.zeek"
	maxCommandOutputBytes    = 8192
	outputTruncatedMarker    = "\n...[truncated]\n"
)

type LimitWriter struct {
	w         io.Writer
	n         int64
	truncated bool
}

func (l *LimitWriter) Write(p []byte) (n int, err error) {
	if l.n <= 0 {
		if !l.truncated {
			l.truncated = true
			_, _ = io.WriteString(l.w, outputTruncatedMarker)
		}
		return len(p), nil
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err = l.w.Write(p)
	l.n -= int64(n)
	if l.n <= 0 && !l.truncated {
		l.truncated = true
		_, _ = io.WriteString(l.w, outputTruncatedMarker)
	}
	return
}

type zeekRunOptions struct {
	taskID     string
	uuid       string
	taskType   string
	pcapID     string
	pcapPath   string
	scriptID   string
	scriptPath string
	outputDir  string
	env        map[string]string
	afterRun   func(context.Context)
}

type AnalyzeReq struct {
	TaskID               string `json:"taskID"`
	UUID                 string `json:"uuid"`
	OnlyNotice           bool   `json:"onlyNotice"`
	PcapID               string `json:"pcapID"`
	PcapPath             string `json:"pcapPath"`
	ScriptID             string `json:"scriptID"`
	ScriptPath           string `json:"scriptPath"`
	ExtractedFileMinSize int    `json:"extractedFileMinSize"`
}

type AnalyzeResp struct {
	TaskID     string `json:"taskID"`
	UUID       string `json:"uuid"`
	PcapPath   string `json:"pcapPath"`
	ScriptPath string `json:"scriptPath"`
	StartTime  string `json:"startTime"`
}

type ExtractReq struct {
	TaskID               string `json:"taskID"`
	UUID                 string `json:"uuid"`
	PcapID               string `json:"pcapID"`
	PcapPath             string `json:"pcapPath"`
	ScriptPath           string `json:"scriptPath"`
	OutputDir            string `json:"outputDir"`
	ExtractedFileMinSize int    `json:"extractedFileMinSize"`
	ExtractedFileMaxSize int    `json:"extractedFileMaxSize"`
}

type ExtractResp struct {
	TaskID     string `json:"taskID"`
	UUID       string `json:"uuid"`
	PcapPath   string `json:"pcapPath"`
	ScriptPath string `json:"scriptPath"`
	OutputDir  string `json:"outputDir"`
	StartTime  string `json:"startTime"`
}

type taskExecutionResult struct {
	result    zeekRunResult
	err       error
	startTime time.Time
}

type zeekRunResult struct {
	output []byte
	stats  zeekLogStats
}

type Service struct {
	pool              *ants.Pool
	configManager     *ConfigManager
	taskManager       *TaskManager
	fileDedupMgr      *FileDedupManager
	analysisPublisher *analysisEventPublisher
	extractPublisher  *extractEventPublisher
}

func NewService(pool *ants.Pool, cm *ConfigManager, tm *TaskManager, fdm *FileDedupManager) *Service {
	return &Service{
		pool:              pool,
		configManager:     cm,
		taskManager:       tm,
		fileDedupMgr:      fdm,
		analysisPublisher: newAnalysisEventPublisher(cm.Get().Kafka.Brokers),
		extractPublisher:  newExtractEventPublisher(cm.Get().Kafka.Brokers),
	}
}

func (s *Service) getConfig() *Config {
	return s.configManager.Get()
}

func (s *Service) ExecuteTaskInPool(ctx context.Context, req AnalyzeReq) (*AnalyzeResp, error) {
	res, err := s.executeOfflineTaskInPool(ctx, newOfflineScanTask(req))
	if err != nil {
		return nil, err
	}

	return &AnalyzeResp{
		TaskID:     req.TaskID,
		UUID:       req.UUID,
		PcapPath:   req.PcapPath,
		ScriptPath: req.ScriptPath,
		StartTime:  res.startTime.Format(time.RFC3339),
	}, nil
}

func (s *Service) ExecuteExtractTask(ctx context.Context, req ExtractReq) (*ExtractResp, error) {
	res, err := s.executeOfflineTaskInPool(ctx, newOfflineExtractTask(req))
	if err != nil {
		return nil, err
	}

	return &ExtractResp{
		TaskID:     req.TaskID,
		UUID:       req.UUID,
		PcapPath:   req.PcapPath,
		ScriptPath: resolveExtractScriptPath(req.ScriptPath),
		OutputDir:  req.OutputDir,
		StartTime:  res.startTime.Format(time.RFC3339),
	}, nil
}

func (s *Service) SubmitExtractAsyncTask(ctx context.Context, req ExtractReq) (*Task, error) {
	if s.taskManager == nil {
		return nil, errors.New("task manager not initialized, Redis required")
	}

	task, err := s.taskManager.CreateExtractTask(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	if err := s.taskManager.EnqueueTask(ctx, task.UUID); err != nil {
		s.taskManager.SetFailed(ctx, task.UUID, "failed to enqueue")
		return nil, fmt.Errorf("failed to enqueue task: %w", err)
	}

	LogTaskEvent("submitted", task.TaskID, task.UUID,
		"status", "queued",
	)

	RecordTask("queued", 0)
	return task, nil
}

func (s *Service) runExtractAnalysis(parentCtx context.Context, req ExtractReq) (zeekRunResult, error) {
	return s.runOfflineTask(parentCtx, newOfflineExtractTask(req))
}

func validateExtractReq(req ExtractReq) error {
	if req.TaskID == "" || req.UUID == "" {
		return errors.New("missing taskID or uuid")
	}
	if req.PcapID == "" {
		return errors.New("missing pcapID")
	}
	if req.PcapPath == "" {
		return errors.New("missing pcapPath")
	}
	if req.OutputDir == "" {
		return errors.New("missing outputDir")
	}

	if err := validatePath(req.PcapPath, "pcap"); err != nil {
		return err
	}
	if !isFileExist(req.PcapPath) {
		return fmt.Errorf("file not found: %s", req.PcapPath)
	}

	if err := validatePath(req.OutputDir, "output dir"); err != nil {
		return err
	}
	if !filepath.IsAbs(req.OutputDir) {
		return errors.New("outputDir must be absolute")
	}

	// 验证脚本路径（如果提供）
	if req.ScriptPath != "" {
		if err := validatePath(req.ScriptPath, "script"); err != nil {
			return err
		}
		if !isFileExist(req.ScriptPath) {
			return fmt.Errorf("script file not found: %s", req.ScriptPath)
		}
	}

	return nil
}

func (s *Service) SubmitAsyncTask(ctx context.Context, req AnalyzeReq) (*Task, error) {
	if s.taskManager == nil {
		return nil, errors.New("task manager not initialized, Redis required")
	}

	task, err := s.taskManager.CreateTask(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	if err := s.taskManager.EnqueueTask(ctx, task.UUID); err != nil {
		s.taskManager.SetFailed(ctx, task.UUID, "failed to enqueue")
		return nil, fmt.Errorf("failed to enqueue task: %w", err)
	}

	LogTaskEvent("submitted", task.TaskID, task.UUID,
		"status", "queued",
	)

	RecordTask("queued", 0)
	return task, nil
}

func (s *Service) executeAsyncTask(ctx context.Context, uuid string, spec offlineTaskSpec, timeout int) {
	taskCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
	defer cancel()

	result, err := s.runOfflineTask(taskCtx, spec)

	if err != nil {
		if errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
			s.taskManager.SetTimeout(ctx, uuid)
			s.publishParentEventIfReady(ctx, spec.taskID)
			RecordTask("timeout", 0)
		} else if errors.Is(taskCtx.Err(), context.Canceled) {
			s.taskManager.SetFailed(ctx, uuid, "canceled")
			s.publishParentEventIfReady(ctx, spec.taskID)
			RecordTask("canceled", 0)
		} else {
			s.taskManager.SetFailed(ctx, uuid, err.Error())
			s.publishParentEventIfReady(ctx, spec.taskID)
			RecordTask("failed", 0)
		}
		return
	}

	s.taskManager.SetSuccessWithStats(
		ctx,
		uuid,
		string(result.output),
		result.stats.NoticeCount+result.stats.IntelCount,
		result.stats.NoticeCount,
		result.stats.IntelCount,
	)
	s.publishParentEventIfReady(ctx, spec.taskID)
	RecordTask("success", 0)
}

func (s *Service) GetTaskStatus(ctx context.Context, uuid string) (*Task, error) {
	if s.taskManager == nil {
		return nil, errors.New("task manager not initialized")
	}
	return s.taskManager.GetTask(ctx, uuid)
}

type ParentTaskStatus struct {
	TaskID       string
	PcapID       string
	PcapPath     string
	TotalCount   int
	PendingCount int
	RunningCount int
	SuccessCount int
	FailedCount  int
	TimeoutCount int
	HitCount     int
	NoticeCount  int
	IntelCount   int
	Status       string
	SubTasks     []*Task
}

func (s *Service) GetParentTaskStatus(ctx context.Context, taskID string) (*ParentTaskStatus, error) {
	if s.taskManager == nil {
		return nil, errors.New("task manager not initialized")
	}

	redisStatus, err := s.taskManager.GetParentTaskStatusFromRedis(ctx, taskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent task status: %w", err)
	}

	status := &ParentTaskStatus{
		TaskID:       redisStatus.TaskID,
		TotalCount:   int(redisStatus.TotalCount),
		PendingCount: int(redisStatus.PendingCount),
		RunningCount: int(redisStatus.RunningCount),
		SuccessCount: int(redisStatus.SuccessCount),
		FailedCount:  int(redisStatus.FailedCount),
		TimeoutCount: int(redisStatus.TimeoutCount),
		Status:       redisStatus.Status,
	}

	tasks, err := s.taskManager.GetTasksByParentID(ctx, taskID)
	if err == nil {
		status.SubTasks = tasks
		for _, task := range tasks {
			if status.PcapID == "" {
				status.PcapID = task.PcapID
			}
			if status.PcapPath == "" {
				status.PcapPath = task.PcapPath
			}
			status.HitCount += task.HitCount
			status.NoticeCount += task.NoticeCount
			status.IntelCount += task.IntelCount
		}
	}

	return status, nil
}

func (s *Service) StartTaskConsumer(ctx context.Context) {
	if s.taskManager == nil {
		LogServiceEvent("consumer_skip", "reason", "no_task_manager")
		return
	}

	LogServiceEvent("consumer_started",
		"pool_size", s.getConfig().Pool.Size,
	)

	go func() {
		for {
			select {
			case <-ctx.Done():
				LogServiceEvent("consumer_stopped")
				return
			default:
				uuid, err := s.taskManager.DequeueTask(ctx, 5*time.Second)
				if err != nil {
					LogServiceError("dequeue_failed", err)
					time.Sleep(time.Second)
					continue
				}

				if uuid == "" {
					continue
				}

				s.processQueuedTask(ctx, uuid)
			}
		}
	}()
}

func (s *Service) processQueuedTask(ctx context.Context, uuid string) {
	task, err := s.taskManager.GetTask(ctx, uuid)
	if err != nil {
		LogTaskError("fetch_failed", "", uuid, err)
		return
	}

	if task.Status != TaskStatusPending {
		LogTaskEvent("skip_processed", task.TaskID, task.UUID,
			"status", task.Status,
		)
		return
	}

	spec := newOfflineTaskFromStored(task)

	cfg := s.getConfig()
	err = s.pool.Submit(func() {
		s.executeAsyncTask(context.Background(), uuid, spec, cfg.Pool.TimeoutMinutes)
	})

	if err != nil {
		if errors.Is(err, ants.ErrPoolOverload) {
			s.taskManager.SetFailed(ctx, uuid, "task pool full")
			if canRetry, _ := s.taskManager.CanRetry(ctx, uuid); canRetry {
				s.taskManager.IncrementRetry(ctx, uuid)
				s.taskManager.EnqueueTask(ctx, uuid)
				LogTaskEvent("requeue", task.TaskID, task.UUID,
					"reason", "pool_full",
					"retries", task.Retries+1,
				)
			}
			RecordTask("rejected", 0)
		} else {
			s.taskManager.SetFailed(ctx, uuid, err.Error())
			RecordTask("error", 0)
		}
		return
	}

	s.taskManager.SetRunning(ctx, uuid)
	LogTaskEvent("started", task.TaskID, task.UUID,
		"pcap", filepath.Base(task.PcapPath),
		"script", filepath.Base(task.ScriptPath),
	)
	RecordTask("started", 0)
}

func (s *Service) runZeekAnalysis(parentCtx context.Context, req AnalyzeReq) (zeekRunResult, error) {
	return s.runOfflineTask(parentCtx, newOfflineScanTask(req))
}

func (s *Service) executeOfflineTaskInPool(ctx context.Context, spec offlineTaskSpec) (*taskExecutionResult, error) {
	resultChan := make(chan taskExecutionResult, 1)
	enqueueTime := time.Now()

	cfg := s.getConfig()
	err := s.pool.Submit(func() {
		if ctx.Err() != nil {
			return
		}

		actualStartTime := time.Now()
		queueDuration := actualStartTime.Sub(enqueueTime)
		if queueDuration > 500*time.Millisecond {
			LogTaskEvent("queue_wait", spec.taskID, spec.uuid,
				"wait_ms", queueDuration.Milliseconds(),
				"pool_running", s.pool.Running(),
			)
		}

		out, e := s.runOfflineTask(ctx, spec)
		select {
		case resultChan <- taskExecutionResult{
			result:    out,
			err:       e,
			startTime: actualStartTime,
		}:
		case <-ctx.Done():
		}
	})

	if err != nil {
		if errors.Is(err, ants.ErrPoolOverload) {
			RecordTask("rejected", 0)
			return nil, status.Errorf(codes.ResourceExhausted, "task pool full (cap: %d)", cfg.Pool.Size)
		}
		RecordTask("error", 0)
		return nil, status.Errorf(codes.Internal, "submit failed: %v", err)
	}

	select {
	case res := <-resultChan:
		duration := time.Since(enqueueTime).Seconds()
		if res.err != nil {
			RecordTask("failed", duration)
			return nil, fmt.Errorf("%w | output: %s", res.err, string(res.result.output))
		}
		RecordTask("success", duration)
		return &res, nil
	case <-ctx.Done():
		RecordTask("canceled", time.Since(enqueueTime).Seconds())
		return nil, ctx.Err()
	}
}

func (s *Service) runOfflineTask(parentCtx context.Context, spec offlineTaskSpec) (zeekRunResult, error) {
	return s.runZeekCommand(parentCtx, spec.zeekRunOptions(s))
}
func (s *Service) runZeekCommand(parentCtx context.Context, opts zeekRunOptions) (zeekRunResult, error) {
	cfg := s.getConfig()
	pcapName := filepath.Base(opts.pcapPath)
	scriptName := filepath.Base(opts.scriptPath)

	LogTaskEvent("zeek_start", opts.taskID, opts.uuid,
		"type", opts.taskType,
		"pcap", pcapName,
		"script", scriptName,
		"timeout_min", cfg.Pool.TimeoutMinutes,
	)

	workDir, err := os.MkdirTemp("", fmt.Sprintf("zeek_run_%s_*", opts.uuid))
	if err != nil {
		LogTaskError("temp_dir_failed", opts.taskID, opts.uuid, err)
		return zeekRunResult{}, status.Errorf(codes.Internal, "create temp dir failed: %v", err)
	}
	defer os.RemoveAll(workDir)

	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(cfg.Pool.TimeoutMinutes)*time.Minute)
	defer cancel()

	if opts.taskType == string(offlineTaskExtract) && opts.outputDir != "" {
		if err := os.MkdirAll(opts.outputDir, 0o755); err != nil {
			LogTaskError("create_output_dir_failed", opts.taskID, opts.uuid, err, "output_dir", opts.outputDir)
			return zeekRunResult{}, status.Errorf(codes.Internal, "create output dir failed: %v", err)
		}
	}

	cmd := exec.CommandContext(ctx, "zeek", "-Cr", opts.pcapPath, opts.scriptPath, customConfigPath)
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.Env = appendCommandEnv(os.Environ(), opts.env)

	var errBuf bytes.Buffer
	limitedOutput := &LimitWriter{w: &errBuf, n: maxCommandOutputBytes}
	cmd.Stdout = limitedOutput
	cmd.Stderr = limitedOutput

	startTime := time.Now()
	err = cmd.Run()
	output := errBuf.Bytes()
	duration := time.Since(startTime)
	stats := collectZeekLogStats(workDir)

	if err != nil {
		errMsg := "zeek_failed"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			errMsg = "timeout"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			errMsg = "canceled"
		}

		LogTaskError(errMsg, opts.taskID, opts.uuid, err,
			"duration_ms", duration.Milliseconds(),
			"stderr", string(output),
		)
		if opts.taskType == string(offlineTaskExtract) {
			_ = s.publishExtractTaskEvent(parentCtx, opts, "task_failed", "failed", extractTaskSummary{}, err)
		}
		s.publishSubtaskEvent(parentCtx, opts, stats, duration, err)
		return zeekRunResult{output: output, stats: stats}, err
	}

	LogTaskEvent("zeek_done", opts.taskID, opts.uuid,
		"duration_ms", duration.Milliseconds(),
		"stderr", string(output),
		"type", opts.taskType,
	)

	if opts.taskType == string(offlineTaskExtract) {
		summary, postErr := s.processExtractedFiles(ctx, opts)
		if postErr != nil {
			LogTaskError("extract_event_failed", opts.taskID, opts.uuid, postErr,
				"output_dir", opts.outputDir,
			)
			_ = s.publishExtractTaskEvent(parentCtx, opts, "task_failed", "failed", summary, postErr)
			return zeekRunResult{output: output, stats: stats}, postErr
		}
		if err := s.publishExtractTaskEvent(parentCtx, opts, "task_completed", "success", summary, nil); err != nil {
			LogTaskError("extract_task_event_failed", opts.taskID, opts.uuid, err,
				"output_dir", opts.outputDir,
			)
			return zeekRunResult{output: output, stats: stats}, err
		}
	} else if opts.afterRun != nil {
		opts.afterRun(ctx)
	}

	if opts.taskType == string(offlineTaskScan) {
		if err := s.publishSubtaskHitEvents(parentCtx, opts, workDir); err != nil {
			LogTaskError("subtask_hit_publish_failed", opts.taskID, opts.uuid, err)
			return zeekRunResult{output: output, stats: stats}, err
		}
	}

	s.publishSubtaskEvent(parentCtx, opts, stats, duration, nil)
	logIntelArtifact(workDir, opts.taskID, opts.uuid)
	return zeekRunResult{output: output, stats: stats}, nil
}

func appendCommandEnv(base []string, envMap map[string]string) []string {
	env := append([]string{}, base...)
	for k, v := range envMap {
		if v != "" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return env
}

func resolveExtractScriptPath(scriptPath string) string {
	if scriptPath == "" {
		scriptPath = defaultExtractScriptPath
	}

	return strings.ReplaceAll(scriptPath, "\\", "/")
}

func logIntelArtifact(workDir string, taskID string, uuid string) {
	intelLogPath := filepath.Join(workDir, "intel.log")
	if _, err := os.Stat(intelLogPath); err != nil {
		return
	}

	intelLogContent, err := os.ReadFile(intelLogPath)
	if err != nil || len(intelLogContent) == 0 {
		return
	}

	LogTaskEvent("intel_log_generated", taskID, uuid, "content", string(intelLogContent))
}

func validateReq(req AnalyzeReq) error {
	if req.TaskID == "" || req.UUID == "" {
		return errors.New("missing taskID or uuid")
	}
	if req.PcapID == "" {
		return errors.New("missing pcapID")
	}
	if req.ScriptID == "" {
		return errors.New("missing scriptID (required for malicious scan)")
	}
	if req.PcapPath == "" || req.ScriptPath == "" {
		return errors.New("missing paths")
	}

	if err := validatePath(req.PcapPath, "pcap"); err != nil {
		return err
	}
	if !isFileExist(req.PcapPath) {
		return fmt.Errorf("file not found: %s", req.PcapPath)
	}

	if err := validatePath(req.ScriptPath, "script"); err != nil {
		return err
	}
	if !isFileExist(req.ScriptPath) {
		return fmt.Errorf("script not found: %s", req.ScriptPath)
	}

	return nil
}

func validatePath(path, name string) error {
	normalizedPath := filepath.ToSlash(path)
	for _, segment := range strings.Split(normalizedPath, "/") {
		if segment == ".." {
			return fmt.Errorf("invalid %s path: path traversal detected", name)
		}
	}

	cleanPath := filepath.Clean(path)
	isAbs := filepath.IsAbs(cleanPath) || strings.HasPrefix(normalizedPath, "/")
	if !isAbs {
		return fmt.Errorf("%s path must be absolute", name)
	}
	return nil
}

func isFileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
