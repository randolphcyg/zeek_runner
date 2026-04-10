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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/panjf2000/ants/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

type Service struct {
	pool          *ants.Pool
	configManager *ConfigManager
	taskManager   *TaskManager
	fileDedupMgr  *FileDedupManager
}

func NewService(pool *ants.Pool, cm *ConfigManager, tm *TaskManager, fdm *FileDedupManager) *Service {
	return &Service{pool: pool, configManager: cm, taskManager: tm, fileDedupMgr: fdm}
}

func (s *Service) getConfig() *Config {
	return s.configManager.Get()
}

func (s *Service) ExecuteTaskInPool(ctx context.Context, req AnalyzeReq) (*AnalyzeResp, error) {
	type result struct {
		output    []byte
		err       error
		startTime time.Time
	}
	resultChan := make(chan result, 1)
	enqueueTime := time.Now()

	cfg := s.getConfig()
	err := s.pool.Submit(func() {
		if ctx.Err() != nil {
			return
		}

		actualStartTime := time.Now()
		queueDuration := actualStartTime.Sub(enqueueTime)
		if queueDuration > 500*time.Millisecond {
			LogTaskEvent("queue_wait", req.TaskID, req.UUID,
				"wait_ms", queueDuration.Milliseconds(),
				"pool_running", s.pool.Running(),
			)
		}

		out, e := s.runZeekAnalysis(ctx, req)
		select {
		case resultChan <- result{
			output:    out,
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
			return nil, fmt.Errorf("%w | output: %s", res.err, string(res.output))
		}
		RecordTask("success", duration)
		return &AnalyzeResp{
			TaskID: req.TaskID, UUID: req.UUID,
			PcapPath: req.PcapPath, ScriptPath: req.ScriptPath,
			StartTime: res.startTime.Format(time.RFC3339),
		}, nil
	case <-ctx.Done():
		RecordTask("canceled", time.Since(enqueueTime).Seconds())
		return nil, ctx.Err()
	}
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

func (s *Service) executeAsyncTask(ctx context.Context, uuid string, req AnalyzeReq, timeout int) {
	taskCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
	defer cancel()

	output, err := s.runZeekAnalysis(taskCtx, req)

	if err != nil {
		if errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
			s.taskManager.SetTimeout(ctx, uuid)
			RecordTask("timeout", 0)
		} else if errors.Is(taskCtx.Err(), context.Canceled) {
			s.taskManager.SetFailed(ctx, uuid, "canceled")
			RecordTask("canceled", 0)
		} else {
			s.taskManager.SetFailed(ctx, uuid, err.Error())
			RecordTask("failed", 0)
		}
		return
	}

	s.taskManager.SetSuccess(ctx, uuid, string(output))
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
	TotalCount   int
	PendingCount int
	RunningCount int
	SuccessCount int
	FailedCount  int
	TimeoutCount int
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

	req := AnalyzeReq{
		TaskID:               task.TaskID,
		UUID:                 task.UUID,
		PcapID:               task.PcapID,
		PcapPath:             task.PcapPath,
		ScriptID:             task.ScriptID,
		ScriptPath:           task.ScriptPath,
		OnlyNotice:           task.OnlyNotice,
		ExtractedFilePath:    task.ExtractedFilePath,
		ExtractedFileMinSize: task.ExtractedFileMinSize,
	}

	cfg := s.getConfig()
	err = s.pool.Submit(func() {
		s.executeAsyncTask(context.Background(), uuid, req, cfg.Pool.TimeoutMinutes)
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

func (s *Service) runZeekAnalysis(parentCtx context.Context, req AnalyzeReq) ([]byte, error) {
	cfg := s.getConfig()
	taskType := deriveTaskType(req)
	pcapName := filepath.Base(req.PcapPath)
	scriptName := filepath.Base(req.ScriptPath)

	LogTaskEvent("zeek_start", req.TaskID, req.UUID,
		"type", taskType,
		"pcap", pcapName,
		"script", scriptName,
		"timeout_min", cfg.Pool.TimeoutMinutes,
	)

	workDir, err := os.MkdirTemp("", fmt.Sprintf("zeek_run_%s_*", req.UUID))
	if err != nil {
		LogTaskError("temp_dir_failed", req.TaskID, req.UUID, err)
		return nil, status.Errorf(codes.Internal, "create temp dir failed: %v", err)
	}
	defer os.RemoveAll(workDir)

	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(cfg.Pool.TimeoutMinutes)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zeek", "-Cr", req.PcapPath, req.ScriptPath, "/usr/local/zeek/share/zeek/base/custom/config.zeek")
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}

	env := os.Environ()
	envMap := map[string]string{
		"TASK_ID": req.TaskID, "UUID": req.UUID,
		"ONLY_NOTICE":             strconv.FormatBool(req.OnlyNotice),
		"PCAP_ID":                 req.PcapID,
		"PCAP_PATH":               req.PcapPath,
		"SCRIPT_ID":               req.ScriptID,
		"SCRIPT_PATH":             req.ScriptPath,
		"EXTRACTED_FILE_PATH":     req.ExtractedFilePath,
		"EXTRACTED_FILE_MIN_SIZE": strconv.Itoa(req.ExtractedFileMinSize),
		"KAFKA_BROKERS":           cfg.Kafka.Brokers,
	}
	for k, v := range envMap {
		if v != "" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env

	var errBuf bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &LimitWriter{w: &errBuf, n: 8192}

	startTime := time.Now()
	err = cmd.Run()
	output := errBuf.Bytes()
	duration := time.Since(startTime)

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

		LogTaskError(errMsg, req.TaskID, req.UUID, err,
			"duration_ms", duration.Milliseconds(),
			"stderr", string(output),
		)
		return output, err
	}

	LogTaskEvent("zeek_done", req.TaskID, req.UUID,
		"duration_ms", duration.Milliseconds(),
		"stderr", string(output),
		"type", taskType,
	)

	if taskType == "FILE_EXTRACT" && s.fileDedupMgr != nil && req.ExtractedFilePath != "" {
		s.processExtractedFiles(ctx, req)
	}

	return output, nil
}

func deriveTaskType(req AnalyzeReq) string {
	if req.ExtractedFilePath != "" || strings.Contains(req.ScriptPath, "extract") {
		return "FILE_EXTRACT"
	}
	return "MALICIOUS_SCAN"
}

func (s *Service) processExtractedFiles(ctx context.Context, req AnalyzeReq) {
	extractDir := req.ExtractedFilePath
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		LogTaskError("read_dir_failed", req.TaskID, req.UUID, err, "dir", extractDir)
		return
	}

	pcapBase := filepath.Base(req.PcapPath)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()

		if filename == pcapBase {
			continue
		}
		ext := strings.ToLower(filepath.Ext(filename))
		if ext == ".pcap" || ext == ".cap" || ext == ".pcapng" {
			continue
		}

		filePath := filepath.Join(extractDir, entry.Name())
		record, isDuplicate, err := s.fileDedupMgr.ProcessExtractedFile(ctx, filePath, req.PcapPath, req.TaskID)
		if err != nil {
			LogTaskError("process_file_failed", req.TaskID, req.UUID, err, "file", entry.Name())
			continue
		}

		if isDuplicate {
			LogTaskEvent("file_dedup", req.TaskID, req.UUID,
				"file", entry.Name(),
				"hash", record.Hash[:16],
				"action", "skipped",
				"ref_count", record.RefCount,
			)
		} else {
			LogTaskEvent("file_saved", req.TaskID, req.UUID,
				"file", entry.Name(),
				"hash", record.Hash[:16],
				"size", record.FileSize,
			)
		}
	}
}

func validateReq(req AnalyzeReq) error {
	if req.TaskID == "" || req.UUID == "" {
		return errors.New("missing taskID or uuid")
	}
	if req.PcapID == "" {
		return errors.New("missing pcapID")
	}
	if req.ExtractedFilePath == "" && req.ScriptID == "" {
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

	if req.ExtractedFilePath != "" {
		if err := validatePath(req.ExtractedFilePath, "extracted file"); err != nil {
			return err
		}
		if !filepath.IsAbs(req.ExtractedFilePath) {
			return errors.New("extracted file path must be absolute")
		}
	}

	return nil
}

func validatePath(path, name string) error {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid %s path: path traversal detected", name)
	}
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("%s path must be absolute", name)
	}
	return nil
}

func isFileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
