package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
			slog.Warn("Task queued too long",
				"uuid", req.UUID,
				"wait", queueDuration,
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
			return nil, status.Errorf(codes.ResourceExhausted, "task pool full (cap: %d)", cfg.PoolSize)
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

	cfg := s.getConfig()
	err = s.pool.Submit(func() {
		s.executeAsyncTask(context.Background(), task.TaskID, req, cfg.ZeekTimeout)
	})

	if err != nil {
		if errors.Is(err, ants.ErrPoolOverload) {
			s.taskManager.SetFailed(ctx, task.TaskID, "task pool full")
			RecordTask("rejected", 0)
			return nil, status.Errorf(codes.ResourceExhausted, "task pool full (cap: %d)", cfg.PoolSize)
		}
		s.taskManager.SetFailed(ctx, task.TaskID, err.Error())
		RecordTask("error", 0)
		return nil, status.Errorf(codes.Internal, "submit failed: %v", err)
	}

	s.taskManager.SetRunning(ctx, task.TaskID)
	RecordTask("submitted", 0)
	return task, nil
}

func (s *Service) executeAsyncTask(ctx context.Context, taskID string, req AnalyzeReq, timeout int) {
	taskCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Minute)
	defer cancel()

	output, err := s.runZeekAnalysis(taskCtx, req)

	if err != nil {
		if errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
			s.taskManager.SetTimeout(ctx, taskID)
			RecordTask("timeout", 0)
		} else if errors.Is(taskCtx.Err(), context.Canceled) {
			s.taskManager.SetFailed(ctx, taskID, "canceled")
			RecordTask("canceled", 0)
		} else {
			s.taskManager.SetFailed(ctx, taskID, err.Error())
			RecordTask("failed", 0)
		}
		return
	}

	s.taskManager.SetSuccess(ctx, taskID, string(output))
	RecordTask("success", 0)
}

func (s *Service) GetTaskStatus(ctx context.Context, taskID string) (*Task, error) {
	if s.taskManager == nil {
		return nil, errors.New("task manager not initialized")
	}
	return s.taskManager.GetTask(ctx, taskID)
}

func (s *Service) runZeekAnalysis(parentCtx context.Context, req AnalyzeReq) ([]byte, error) {
	cfg := s.getConfig()
	taskType := deriveTaskType(req)
	pcapName := filepath.Base(req.PcapPath)
	scriptName := filepath.Base(req.ScriptPath)

	logger := slog.With(
		slog.String("type", taskType),
		slog.String("taskID", req.TaskID),
		slog.String("uuid", req.UUID),
		slog.String("pcap", pcapName),
		slog.String("script", scriptName),
	)

	logger.Info("started",
		slog.String("pcap_path", req.PcapPath),
		slog.String("script_path", req.ScriptPath),
		slog.String("extracted_file_path", req.ExtractedFilePath),
		slog.Int("extracted_file_min_size", req.ExtractedFileMinSize),
	)

	workDir, err := os.MkdirTemp("", fmt.Sprintf("zeek_run_%s_*", req.UUID))
	if err != nil {
		logger.Error("create temp dir failed", "err", err)
		return nil, status.Errorf(codes.Internal, "create temp dir failed: %v", err)
	}
	logger.Debug("created temp work dir", "dir", workDir)
	defer os.RemoveAll(workDir)

	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(cfg.ZeekTimeout)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zeek", "-Cr", req.PcapPath, req.ScriptPath)
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	logger.Debug("executing zeek command", "cmd", cmd.String())

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
		errMsg := "Zeek execution failed"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			errMsg = fmt.Sprintf("Timeout after %dm", cfg.ZeekTimeout)
		} else if errors.Is(ctx.Err(), context.Canceled) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			errMsg = "Request canceled by client"
		}

		logger.Error(errMsg,
			slog.Any("err", err),
			slog.String("stderr", string(output)),
			slog.Duration("duration", duration),
		)
		return output, err
	}

	logger.Info("Done",
		slog.String("duration", duration.String()),
		slog.Int("stderr_size", len(output)),
		slog.String("work_dir", workDir),
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
		slog.Warn("failed to read extracted files directory", "dir", extractDir, "err", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(extractDir, entry.Name())
		record, isDuplicate, err := s.fileDedupMgr.ProcessExtractedFile(ctx, filePath, req.PcapPath, req.TaskID)
		if err != nil {
			slog.Warn("failed to process extracted file", "file", filePath, "err", err)
			continue
		}

		if isDuplicate {
			slog.Info("duplicate file removed",
				"file", entry.Name(),
				"hash", record.Hash[:16],
				"original", record.FilePath,
				"refCount", record.RefCount,
			)
		} else {
			slog.Info("new file registered",
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
