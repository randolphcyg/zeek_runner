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
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type batchRunGroup struct {
	tasks []*Task
}

func (s *Service) executeAsyncBatchJob(ctx context.Context, job *BatchQueueJob, timeout int) {
	tasks := make([]*Task, 0, len(job.UUIDs))
	for _, uuid := range job.UUIDs {
		task, err := s.taskManager.GetTask(ctx, uuid)
		if err != nil {
			LogTaskError("batch_fetch_failed", job.TaskID, uuid, err)
			continue
		}
		if task.Status != TaskStatusRunning && task.Status != TaskStatusPending {
			continue
		}
		tasks = append(tasks, task)
	}
	if len(tasks) == 0 {
		return
	}

	for _, group := range s.planBatchRunGroups(tasks) {
		if len(group.tasks) == 1 {
			task := group.tasks[0]
			s.executeAsyncTask(ctx, task.UUID, newOfflineTaskFromStored(task), timeout)
			continue
		}
		s.executeZeekBatchGroup(ctx, group)
	}
	s.publishParentEventIfReady(ctx, job.TaskID)
}

func (s *Service) planBatchRunGroups(tasks []*Task) []batchRunGroup {
	cfg := s.getConfig()
	if !cfg.Batch.Enabled {
		groups := make([]batchRunGroup, 0, len(tasks))
		for _, task := range tasks {
			groups = append(groups, batchRunGroup{tasks: []*Task{task}})
		}
		return groups
	}

	maxScripts := cfg.Batch.MaxScriptsPerZeekRun
	if maxScripts <= 0 {
		maxScripts = 16
	}

	noticeOwners := map[string]string{}
	taskNotices := map[string][]string{}
	batchable := make([]*Task, 0, len(tasks))
	var singles []batchRunGroup

	for _, task := range tasks {
		spec := newOfflineTaskFromStored(task)
		if spec.kind != offlineTaskScan || spec.isIntelDetection() {
			singles = append(singles, batchRunGroup{tasks: []*Task{task}})
			continue
		}
		script, err := s.ResolveManagedScript(task.ScriptID, task.ScriptPath)
		if err != nil || len(script.NoticeTypes) == 0 {
			singles = append(singles, batchRunGroup{tasks: []*Task{task}})
			continue
		}
		duplicate := false
		for _, notice := range script.NoticeTypes {
			if owner := noticeOwners[notice]; owner != "" && owner != task.ScriptID {
				duplicate = true
				break
			}
		}
		if duplicate {
			singles = append(singles, batchRunGroup{tasks: []*Task{task}})
			continue
		}
		for _, notice := range script.NoticeTypes {
			noticeOwners[notice] = task.ScriptID
		}
		taskNotices[task.UUID] = script.NoticeTypes
		batchable = append(batchable, task)
	}

	groups := make([]batchRunGroup, 0, len(singles)+len(batchable)/maxScripts+1)
	groups = append(groups, singles...)
	for i := 0; i < len(batchable); i += maxScripts {
		end := i + maxScripts
		if end > len(batchable) {
			end = len(batchable)
		}
		group := batchRunGroup{tasks: batchable[i:end]}
		if len(group.tasks) == 1 || !uniqueNoticeSet(group.tasks, taskNotices) {
			for _, task := range group.tasks {
				groups = append(groups, batchRunGroup{tasks: []*Task{task}})
			}
		} else {
			groups = append(groups, group)
		}
	}
	return groups
}

func uniqueNoticeSet(tasks []*Task, taskNotices map[string][]string) bool {
	seen := map[string]bool{}
	for _, task := range tasks {
		for _, notice := range taskNotices[task.UUID] {
			if seen[notice] {
				return false
			}
			seen[notice] = true
		}
	}
	return true
}

func (s *Service) executeZeekBatchGroup(parentCtx context.Context, group batchRunGroup) {
	first := group.tasks[0]
	optsByUUID := make(map[string]zeekRunOptions, len(group.tasks))
	noticeToUUID := map[string]string{}
	scriptPaths := make([]string, 0, len(group.tasks))

	for _, task := range group.tasks {
		spec := newOfflineTaskFromStored(task)
		optsByUUID[task.UUID] = spec.zeekRunOptions(s)
		scriptPaths = append(scriptPaths, spec.scriptPath)
		script, err := s.ResolveManagedScript(task.ScriptID, task.ScriptPath)
		if err != nil {
			_ = s.taskManager.SetFailed(parentCtx, task.UUID, err.Error())
			continue
		}
		for _, notice := range script.NoticeTypes {
			noticeToUUID[notice] = task.UUID
		}
	}

	workDir, output, duration, err := s.runZeekBatchCommand(parentCtx, first, scriptPaths)
	if workDir != "" {
		defer os.RemoveAll(workDir)
	}
	statsByUUID := map[string]zeekLogStats{}
	if err == nil {
		statsByUUID = statsByNoticeOwner(workDir, noticeToUUID)
	}

	for _, task := range group.tasks {
		opts := optsByUUID[task.UUID]
		stats := statsByUUID[task.UUID]
		if err != nil {
			_ = s.taskManager.SetFailed(parentCtx, task.UUID, err.Error())
			s.publishSubtaskEvent(parentCtx, opts, stats, duration, err)
			continue
		}
		_ = s.taskManager.SetSuccessWithStats(
			parentCtx,
			task.UUID,
			string(output),
			stats.NoticeCount+stats.IntelCount,
			stats.NoticeCount,
			stats.IntelCount,
		)
		if opts.onlyNotice {
			_ = s.publishFilteredSubtaskHitEvents(parentCtx, opts, workDir, noticeToUUID)
		}
		s.publishSubtaskEvent(parentCtx, opts, stats, duration, nil)
	}
}

func (s *Service) runZeekBatchCommand(parentCtx context.Context, first *Task, scriptPaths []string) (string, []byte, time.Duration, error) {
	cfg := s.getConfig()
	workDir, err := os.MkdirTemp("", fmt.Sprintf("zeek_batch_%s_*", first.TaskID))
	if err != nil {
		return "", nil, 0, status.Errorf(codes.Internal, "create temp dir failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(cfg.Pool.TimeoutMinutes)*time.Minute)
	defer cancel()

	envSpec := newOfflineTaskFromStored(first)
	env := envSpec.zeekEnv()
	env["UUID"] = first.TaskID
	env["SCRIPT_ID"] = "BATCH"
	env["SCRIPT_PATH"] = strings.Join(scriptPaths, ",")

	args := []string{"-Cr", first.PcapPath}
	args = append(args, scriptPaths...)
	args = append(args, customConfigPath)
	cmd := exec.CommandContext(ctx, "zeek", args...)
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.Env = appendCommandEnv(os.Environ(), env)

	var errBuf bytes.Buffer
	limitedOutput := &LimitWriter{w: &errBuf, n: maxCommandOutputBytes}
	cmd.Stdout = limitedOutput
	cmd.Stderr = limitedOutput

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)
	output := errBuf.Bytes()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		slog.Warn("zeek batch failed", "taskID", first.TaskID, "pcap", filepath.Base(first.PcapPath), "err", err, "stderr", string(output))
		return workDir, output, duration, err
	}
	return workDir, output, duration, nil
}

func statsByNoticeOwner(workDir string, noticeToUUID map[string]string) map[string]zeekLogStats {
	stats := map[string]zeekLogStats{}
	records, _ := parseZeekTSVLog(filepath.Join(workDir, "notice.log"))
	for _, record := range records {
		note := recordValue(record, "note")
		if uuid := matchNoticeOwner(note, noticeToUUID); uuid != "" {
			current := stats[uuid]
			current.NoticeCount++
			stats[uuid] = current
		}
	}
	return stats
}

func matchNoticeOwner(note string, noticeToUUID map[string]string) string {
	for notice, uuid := range noticeToUUID {
		if noticeTypeMatches(note, notice) {
			return uuid
		}
	}
	return ""
}

func noticeTypeMatches(actual, declared string) bool {
	actual = strings.TrimSpace(actual)
	declared = strings.TrimSpace(declared)
	if actual == "" || declared == "" {
		return false
	}
	return actual == declared ||
		strings.HasSuffix(actual, "::"+declared) ||
		strings.HasSuffix(declared, "::"+actual)
}

func (s *Service) publishFilteredSubtaskHitEvents(ctx context.Context, opts zeekRunOptions, workDir string, noticeToUUID map[string]string) error {
	if s == nil || s.analysisPublisher == nil || opts.taskType != string(offlineTaskScan) {
		return nil
	}
	noticeHits, err := parseNoticeLog(filepath.Join(workDir, "notice.log"))
	if err != nil {
		return err
	}

	var redisHits []TaskHitEvent

	for _, hit := range noticeHits {
		if matchNoticeOwner(hit.RuleType, noticeToUUID) != opts.uuid {
			continue
		}
		hit.EventID = stableEventID("subtask_hit", opts.taskID, opts.uuid, hit.RuleType, hit.UID, hit.Message)
		hit.EventType = "subtask_hit"
		hit.EventVersion = eventVersion
		hit.EventTime = time.Now().Format(time.RFC3339)
		hit.Producer = producerName
		hit.AnalysisMode = "offline"
		hit.TaskID = opts.taskID
		hit.UUID = opts.uuid
		hit.PcapID = opts.pcapID
		hit.PcapPath = opts.pcapPath
		hit.ScriptID = opts.scriptID
		hit.ScriptPath = opts.scriptPath
		hit.Verdict = "malicious"

		redisHits = append(redisHits, TaskHitEvent{
			EventID:    hit.EventID,
			EventType:  hit.EventType,
			EventTime:  hit.EventTime,
			TaskID:     hit.TaskID,
			UUID:       hit.UUID,
			PcapID:     hit.PcapID,
			PcapPath:   hit.PcapPath,
			ScriptID:   hit.ScriptID,
			ScriptPath: hit.ScriptPath,
			Verdict:    hit.Verdict,
			SourceType: hit.SourceType,
			RuleType:   hit.RuleType,
			RuleName:   hit.RuleName,
			Message:    hit.Message,
			Indicator:  hit.Indicator,
			SrcIp:      hit.SrcIp,
			SrcPort:    hit.SrcPort,
			DstIp:      hit.DstIp,
			DstPort:    hit.DstPort,
			Proto:      hit.Proto,
			UID:        hit.UID,
		})

		if err := s.publishAnalysisEvent(ctx, opts.taskID, "subtask_hit", hit); err != nil {
			return err
		}
	}

	// Store hits in Redis for later querying via MCP
	if s.taskManager != nil && len(redisHits) > 0 {
		if err := s.taskManager.SaveTaskHits(ctx, opts.uuid, opts.taskID, redisHits); err != nil {
			slog.Warn("failed to save batch task hits to Redis", "uuid", opts.uuid, "err", err)
		}
	}

	return nil
}

var _ io.Writer = (*LimitWriter)(nil)
