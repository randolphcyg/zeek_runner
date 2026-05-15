package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type TaskStatus string

const (
	TaskStatusPending  TaskStatus = "pending"
	TaskStatusRunning  TaskStatus = "running"
	TaskStatusSuccess  TaskStatus = "success"
	TaskStatusFailed   TaskStatus = "failed"
	TaskStatusTimeout  TaskStatus = "timeout"
	TaskStatusCanceled TaskStatus = "canceled"
)

type Task struct {
	TaskID               string     `json:"taskID"`
	UUID                 string     `json:"uuid"`
	PcapID               string     `json:"pcapID"`
	PcapPath             string     `json:"pcapPath"`
	ScriptID             string     `json:"scriptID"`
	ScriptPath           string     `json:"scriptPath"`
	RunMode              string     `json:"runMode"`
	Weight               int        `json:"weight"`
	OnlyNotice           bool       `json:"onlyNotice"`
	OutputDir            string     `json:"outputDir"`
	ExtractedFileMinSize int        `json:"extractedFileMinSize"`
	ExtractedFileMaxSize int        `json:"extractedFileMaxSize"`
	Status               TaskStatus `json:"status"`
	CreateTime           time.Time  `json:"createTime"`
	StartTime            time.Time  `json:"startTime"`
	EndTime              time.Time  `json:"endTime"`
	Duration             float64    `json:"duration"`
	HitCount             int        `json:"hitCount"`
	NoticeCount          int        `json:"noticeCount"`
	IntelCount           int        `json:"intelCount"`
	Error                string     `json:"error"`
	Output               string     `json:"output"`
	Retries              int        `json:"retries"`
	MaxRetries           int        `json:"maxRetries"`
}

type TaskManager struct {
	redis           *redis.Client
	prefix          string
	parentKeyPrefix string
	queueKey        string
	streamKey       string
	consumerGroup   string
	expiration      time.Duration
	instanceID      string
}

type RedisPoolConfig struct {
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolTimeout  time.Duration
	MaxLifetime  time.Duration
	MaxIdleTime  time.Duration
}

func NewTaskManager(redisAddr, redisPassword string, redisDB int, poolCfg *RedisPoolConfig) *TaskManager {
	poolSize := 10
	minIdleConns := 0
	maxRetries := 3
	dialTimeout := 5 * time.Second
	readTimeout := 3 * time.Second
	writeTimeout := 3 * time.Second
	poolTimeout := 4 * time.Second
	var maxLifetime, maxIdleTime time.Duration

	if poolCfg != nil {
		if poolCfg.PoolSize > 0 {
			poolSize = poolCfg.PoolSize
		}
		if poolCfg.MinIdleConns > 0 {
			minIdleConns = poolCfg.MinIdleConns
		}
		if poolCfg.MaxRetries > 0 {
			maxRetries = poolCfg.MaxRetries
		}
		if poolCfg.DialTimeout > 0 {
			dialTimeout = poolCfg.DialTimeout
		}
		if poolCfg.ReadTimeout > 0 {
			readTimeout = poolCfg.ReadTimeout
		}
		if poolCfg.WriteTimeout > 0 {
			writeTimeout = poolCfg.WriteTimeout
		}
		if poolCfg.PoolTimeout > 0 {
			poolTimeout = poolCfg.PoolTimeout
		}
		maxLifetime = poolCfg.MaxLifetime
		maxIdleTime = poolCfg.MaxIdleTime
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:            redisAddr,
		Password:        redisPassword,
		DB:              redisDB,
		PoolSize:        poolSize,
		MinIdleConns:    minIdleConns,
		MaxRetries:      maxRetries,
		DialTimeout:     dialTimeout,
		ReadTimeout:     readTimeout,
		WriteTimeout:    writeTimeout,
		PoolTimeout:     poolTimeout,
		ConnMaxLifetime: maxLifetime,
		ConnMaxIdleTime: maxIdleTime,
	})

	instanceID := generateInstanceID()

	return &TaskManager{
		redis:           rdb,
		prefix:          "zeek:task:",
		parentKeyPrefix: "zeek:parent_task:",
		queueKey:        "zeek:task:queue",
		streamKey:       "zeek:task:stream",
		consumerGroup:   "zeek_runner",
		expiration:      24 * time.Hour,
		instanceID:      instanceID,
	}
}

type BatchQueueJob struct {
	JobID      string    `json:"jobID"`
	TaskID     string    `json:"taskID"`
	PcapID     string    `json:"pcapID"`
	PcapPath   string    `json:"pcapPath"`
	UUIDs      []string  `json:"uuids"`
	Weight     int       `json:"weight"`
	OnlyNotice bool      `json:"onlyNotice"`
	CreatedAt  time.Time `json:"createdAt"`
	StreamID   string    `json:"streamID,omitempty"`
}

func generateInstanceID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s-%d", hostname, time.Now().UnixNano()%10000)
}

func normalizeTaskWeight(weight int) int {
	if weight <= 0 {
		return 1
	}
	if weight > 100 {
		return 100
	}
	return weight
}

func (tm *TaskManager) key(uuid string) string {
	return tm.prefix + uuid
}

func (tm *TaskManager) parentKey(taskID string) string {
	return tm.parentKeyPrefix + taskID
}

func (tm *TaskManager) batchJobMarkerKey(jobID string) string {
	return "zeek:batch_job:" + jobID
}

func (tm *TaskManager) CreateTask(ctx context.Context, req AnalyzeReq) (*Task, error) {
	task := newOfflineScanTask(req).newTaskRecord()

	if err := tm.saveTask(ctx, task); err != nil {
		return nil, err
	}

	tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusPending, "")

	slog.Info("task created", "taskID", task.TaskID, "uuid", task.UUID)
	return task, nil
}

func (tm *TaskManager) CreateBatchTasks(ctx context.Context, req AnalyzeBatchReq) ([]*Task, error) {
	tasks := make([]*Task, 0, len(req.Scripts))
	for _, script := range req.Scripts {
		task := newOfflineScanTask(AnalyzeReq{
			TaskID:     req.TaskID,
			UUID:       script.UUID,
			OnlyNotice: req.OnlyNotice,
			PcapID:     req.PcapID,
			PcapPath:   req.PcapPath,
			ScriptID:   script.ScriptID,
			ScriptPath: script.ScriptPath,
		}).newTaskRecord()
		task.RunMode = script.RunMode
		task.Weight = normalizeTaskWeight(script.Weight)
		if err := tm.saveTask(ctx, task); err != nil {
			return tasks, err
		}
		tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusPending, "")
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func (tm *TaskManager) CreateAndEnqueueBatchTasks(ctx context.Context, req AnalyzeBatchReq) ([]*Task, error) {
	tasks := make([]*Task, 0, len(req.Scripts))
	uuids := make([]string, 0, len(req.Scripts))
	weight := 0
	for _, script := range req.Scripts {
		task := newOfflineScanTask(AnalyzeReq{
			TaskID:     req.TaskID,
			UUID:       script.UUID,
			OnlyNotice: req.OnlyNotice,
			PcapID:     req.PcapID,
			PcapPath:   req.PcapPath,
			ScriptID:   script.ScriptID,
			ScriptPath: script.ScriptPath,
		}).newTaskRecord()
		task.RunMode = script.RunMode
		task.Weight = normalizeTaskWeight(script.Weight)
		tasks = append(tasks, task)
		uuids = append(uuids, task.UUID)
		weight += normalizeTaskWeight(task.Weight)
	}
	return tm.createAndEnqueueTasks(ctx, tasks, BatchQueueJob{
		JobID:      req.TaskID + ":" + req.PcapID,
		TaskID:     req.TaskID,
		PcapID:     req.PcapID,
		PcapPath:   req.PcapPath,
		UUIDs:      uuids,
		Weight:     weight,
		OnlyNotice: req.OnlyNotice,
	})
}

// CreateExtractTask 创建文件提取任务
func (tm *TaskManager) CreateExtractTask(ctx context.Context, req ExtractReq) (*Task, error) {
	task := newOfflineExtractTask(req).newTaskRecord()

	if err := tm.saveTask(ctx, task); err != nil {
		return nil, err
	}

	tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusPending, "")

	slog.Info("extract task created", "taskID", task.TaskID, "uuid", task.UUID)
	return task, nil
}

func (tm *TaskManager) CreateAndEnqueueExtractTask(ctx context.Context, req ExtractReq) (*Task, error) {
	task := newOfflineExtractTask(req).newTaskRecord()
	tasks, err := tm.createAndEnqueueTasks(ctx, []*Task{task}, BatchQueueJob{
		JobID:     task.UUID,
		TaskID:    task.TaskID,
		PcapID:    task.PcapID,
		PcapPath:  task.PcapPath,
		UUIDs:     []string{task.UUID},
		Weight:    1,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	return tasks[0], nil
}

func (tm *TaskManager) createAndEnqueueTasks(ctx context.Context, tasks []*Task, job BatchQueueJob) ([]*Task, error) {
	if len(tasks) == 0 {
		return nil, nil
	}
	tm.ensureConsumerGroup(ctx)
	if job.JobID == "" {
		job.JobID = fmt.Sprintf("%s:%d", job.TaskID, time.Now().UnixNano())
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now()
	}
	if job.Weight <= 0 {
		job.Weight = len(job.UUIDs)
		if job.Weight <= 0 {
			job.Weight = 1
		}
	}

	taskPayloads := make([]string, 0, len(tasks))
	keys := make([]string, 0, len(tasks)+3)
	for _, task := range tasks {
		data, err := json.Marshal(task)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal task: %w", err)
		}
		taskPayloads = append(taskPayloads, string(data))
		keys = append(keys, tm.key(task.UUID))
	}
	keys = append(keys, tm.parentKey(tasks[0].TaskID), tm.streamKey, tm.batchJobMarkerKey(job.JobID))
	jobPayload, err := json.Marshal(job)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch job: %w", err)
	}
	tasksPayload, err := json.Marshal(taskPayloads)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal task payloads: %w", err)
	}

	const createAndEnqueueScript = `
local taskCount = tonumber(ARGV[1])
local taskPayloads = cjson.decode(ARGV[2])
local taskID = ARGV[3]
local jobPayload = ARGV[4]
local terminalTTLMillis = tonumber(ARGV[5])
local parentKey = KEYS[taskCount + 1]
local streamKey = KEYS[taskCount + 2]
local jobMarkerKey = KEYS[taskCount + 3]
local parentRaw = redis.call("GET", parentKey)
local parent
local rebuildParent = false
if parentRaw then
  parent = cjson.decode(parentRaw)
else
  parent = {TaskID = taskID, TotalCount = 0, PendingCount = 0, RunningCount = 0, SuccessCount = 0, FailedCount = 0, TimeoutCount = 0, Status = "pending"}
  rebuildParent = true
end

local created = 0
local activeExisting = false
local results = {}
for i = 1, taskCount do
  local current = redis.call("GET", KEYS[i])
  if current then
    local task = cjson.decode(current)
    if task.status == "pending" or task.status == "running" then
      activeExisting = true
    end
    if rebuildParent then
      parent.TotalCount = parent.TotalCount + 1
      if task.status == "pending" then
        parent.PendingCount = parent.PendingCount + 1
      elseif task.status == "running" then
        parent.RunningCount = parent.RunningCount + 1
      elseif task.status == "success" then
        parent.SuccessCount = parent.SuccessCount + 1
      elseif task.status == "failed" then
        parent.FailedCount = parent.FailedCount + 1
      elseif task.status == "timeout" then
        parent.TimeoutCount = parent.TimeoutCount + 1
      end
    end
    results[i] = current
  else
    redis.call("SET", KEYS[i], taskPayloads[i])
    parent.TotalCount = (parent.TotalCount or 0) + 1
    parent.PendingCount = (parent.PendingCount or 0) + 1
    created = created + 1
    activeExisting = true
    results[i] = taskPayloads[i]
  end
end

if rebuildParent or created > 0 then
  if parent.PendingCount > 0 or parent.RunningCount > 0 then
    parent.Status = "running"
  elseif parent.FailedCount == parent.TotalCount then
    parent.Status = "failed"
  elseif parent.FailedCount > 0 or parent.TimeoutCount > 0 then
    parent.Status = "partial_failed"
  else
    parent.Status = "completed"
  end
  redis.call("SET", parentKey, cjson.encode(parent))
  if parent.Status ~= "running" and terminalTTLMillis > 0 then
    redis.call("PEXPIRE", parentKey, terminalTTLMillis)
  end
end

local markerExists = redis.call("EXISTS", jobMarkerKey)
if created > 0 or (markerExists == 0 and activeExisting) then
  redis.call("XADD", streamKey, "*", "job", jobPayload)
  redis.call("SET", jobMarkerKey, "1")
end
return results
`

	raw, err := tm.redis.Eval(ctx, createAndEnqueueScript, keys, len(tasks), string(tasksPayload), tasks[0].TaskID, string(jobPayload), tm.expiration.Milliseconds()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to create and enqueue tasks: %w", err)
	}
	values, ok := raw.([]interface{})
	if !ok || len(values) != len(tasks) {
		return nil, fmt.Errorf("unexpected create task response")
	}
	stored := make([]*Task, 0, len(values))
	for _, value := range values {
		payload, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected task payload")
		}
		var task Task
		if err := json.Unmarshal([]byte(payload), &task); err != nil {
			return nil, fmt.Errorf("failed to unmarshal stored task: %w", err)
		}
		stored = append(stored, &task)
	}
	return stored, nil
}

func (tm *TaskManager) updateParentTaskStatus(ctx context.Context, taskID string, newStatus TaskStatus, oldStatus TaskStatus) {
	key := tm.parentKey(taskID)

	data, err := tm.redis.Get(ctx, key).Bytes()
	var status ParentTaskStatus
	if err == nil {
		json.Unmarshal(data, &status)
	} else {
		status = ParentTaskStatus{TaskID: taskID}
	}

	if oldStatus != "" {
		switch oldStatus {
		case TaskStatusPending:
			status.PendingCount--
		case TaskStatusRunning:
			status.RunningCount--
		case TaskStatusSuccess:
			status.SuccessCount--
		case TaskStatusFailed:
			status.FailedCount--
		case TaskStatusTimeout:
			status.TimeoutCount--
		}
	} else {
		status.TotalCount++
	}

	switch newStatus {
	case TaskStatusPending:
		status.PendingCount++
	case TaskStatusRunning:
		status.RunningCount++
	case TaskStatusSuccess:
		status.SuccessCount++
	case TaskStatusFailed:
		status.FailedCount++
	case TaskStatusTimeout:
		status.TimeoutCount++
	}

	status.Status = tm.deriveParentStatus(&status)

	data, _ = json.Marshal(status)
	tm.redis.Set(ctx, key, data, tm.parentStatusExpiration(status.Status))
}

func (tm *TaskManager) deriveParentStatus(s *ParentTaskStatus) string {
	if s.TotalCount == 0 {
		return "pending"
	}
	if s.PendingCount > 0 || s.RunningCount > 0 {
		return "running"
	}
	if s.FailedCount == s.TotalCount {
		return "failed"
	}
	if s.FailedCount > 0 || s.TimeoutCount > 0 {
		return "partial_failed"
	}
	return "completed"
}

func (tm *TaskManager) GetParentTaskStatusFromRedis(ctx context.Context, taskID string) (*ParentTaskStatus, error) {
	key := tm.parentKey(taskID)
	data, err := tm.redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("parent task not found: %s", taskID)
	}

	var status ParentTaskStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal parent task status: %w", err)
	}

	return &status, nil
}

func (tm *TaskManager) MarkParentEventPublished(ctx context.Context, taskID string) (bool, error) {
	if tm == nil || tm.redis == nil {
		return false, nil
	}

	key := tm.parentKey(taskID) + ":analysis_event_published"
	return tm.redis.SetNX(ctx, key, tm.instanceID, tm.expiration).Result()
}

func (tm *TaskManager) UpdateStatus(ctx context.Context, uuid string, status TaskStatus) error {
	task, err := tm.GetTask(ctx, uuid)
	if err != nil {
		return err
	}

	oldStatus := task.Status
	task.Status = status

	switch status {
	case TaskStatusRunning:
		task.StartTime = time.Now()
	case TaskStatusSuccess, TaskStatusFailed, TaskStatusTimeout, TaskStatusCanceled:
		task.EndTime = time.Now()
		if !task.StartTime.IsZero() {
			task.Duration = task.EndTime.Sub(task.StartTime).Seconds()
		}
	}

	if err := tm.saveTask(ctx, task); err != nil {
		return err
	}

	if oldStatus != status {
		tm.updateParentTaskStatus(ctx, task.TaskID, status, oldStatus)
	}

	return nil
}

func (tm *TaskManager) SetRunning(ctx context.Context, uuid string) error {
	return tm.UpdateStatus(ctx, uuid, TaskStatusRunning)
}

func (tm *TaskManager) SetSuccess(ctx context.Context, uuid string, output string) error {
	return tm.SetSuccessWithStats(ctx, uuid, output, 0, 0, 0)
}

func (tm *TaskManager) SetSuccessWithStats(ctx context.Context, uuid string, output string, hitCount, noticeCount, intelCount int) error {
	task, err := tm.GetTask(ctx, uuid)
	if err != nil {
		return err
	}

	oldStatus := task.Status
	task.Status = TaskStatusSuccess
	task.EndTime = time.Now()
	if !task.StartTime.IsZero() {
		task.Duration = task.EndTime.Sub(task.StartTime).Seconds()
	}
	task.Output = output
	task.HitCount = hitCount
	task.NoticeCount = noticeCount
	task.IntelCount = intelCount

	if err := tm.saveTask(ctx, task); err != nil {
		return err
	}

	tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusSuccess, oldStatus)
	return nil
}

func (tm *TaskManager) SetFailed(ctx context.Context, uuid string, errMsg string) error {
	task, err := tm.GetTask(ctx, uuid)
	if err != nil {
		return err
	}

	oldStatus := task.Status
	task.Status = TaskStatusFailed
	task.EndTime = time.Now()
	if !task.StartTime.IsZero() {
		task.Duration = task.EndTime.Sub(task.StartTime).Seconds()
	}
	task.Error = errMsg

	if err := tm.saveTask(ctx, task); err != nil {
		return err
	}

	tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusFailed, oldStatus)
	return nil
}

func (tm *TaskManager) SetTimeout(ctx context.Context, uuid string) error {
	return tm.UpdateStatus(ctx, uuid, TaskStatusTimeout)
}

func (tm *TaskManager) IncrementRetry(ctx context.Context, uuid string) error {
	task, err := tm.GetTask(ctx, uuid)
	if err != nil {
		return err
	}

	oldStatus := task.Status
	task.Retries++
	task.Status = TaskStatusPending

	if err := tm.saveTask(ctx, task); err != nil {
		return err
	}

	if oldStatus != TaskStatusPending {
		tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusPending, oldStatus)
	}
	return nil
}

func (tm *TaskManager) CanRetry(ctx context.Context, uuid string) (bool, error) {
	task, err := tm.GetTask(ctx, uuid)
	if err != nil {
		return false, err
	}
	return task.Retries < task.MaxRetries, nil
}

func (tm *TaskManager) GetTask(ctx context.Context, uuid string) (*Task, error) {
	data, err := tm.redis.Get(ctx, tm.key(uuid)).Bytes()
	if err != nil {
		return nil, fmt.Errorf("task not found: %s", uuid)
	}

	var task Task
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("failed to unmarshal task: %w", err)
	}

	return &task, nil
}

func (tm *TaskManager) saveTask(ctx context.Context, task *Task) error {
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to marshal task: %w", err)
	}

	return tm.redis.Set(ctx, tm.key(task.UUID), data, tm.taskExpiration(task.Status)).Err()
}

func (tm *TaskManager) taskExpiration(status TaskStatus) time.Duration {
	switch status {
	case TaskStatusSuccess, TaskStatusFailed, TaskStatusTimeout, TaskStatusCanceled:
		return tm.expiration
	default:
		return 0
	}
}

func (tm *TaskManager) parentStatusExpiration(status string) time.Duration {
	switch status {
	case "completed", "partial_failed", "failed":
		return tm.expiration
	default:
		return 0
	}
}

func (tm *TaskManager) DeleteTask(ctx context.Context, uuid string) error {
	return tm.redis.Del(ctx, tm.key(uuid)).Err()
}

func (tm *TaskManager) ListPendingTasks(ctx context.Context) ([]*Task, error) {
	var tasks []*Task
	var cursor uint64

	for {
		keys, nextCursor, err := tm.redis.Scan(ctx, cursor, tm.prefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			data, err := tm.redis.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			var task Task
			if err := json.Unmarshal(data, &task); err != nil {
				continue
			}

			if task.Status == TaskStatusPending {
				tasks = append(tasks, &task)
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return tasks, nil
}

func (tm *TaskManager) GetTasksByParentID(ctx context.Context, taskID string) ([]*Task, error) {
	var tasks []*Task
	var cursor uint64

	for {
		keys, nextCursor, err := tm.redis.Scan(ctx, cursor, tm.prefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			data, err := tm.redis.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			var task Task
			if err := json.Unmarshal(data, &task); err != nil {
				continue
			}

			if task.TaskID == taskID {
				tasks = append(tasks, &task)
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return tasks, nil
}

func (tm *TaskManager) HealthCheck(ctx context.Context) error {
	return tm.redis.Ping(ctx).Err()
}

func (tm *TaskManager) Close() error {
	return tm.redis.Close()
}

func (tm *TaskManager) EnqueueTask(ctx context.Context, uuid string) error {
	return tm.EnqueueBatchJob(ctx, BatchQueueJob{
		JobID:     uuid,
		UUIDs:     []string{uuid},
		Weight:    1,
		CreatedAt: time.Now(),
	})
}

func (tm *TaskManager) ensureConsumerGroup(ctx context.Context) {
	err := tm.redis.XGroupCreateMkStream(ctx, tm.streamKey, tm.consumerGroup, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		slog.Warn("create redis stream consumer group failed", "stream", tm.streamKey, "group", tm.consumerGroup, "err", err)
	}
}

func (tm *TaskManager) EnqueueBatchJob(ctx context.Context, job BatchQueueJob) error {
	tm.ensureConsumerGroup(ctx)
	if job.JobID == "" {
		job.JobID = fmt.Sprintf("%s:%d", job.TaskID, time.Now().UnixNano())
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now()
	}
	if job.Weight <= 0 {
		job.Weight = len(job.UUIDs)
		if job.Weight <= 0 {
			job.Weight = 1
		}
	}
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	err = tm.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: tm.streamKey,
		Values: map[string]any{"job": string(data)},
	}).Err()
	if err != nil {
		return fmt.Errorf("failed to enqueue task: %w", err)
	}
	slog.Debug("task enqueued", "job", job.JobID, "instance", tm.instanceID)
	return nil
}

func (tm *TaskManager) DequeueTask(ctx context.Context, timeout time.Duration) (string, error) {
	job, err := tm.DequeueBatchJob(ctx, timeout, 10*time.Minute)
	if err != nil || job == nil || len(job.UUIDs) == 0 {
		return "", err
	}
	return job.UUIDs[0], nil
}

func (tm *TaskManager) GetQueueLength(ctx context.Context) (int64, error) {
	return tm.redis.XLen(ctx, tm.streamKey).Result()
}

func (tm *TaskManager) DequeueBatchJob(ctx context.Context, timeout time.Duration, minIdle time.Duration) (*BatchQueueJob, error) {
	tm.ensureConsumerGroup(ctx)
	claimed, _, err := tm.redis.XAutoClaim(ctx, &redis.XAutoClaimArgs{
		Stream:   tm.streamKey,
		Group:    tm.consumerGroup,
		Consumer: tm.instanceID,
		MinIdle:  minIdle,
		Start:    "0-0",
		Count:    1,
	}).Result()
	if err == nil && len(claimed) > 0 {
		return batchJobFromRedisMessage(claimed[0])
	}
	if err != nil && err != redis.Nil {
		slog.Warn("redis stream autoclaim failed", "err", err)
	}

	streams, err := tm.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    tm.consumerGroup,
		Consumer: tm.instanceID,
		Streams:  []string{tm.streamKey, ">"},
		Count:    1,
		Block:    timeout,
	}).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to dequeue task: %w", err)
	}
	for _, stream := range streams {
		for _, msg := range stream.Messages {
			return batchJobFromRedisMessage(msg)
		}
	}
	return nil, nil
}

func batchJobFromRedisMessage(msg redis.XMessage) (*BatchQueueJob, error) {
	value, ok := msg.Values["job"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid batch job payload")
	}
	var job BatchQueueJob
	if err := json.Unmarshal([]byte(value), &job); err != nil {
		return nil, err
	}
	job.StreamID = msg.ID
	return &job, nil
}

func (tm *TaskManager) AckBatchJob(ctx context.Context, job *BatchQueueJob) error {
	if job == nil || job.StreamID == "" {
		return nil
	}
	if err := tm.redis.XAck(ctx, tm.streamKey, tm.consumerGroup, job.StreamID).Err(); err != nil {
		return err
	}
	return tm.redis.XDel(ctx, tm.streamKey, job.StreamID).Err()
}

func (tm *TaskManager) AssignTask(ctx context.Context, uuid string) error {
	task, err := tm.GetTask(ctx, uuid)
	if err != nil {
		return err
	}

	task.Status = TaskStatusRunning
	task.StartTime = time.Now()

	return tm.saveTask(ctx, task)
}

func (tm *TaskManager) GetInstanceID() string {
	return tm.instanceID
}
