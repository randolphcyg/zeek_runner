package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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
	OnlyNotice           bool       `json:"onlyNotice"`
	ExtractedFilePath    string     `json:"extractedFilePath"`
	ExtractedFileMinSize int        `json:"extractedFileMinSize"`
	Status               TaskStatus `json:"status"`
	CreateTime           time.Time  `json:"createTime"`
	StartTime            time.Time  `json:"startTime"`
	EndTime              time.Time  `json:"endTime"`
	Duration             float64    `json:"duration"`
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
		expiration:      24 * time.Hour,
		instanceID:      instanceID,
	}
}

func generateInstanceID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s-%d", hostname, time.Now().UnixNano()%10000)
}

func (tm *TaskManager) key(uuid string) string {
	return tm.prefix + uuid
}

func (tm *TaskManager) parentKey(taskID string) string {
	return tm.parentKeyPrefix + taskID
}

func (tm *TaskManager) CreateTask(ctx context.Context, req AnalyzeReq) (*Task, error) {
	task := &Task{
		TaskID:               req.TaskID,
		UUID:                 req.UUID,
		PcapID:               req.PcapID,
		PcapPath:             req.PcapPath,
		ScriptID:             req.ScriptID,
		ScriptPath:           req.ScriptPath,
		OnlyNotice:           req.OnlyNotice,
		ExtractedFilePath:    req.ExtractedFilePath,
		ExtractedFileMinSize: req.ExtractedFileMinSize,
		Status:               TaskStatusPending,
		CreateTime:           time.Now(),
		MaxRetries:           3,
	}

	if err := tm.saveTask(ctx, task); err != nil {
		return nil, err
	}

	tm.updateParentTaskStatus(ctx, task.TaskID, TaskStatusPending, "")

	slog.Info("task created", "taskID", task.TaskID, "uuid", task.UUID)
	return task, nil
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
	tm.redis.Set(ctx, key, data, tm.expiration)
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

	return tm.redis.Set(ctx, tm.key(task.UUID), data, tm.expiration).Err()
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
	err := tm.redis.RPush(ctx, tm.queueKey, uuid).Err()
	if err != nil {
		return fmt.Errorf("failed to enqueue task: %w", err)
	}
	slog.Debug("task enqueued", "uuid", uuid, "instance", tm.instanceID)
	return nil
}

func (tm *TaskManager) DequeueTask(ctx context.Context, timeout time.Duration) (string, error) {
	result, err := tm.redis.BLPop(ctx, timeout, tm.queueKey).Result()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to dequeue task: %w", err)
	}

	if len(result) < 2 {
		return "", fmt.Errorf("invalid dequeue result")
	}

	uuid := result[1]
	slog.Debug("task dequeued", "uuid", uuid, "instance", tm.instanceID)
	return uuid, nil
}

func (tm *TaskManager) GetQueueLength(ctx context.Context) (int64, error) {
	return tm.redis.LLen(ctx, tm.queueKey).Result()
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
