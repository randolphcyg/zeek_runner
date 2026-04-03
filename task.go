package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	redis      *redis.Client
	prefix     string
	expiration time.Duration
}

func NewTaskManager(redisAddr string) *TaskManager {
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		DB:       0,
		PoolSize: 10,
	})

	return &TaskManager{
		redis:      rdb,
		prefix:     "zeek:task:",
		expiration: 24 * time.Hour,
	}
}

func (tm *TaskManager) key(taskID string) string {
	return tm.prefix + taskID
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

	slog.Info("task created", "taskID", task.TaskID, "uuid", task.UUID)
	return task, nil
}

func (tm *TaskManager) UpdateStatus(ctx context.Context, taskID string, status TaskStatus) error {
	task, err := tm.GetTask(ctx, taskID)
	if err != nil {
		return err
	}

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

	return tm.saveTask(ctx, task)
}

func (tm *TaskManager) SetRunning(ctx context.Context, taskID string) error {
	return tm.UpdateStatus(ctx, taskID, TaskStatusRunning)
}

func (tm *TaskManager) SetSuccess(ctx context.Context, taskID string, output string) error {
	task, err := tm.GetTask(ctx, taskID)
	if err != nil {
		return err
	}
	task.Status = TaskStatusSuccess
	task.EndTime = time.Now()
	if !task.StartTime.IsZero() {
		task.Duration = task.EndTime.Sub(task.StartTime).Seconds()
	}
	task.Output = output
	return tm.saveTask(ctx, task)
}

func (tm *TaskManager) SetFailed(ctx context.Context, taskID string, errMsg string) error {
	task, err := tm.GetTask(ctx, taskID)
	if err != nil {
		return err
	}
	task.Status = TaskStatusFailed
	task.EndTime = time.Now()
	if !task.StartTime.IsZero() {
		task.Duration = task.EndTime.Sub(task.StartTime).Seconds()
	}
	task.Error = errMsg
	return tm.saveTask(ctx, task)
}

func (tm *TaskManager) SetTimeout(ctx context.Context, taskID string) error {
	return tm.UpdateStatus(ctx, taskID, TaskStatusTimeout)
}

func (tm *TaskManager) IncrementRetry(ctx context.Context, taskID string) error {
	task, err := tm.GetTask(ctx, taskID)
	if err != nil {
		return err
	}
	task.Retries++
	task.Status = TaskStatusPending
	return tm.saveTask(ctx, task)
}

func (tm *TaskManager) CanRetry(ctx context.Context, taskID string) (bool, error) {
	task, err := tm.GetTask(ctx, taskID)
	if err != nil {
		return false, err
	}
	return task.Retries < task.MaxRetries, nil
}

func (tm *TaskManager) GetTask(ctx context.Context, taskID string) (*Task, error) {
	data, err := tm.redis.Get(ctx, tm.key(taskID)).Bytes()
	if err != nil {
		return nil, fmt.Errorf("task not found: %s", taskID)
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

	return tm.redis.Set(ctx, tm.key(task.TaskID), data, tm.expiration).Err()
}

func (tm *TaskManager) DeleteTask(ctx context.Context, taskID string) error {
	return tm.redis.Del(ctx, tm.key(taskID)).Err()
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

func (tm *TaskManager) HealthCheck(ctx context.Context) error {
	return tm.redis.Ping(ctx).Err()
}

func (tm *TaskManager) Close() error {
	return tm.redis.Close()
}
