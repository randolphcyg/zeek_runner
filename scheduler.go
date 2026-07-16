package main

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// 领域错误：用于将准入失败与依赖故障精确映射到 gRPC/HTTP 状态码。
var (
	// ErrCapacityExhausted 表示实例容量已满（磁盘阈值、worker pool 或权重上限）。
	// 调用方应映射为 ResourceExhausted / HTTP 503，但不视为业务失败。
	ErrCapacityExhausted = errors.New("capacity exhausted")
	// ErrDependencyUnavailable 表示依赖（如 Redis/TaskManager）不可用。
	// 调用方应映射为 Unavailable / HTTP 503，不得误报为容量满。
	ErrDependencyUnavailable = errors.New("dependency unavailable")
)

type ResourceSnapshot struct {
	QueuePending     int64
	WeightedRunning  int
	WeightedCapacity int
	CPUUsage         float64
	MemUsage         float64
	DiskIOBusy       float64
	KafkaLag         int64
	AcceptingJobs    bool
}

type ResourceScheduler struct {
	mu      sync.Mutex
	running int
}

func (s *ResourceScheduler) TryAcquire(weight, capacity int) bool {
	if weight <= 0 {
		weight = 1
	}
	if capacity <= 0 {
		capacity = 1
	}
	if weight > capacity {
		weight = capacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running+weight > capacity {
		return false
	}
	s.running += weight
	return true
}

func (s *ResourceScheduler) Release(weight int) {
	if weight <= 0 {
		weight = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running -= weight
	if s.running < 0 {
		s.running = 0
	}
}

func (s *ResourceScheduler) Running() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Service) weightedCapacity() int {
	cfg := s.getConfig()
	if cfg.Scheduler.WeightedCapacity > 0 {
		return cfg.Scheduler.WeightedCapacity
	}
	if cfg.Pool.Size > 0 {
		return cfg.Pool.Size
	}
	return 1
}

// admitJob 是 SubmitExtractAsyncTask 与 CapacityCheck 共享的准入逻辑，
// 确保“健康接口说满”与“提交仍成功”不会同时发生。
// 返回 nil 表示可接收；ErrDependencyUnavailable 表示依赖故障；ErrCapacityExhausted 表示容量满。
func (s *Service) admitJob(ctx context.Context) error {
	if s == nil {
		return ErrDependencyUnavailable
	}
	if s.taskManager == nil {
		return ErrDependencyUnavailable
	}
	cfg := s.getConfig()
	if cfg.Scheduler.MinFreeDiskPercent > 0 {
		if free := freeDiskPercent("."); free > 0 && free < float64(cfg.Scheduler.MinFreeDiskPercent) {
			return ErrCapacityExhausted
		}
	}
	if s.pool != nil && s.pool.Running() >= cfg.Pool.Size {
		return ErrCapacityExhausted
	}
	if s.scheduler != nil && s.scheduler.Running() >= s.weightedCapacity() {
		return ErrCapacityExhausted
	}
	return nil
}

func (s *Service) acceptingJobs(ctx context.Context) bool {
	return s.admitJob(ctx) == nil
}

// CapacitySnapshot 是 CapacityCheck 的领域级返回，仅包含真实可用于背压的字段。
type CapacitySnapshot struct {
	AcceptingJobs    bool
	PoolRunning      int
	PoolCapacity     int
	WeightedRunning  int
	WeightedCapacity int
	QueuePending     int64
}

// CapacityCheck 返回单实例容量口径快照，供 gRPC/HTTP 暴露给 downstream 做背压。
// accepting_jobs 与 SubmitExtractAsyncTask 入队前调用的 admitJob 共享同一套准入逻辑。
func (s *Service) CapacityCheck(ctx context.Context) CapacitySnapshot {
	cfg := s.getConfig()
	poolRunning := 0
	if s.pool != nil {
		poolRunning = s.pool.Running()
	}
	weightedRunning := 0
	if s.scheduler != nil {
		weightedRunning = s.scheduler.Running()
	}
	var queuePending int64
	if s.taskManager != nil {
		if q, err := s.taskManager.GetPendingQueueLength(ctx); err == nil {
			queuePending = q
		}
	}
	return CapacitySnapshot{
		AcceptingJobs:    s.admitJob(ctx) == nil,
		PoolRunning:      poolRunning,
		PoolCapacity:     cfg.Pool.Size,
		WeightedRunning:  weightedRunning,
		WeightedCapacity: s.weightedCapacity(),
		QueuePending:     queuePending,
	}
}

func (s *Service) resourceSnapshot(ctx context.Context) ResourceSnapshot {
	var queueLen int64
	if s != nil && s.taskManager != nil {
		queueLen, _ = s.taskManager.GetQueueLength(ctx)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	memUsage := 0.0
	if mem.Sys > 0 {
		memUsage = float64(mem.Alloc) / float64(mem.Sys)
	}
	running := 0
	if s != nil && s.scheduler != nil {
		running = s.scheduler.Running()
	}
	return ResourceSnapshot{
		QueuePending:     queueLen,
		WeightedRunning:  running,
		WeightedCapacity: s.weightedCapacity(),
		CPUUsage:         0,
		MemUsage:         memUsage,
		DiskIOBusy:       0,
		KafkaLag:         s.kafkaLag(ctx),
		AcceptingJobs:    s.acceptingJobs(ctx),
	}
}

func (s *Service) kafkaLag(ctx context.Context) int64 {
	return 0
}

func (s *Service) leaseTimeout() time.Duration {
	cfg := s.getConfig()
	if cfg.Scheduler.LeaseTimeout != "" {
		if d, err := time.ParseDuration(cfg.Scheduler.LeaseTimeout); err == nil && d > 0 {
			return d
		}
	}
	return 10 * time.Minute
}

func freeDiskPercent(path string) float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	free := float64(stat.Bavail) * float64(stat.Bsize)
	if total <= 0 {
		return 0
	}
	return free / total * 100
}
