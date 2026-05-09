package main

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"time"
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

func (s *Service) acceptingJobs(ctx context.Context) bool {
	if s == nil || s.taskManager == nil {
		return false
	}
	cfg := s.getConfig()
	if cfg.Scheduler.KafkaLagHighWatermark > 0 {
		if lag := s.kafkaLag(ctx); lag > cfg.Scheduler.KafkaLagHighWatermark {
			return false
		}
	}
	if cfg.Scheduler.MinFreeDiskPercent > 0 {
		if free := freeDiskPercent("."); free > 0 && free < float64(cfg.Scheduler.MinFreeDiskPercent) {
			return false
		}
	}
	return true
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
