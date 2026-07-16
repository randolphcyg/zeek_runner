package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/panjf2000/ants/v2"
	pb "zeek_runner/api/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newCapacityService(t *testing.T, poolSize, weightedCapacity int) (*Service, *ants.Pool) {
	t.Helper()
	pool, err := ants.NewPool(poolSize)
	if err != nil {
		t.Fatalf("ants.NewPool: %v", err)
	}
	cm := &ConfigManager{}
	cm.config.Store(&Config{
		Pool:      PoolConfig{Size: poolSize},
		Scheduler: SchedulerConfig{WeightedCapacity: weightedCapacity, MinFreeDiskPercent: 0},
	})
	svc := &Service{
		pool:          pool,
		configManager: cm,
		scheduler:     &ResourceScheduler{},
		taskManager:   &TaskManager{}, // 非 nil 占位，admitJob 仅检查 nil
	}
	return svc, pool
}

// waitUntilPoolRunning 轮询直到 pool.Running() 达到 want 或超时，避免 Submit 后的调度竞态。
func waitUntilPoolRunning(t *testing.T, pool *ants.Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pool.Running() == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("pool.Running() never reached %d (got %d)", want, pool.Running())
}

func TestAdmitJob_DependencyUnavailableWhenNoTaskManager(t *testing.T) {
	cm := &ConfigManager{}
	cm.config.Store(&Config{Pool: PoolConfig{Size: 8}})
	svc := &Service{pool: nil, configManager: cm, scheduler: &ResourceScheduler{}, taskManager: nil}

	if err := svc.admitJob(context.Background()); !errors.Is(err, ErrDependencyUnavailable) {
		t.Fatalf("expected ErrDependencyUnavailable, got %v", err)
	}
}

func TestAdmitJob_CapacityExhaustedWhenPoolFull(t *testing.T) {
	svc, pool := newCapacityService(t, 1, 4)
	defer pool.Release()

	release := make(chan struct{})
	defer close(release)
	if err := pool.Submit(func() { <-release }); err != nil {
		t.Fatalf("submit blocking task: %v", err)
	}
	waitUntilPoolRunning(t, pool, 1)

	err := svc.admitJob(context.Background())
	if !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("expected ErrCapacityExhausted, got %v", err)
	}
}

func TestAdmitJob_CapacityExhaustedWhenWeightedFull(t *testing.T) {
	svc, pool := newCapacityService(t, 8, 2)
	defer pool.Release()

	// 占满权重上限（weightedCapacity=2）
	if !svc.scheduler.TryAcquire(2, svc.weightedCapacity()) {
		t.Fatalf("TryAcquire(2) failed")
	}
	defer svc.scheduler.Release(2)

	// pool 仍有空闲，但权重已满 -> 容量耗尽
	err := svc.admitJob(context.Background())
	if !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("expected ErrCapacityExhausted, got %v", err)
	}
}

func TestAdmitJob_Accepting(t *testing.T) {
	svc, pool := newCapacityService(t, 8, 4)
	defer pool.Release()

	if err := svc.admitJob(context.Background()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !svc.acceptingJobs(context.Background()) {
		t.Fatalf("expected acceptingJobs=true")
	}
}

func TestServiceCapacityCheck_Snapshot(t *testing.T) {
	svc, pool := newCapacityService(t, 8, 4)
	defer pool.Release()

	svc.scheduler.TryAcquire(1, svc.weightedCapacity()) // weighted_running=1
	defer svc.scheduler.Release(1)

	snap := svc.CapacityCheck(context.Background())
	if !snap.AcceptingJobs {
		t.Errorf("expected AcceptingJobs=true, got false")
	}
	if snap.PoolCapacity != 8 {
		t.Errorf("PoolCapacity: expected 8, got %d", snap.PoolCapacity)
	}
	if snap.WeightedRunning != 1 {
		t.Errorf("WeightedRunning: expected 1, got %d", snap.WeightedRunning)
	}
	if snap.WeightedCapacity != 4 {
		t.Errorf("WeightedCapacity: expected 4, got %d", snap.WeightedCapacity)
	}
	if snap.QueuePending != 0 {
		t.Errorf("QueuePending: expected 0, got %d", snap.QueuePending)
	}
}

func TestGRPCServer_CapacityCheck(t *testing.T) {
	svc, pool := newCapacityService(t, 8, 4)
	defer pool.Release()

	server := NewGRPCServer(svc, nil)
	resp, err := server.CapacityCheck(context.Background(), &pb.CapacityCheckRequest{})
	if err != nil {
		t.Fatalf("CapacityCheck failed: %v", err)
	}
	if !resp.GetAcceptingJobs() {
		t.Errorf("expected AcceptingJobs=true")
	}
	if resp.GetPoolCapacity() != 8 {
		t.Errorf("PoolCapacity: expected 8, got %d", resp.GetPoolCapacity())
	}
	if resp.GetWeightedCapacity() != 4 {
		t.Errorf("WeightedCapacity: expected 4, got %d", resp.GetWeightedCapacity())
	}
	if resp.GetTimestamp() == "" {
		t.Errorf("expected non-empty timestamp")
	}
}

func TestGRPCStatusFromError_CapacityAndDependency(t *testing.T) {
	if code := status.Code(grpcStatusFromError(ErrCapacityExhausted)); code != codes.ResourceExhausted {
		t.Errorf("ErrCapacityExhausted: expected ResourceExhausted, got %v", code)
	}
	if code := status.Code(grpcStatusFromError(ErrDependencyUnavailable)); code != codes.Unavailable {
		t.Errorf("ErrDependencyUnavailable: expected Unavailable, got %v", code)
	}
}

func TestHTTPCodeFromError_CapacityAndDependency(t *testing.T) {
	if code := httpCodeFromError(ErrCapacityExhausted); code != http.StatusServiceUnavailable {
		t.Errorf("ErrCapacityExhausted: expected 503, got %d", code)
	}
	if code := httpCodeFromError(ErrDependencyUnavailable); code != http.StatusServiceUnavailable {
		t.Errorf("ErrDependencyUnavailable: expected 503, got %d", code)
	}
	// 同步 pool 满返回的 gRPC ResourceExhausted 状态码也应映射为 503
	st := status.Error(codes.ResourceExhausted, "task pool full")
	if code := httpCodeFromError(st); code != http.StatusServiceUnavailable {
		t.Errorf("ResourceExhausted status: expected 503, got %d", code)
	}
}
