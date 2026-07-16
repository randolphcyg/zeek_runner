package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	pb "zeek_runner/api/pb"
)

func dialHealthServer(t *testing.T, hs *HealthServer) (grpc_health_v1.HealthClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	hs.Register(srv)
	go func() { _ = srv.Serve(lis) }()

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
	}
	return grpc_health_v1.NewHealthClient(conn), cleanup
}

func checkStatus(t *testing.T, ctx context.Context, c grpc_health_v1.HealthClient, service string) grpc_health_v1.HealthCheckResponse_ServingStatus {
	t.Helper()
	resp, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: service})
	if err != nil {
		t.Fatalf("Check(%q) failed: %v", service, err)
	}
	return resp.Status
}

func TestHealthServer_LivenessAndReadiness(t *testing.T) {
	hs := NewHealthServer()
	// 初始状态：存活 SERVING（进程已起），就绪显式置为 SERVING。
	hs.SetLiveness(true)
	hs.SetReadiness(true)

	client, cleanup := dialHealthServer(t, hs)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if got := checkStatus(t, ctx, client, ""); got != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("liveness: expected SERVING, got %v", got)
	}
	if got := checkStatus(t, ctx, client, zeekAnalysisServiceName); got != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("readiness: expected SERVING, got %v", got)
	}

	// 就绪与存活独立：Redis 失联只影响就绪，存活仍 SERVING。
	hs.SetReadiness(false)
	if got := checkStatus(t, ctx, client, zeekAnalysisServiceName); got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness after redis down: expected NOT_SERVING, got %v", got)
	}
	if got := checkStatus(t, ctx, client, ""); got != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("liveness after redis down: expected SERVING, got %v", got)
	}
}

func TestHealthServer_ShutdownSetsNotServing(t *testing.T) {
	hs := NewHealthServer()
	hs.SetLiveness(true)
	hs.SetReadiness(true)

	client, cleanup := dialHealthServer(t, hs)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 优雅退出前置所有状态为 NOT_SERVING。
	hs.Shutdown()
	if got := checkStatus(t, ctx, client, ""); got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("liveness after shutdown: expected NOT_SERVING, got %v", got)
	}
	if got := checkStatus(t, ctx, client, zeekAnalysisServiceName); got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness after shutdown: expected NOT_SERVING, got %v", got)
	}
}

// TestGRPCIntegration_HealthAndCapacityCheck 是端到端 gRPC 集成测试：
// 在同一个 bufconn gRPC server 上同时注册标准 Health 服务与 ZeekAnalysisService（含 CapacityCheck），
// 通过真实 gRPC client 验证“就绪”与“容量”两条路径独立工作。
func TestGRPCIntegration_HealthAndCapacityCheck(t *testing.T) {
	svc, pool := newCapacityService(t, 8, 4)
	defer pool.Release()
	svc.scheduler.TryAcquire(1, svc.weightedCapacity()) // weighted_running=1
	defer svc.scheduler.Release(1)

	hs := NewHealthServer()
	hs.SetLiveness(true)
	hs.SetReadiness(true)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	pb.RegisterZeekAnalysisServiceServer(srv, NewGRPCServer(svc, nil))
	hs.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.Dial: %v", err)
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	zeekClient := pb.NewZeekAnalysisServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1) 标准 Health：存活与就绪均为 SERVING。
	if got := checkStatus(t, ctx, healthClient, ""); got != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("liveness: expected SERVING, got %v", got)
	}
	if got := checkStatus(t, ctx, healthClient, zeekAnalysisServiceName); got != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("readiness: expected SERVING, got %v", got)
	}

	// 2) CapacityCheck：通过真实 gRPC client 调用，返回真实容量快照。
	capResp, err := zeekClient.CapacityCheck(ctx, &pb.CapacityCheckRequest{})
	if err != nil {
		t.Fatalf("CapacityCheck via gRPC: %v", err)
	}
	if !capResp.GetAcceptingJobs() {
		t.Errorf("AcceptingJobs: expected true")
	}
	if capResp.GetPoolCapacity() != 8 {
		t.Errorf("PoolCapacity: expected 8, got %d", capResp.GetPoolCapacity())
	}
	if capResp.GetWeightedRunning() != 1 {
		t.Errorf("WeightedRunning: expected 1, got %d", capResp.GetWeightedRunning())
	}
	if capResp.GetWeightedCapacity() != 4 {
		t.Errorf("WeightedCapacity: expected 4, got %d", capResp.GetWeightedCapacity())
	}
	if capResp.GetTimestamp() == "" {
		t.Errorf("Timestamp: expected non-empty")
	}

	// 3) 就绪与容量独立：就绪翻为 NOT_SERVING（模拟 Redis 失联）不影响存活，也不影响 CapacityCheck 的 pool/weighted 字段。
	hs.SetReadiness(false)
	if got := checkStatus(t, ctx, healthClient, zeekAnalysisServiceName); got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness after flip: expected NOT_SERVING, got %v", got)
	}
	if got := checkStatus(t, ctx, healthClient, ""); got != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("liveness after readiness flip: expected SERVING, got %v", got)
	}
	capResp2, err := zeekClient.CapacityCheck(ctx, &pb.CapacityCheckRequest{})
	if err != nil {
		t.Fatalf("CapacityCheck after readiness flip: %v", err)
	}
	if capResp2.GetPoolCapacity() != 8 || capResp2.GetWeightedRunning() != 1 {
		t.Errorf("capacity fields changed after readiness flip: %+v", capResp2)
	}

	// 4) 优雅退出：Shutdown 后存活与就绪均 NOT_SERVING。
	hs.Shutdown()
	if got := checkStatus(t, ctx, healthClient, ""); got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("liveness after shutdown: expected NOT_SERVING, got %v", got)
	}
	if got := checkStatus(t, ctx, healthClient, zeekAnalysisServiceName); got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness after shutdown: expected NOT_SERVING, got %v", got)
	}
}
