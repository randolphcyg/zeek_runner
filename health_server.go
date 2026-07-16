package main

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// zeekAnalysisServiceName 是就绪检查使用的 gRPC 服务名（与 proto 中 service 定义一致）。
const zeekAnalysisServiceName = "zeek_runner.ZeekAnalysisService"

// HealthServer 封装标准 grpc.health.v1.Health 服务，彻底分离“存活”与“就绪”两类检查。
//
//   - Check(service="")                              存活检查：进程启动完成后 SERVING，优雅退出前置为 NOT_SERVING。
//   - Check(service="zeek_runner.ZeekAnalysisService") 就绪检查：Redis/TaskManager 可连通时 SERVING，不可用时 NOT_SERVING。
//
// 本服务没有 Mongo，不引入 Mongo 就绪条件；Kafka 单独暴露状态与告警，不作为任务接收的标准就绪条件。
type HealthServer struct {
	server *health.Server
}

func NewHealthServer() *HealthServer {
	return &HealthServer{server: health.NewServer()}
}

// Register 将标准 Health 服务注册到 gRPC server。
func (h *HealthServer) Register(s *grpc.Server) {
	healthpb.RegisterHealthServer(s, h.server)
}

// SetLiveness 设置存活状态（service=""）。
func (h *HealthServer) SetLiveness(serving bool) {
	h.server.SetServingStatus("", servingStatus(serving))
}

// SetReadiness 设置就绪状态（service="zeek_runner.ZeekAnalysisService"）。
func (h *HealthServer) SetReadiness(serving bool) {
	h.server.SetServingStatus(zeekAnalysisServiceName, servingStatus(serving))
}

func servingStatus(serving bool) healthpb.HealthCheckResponse_ServingStatus {
	if serving {
		return healthpb.HealthCheckResponse_SERVING
	}
	return healthpb.HealthCheckResponse_NOT_SERVING
}

// Shutdown 优雅退出前置所有服务状态为 NOT_SERVING，使下游负载均衡器摘除流量。
func (h *HealthServer) Shutdown() {
	h.server.Shutdown()
}
