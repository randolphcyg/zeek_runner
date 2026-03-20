package main

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"zeek_runner/api/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GRPCServer struct {
	pb.UnimplementedZeekAnalysisServiceServer
	service *Service
	app     *App
}

func NewGRPCServer(service *Service, app *App) *GRPCServer {
	return &GRPCServer{service: service, app: app}
}

func (s *GRPCServer) Analyze(ctx context.Context, req *pb.AnalyzeRequest) (*pb.AnalyzeResponse, error) {
	ar := AnalyzeReq{
		TaskID: req.TaskID, UUID: req.Uuid, OnlyNotice: req.OnlyNotice,
		PcapID: req.PcapID, PcapPath: req.PcapPath,
		ScriptID: req.ScriptID, ScriptPath: req.ScriptPath,
		ExtractedFilePath: req.ExtractedFilePath, ExtractedFileMinSize: int(req.ExtractedFileMinSize),
	}

	if ar.ExtractedFilePath != "" && ar.ScriptID == "" {
		ar.ScriptID = "EXTRACT_TASK"
	}

	if err := validateReq(ar); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.ExecuteTaskInPool(ctx, ar)
	if err != nil {
		if strings.Contains(err.Error(), "pool full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.AnalyzeResponse{
		TaskID: resp.TaskID, Uuid: resp.UUID,
		PcapPath: resp.PcapPath, ScriptPath: resp.ScriptPath, StartTime: resp.StartTime,
	}, nil
}

func (s *GRPCServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	statusMsg := "ok"
	if !s.app.IsKafkaReady() {
		statusMsg = "kafka_down"
	}
	cfg := s.app.ConfigManager.Get()
	return &pb.HealthCheckResponse{
		Status:       statusMsg,
		PoolRunning:  int32(s.app.TaskPool.Running()),
		PoolCapacity: int32(cfg.PoolSize),
		KafkaReady:   s.app.IsKafkaReady(),
		Timestamp:    time.Now().Format(time.RFC3339),
		Version:      "1.0.0",
		GoVersion:    "1.23",
		Os:           "linux",
		Arch:         "amd64",
	}, nil
}

func (s *GRPCServer) VersionCheck(ctx context.Context, req *pb.VersionCheckRequest) (*pb.VersionCheckResponse, error) {
	component := req.GetComponent()
	if component != "zeek" && component != "zeek-kafka" {
		return nil, status.Error(codes.InvalidArgument, "component must be 'zeek' or 'zeek-kafka'")
	}

	var cmd *exec.Cmd
	if component == "zeek" {
		cmd = exec.Command("zeek", "--version")
	} else {
		cmd = exec.Command("zeek", "-N", "Seiso::Kafka")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get %s version: %v", component, err)
	}

	return &pb.VersionCheckResponse{
		Component: component,
		Version:   strings.TrimSpace(string(out)),
	}, nil
}

func (s *GRPCServer) ZeekSyntaxCheck(ctx context.Context, req *pb.ZeekSyntaxCheckRequest) (*pb.ZeekSyntaxCheckResponse, error) {
	result, err := doSyntaxCheck(req.GetScriptPath(), req.GetScriptContent())
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &pb.ZeekSyntaxCheckResponse{
		Valid: result.Valid,
		Error: result.Error,
	}, nil
}
