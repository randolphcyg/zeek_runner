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
	LogServiceEvent("health_check")

	statusMsg := "ok"
	if !s.app.IsKafkaReady() {
		statusMsg = "kafka_down"
	}
	cfg := s.app.ConfigManager.Get()

	redisReady := s.app.TaskManager != nil
	if redisReady {
		if err := s.app.TaskManager.HealthCheck(ctx); err != nil {
			redisReady = false
		}
	}

	return &pb.HealthCheckResponse{
		Status:       statusMsg,
		PoolRunning:  int32(s.app.TaskPool.Running()),
		PoolCapacity: int32(cfg.Pool.Size),
		KafkaReady:   s.app.IsKafkaReady(),
		RedisReady:   redisReady,
		Timestamp:    time.Now().Format(time.RFC3339),
		Version:      "1.0.0",
		GoVersion:    "1.23",
		Os:           "linux",
		Arch:         "amd64",
	}, nil
}

func (s *GRPCServer) VersionCheck(ctx context.Context, req *pb.VersionCheckRequest) (*pb.VersionCheckResponse, error) {
	component := req.GetComponent()
	LogServiceEvent("version_check", "component", component)

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

func (s *GRPCServer) AsyncAnalyze(ctx context.Context, req *pb.AsyncAnalyzeRequest) (*pb.AsyncAnalyzeResponse, error) {
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

	task, err := s.service.SubmitAsyncTask(ctx, ar)
	if err != nil {
		if strings.Contains(err.Error(), "pool full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		if strings.Contains(err.Error(), "Redis required") {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.AsyncAnalyzeResponse{
		TaskID:     task.TaskID,
		Uuid:       task.UUID,
		Status:     string(task.Status),
		CreateTime: task.CreateTime.Format(time.RFC3339),
	}, nil
}

func (s *GRPCServer) GetTaskStatus(ctx context.Context, req *pb.TaskStatusRequest) (*pb.TaskStatusResponse, error) {
	task, err := s.service.GetTaskStatus(ctx, req.TaskID)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &pb.TaskStatusResponse{
		TaskID:     task.TaskID,
		Uuid:       task.UUID,
		PcapID:     task.PcapID,
		PcapPath:   task.PcapPath,
		ScriptID:   task.ScriptID,
		ScriptPath: task.ScriptPath,
		Status:     string(task.Status),
		CreateTime: task.CreateTime.Format(time.RFC3339),
		StartTime:  task.StartTime.Format(time.RFC3339),
		EndTime:    task.EndTime.Format(time.RFC3339),
		Duration:   task.Duration,
		Error:      task.Error,
		Output:     task.Output,
		Retries:    int32(task.Retries),
	}, nil
}
