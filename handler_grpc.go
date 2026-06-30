package main

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
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
	ar := analyzeReqFromGRPC(req)

	if err := validateReq(ar); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.ExecuteTaskInPool(ctx, ar)
	if err != nil {
		if strings.Contains(err.Error(), "pool full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		return nil, grpcStatusFromError(err)
	}

	return &pb.AnalyzeResponse{
		TaskID: resp.TaskID, Uuid: resp.UUID,
		PcapPath: resp.PcapPath, ScriptPath: resp.ScriptPath, StartTime: resp.StartTime,
	}, nil
}

// Extract 处理同步文件提取请求
func (s *GRPCServer) Extract(ctx context.Context, req *pb.ExtractRequest) (*pb.ExtractResponse, error) {
	er := extractReqFromGRPC(req)

	if err := validateExtractReq(er); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.ExecuteExtractTask(ctx, er)
	if err != nil {
		if strings.Contains(err.Error(), "pool full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.ExtractResponse{
		TaskID: resp.TaskID, Uuid: resp.UUID,
		PcapPath: resp.PcapPath, OutputDir: resp.OutputDir, StartTime: resp.StartTime,
	}, nil
}

func (s *GRPCServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	LogServiceEvent("health_check")

	statusMsg := "ok"
	if !s.app.IsKafkaReady() {
		statusMsg = "kafka_down"
	}
	cfg := s.app.ConfigManager.Get()

	redisReady := s.app.IsRedisReady()
	if s.app.TaskManager != nil {
		if err := s.app.TaskManager.HealthCheck(ctx); err != nil {
			redisReady = false
		}
	}
	snapshot := s.service.resourceSnapshot(ctx)

	return &pb.HealthCheckResponse{
		Status:           statusMsg,
		PoolRunning:      int32(s.app.TaskPool.Running()),
		PoolCapacity:     int32(cfg.Pool.Size),
		KafkaReady:       s.app.IsKafkaReady(),
		RedisReady:       redisReady,
		Timestamp:        time.Now().Format(time.RFC3339),
		Version:          Version,
		GoVersion:        runtime.Version(),
		Os:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		QueuePending:     snapshot.QueuePending,
		WeightedRunning:  int32(snapshot.WeightedRunning),
		WeightedCapacity: int32(snapshot.WeightedCapacity),
		CpuUsage:         snapshot.CPUUsage,
		MemUsage:         snapshot.MemUsage,
		DiskIoBusy:       snapshot.DiskIOBusy,
		KafkaLag:         snapshot.KafkaLag,
		AcceptingJobs:    snapshot.AcceptingJobs,
	}, nil
}

func (s *GRPCServer) VersionCheck(ctx context.Context, req *pb.VersionCheckRequest) (*pb.VersionCheckResponse, error) {
	component := req.GetComponent()
	LogServiceEvent("version_check", "component", component)

	if component != "zeek" {
		return nil, status.Error(codes.InvalidArgument, "component must be 'zeek'")
	}

	cmd := exec.Command("zeek", "--version")

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
	scriptPath := req.GetScriptPath()
	if req.GetScriptContent() == "" && req.GetScriptID() != "" {
		script, err := s.service.ResolveManagedScript(req.GetScriptID(), "")
		if err != nil {
			return nil, grpcStatusFromError(err)
		}
		scriptPath = script.ScriptPath
	}

	result, err := doSyntaxCheck(scriptPath, req.GetScriptContent())
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
	ar := asyncAnalyzeReqFromGRPC(req)

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
		return nil, grpcStatusFromError(err)
	}

	return &pb.AsyncAnalyzeResponse{
		TaskID:     task.TaskID,
		Uuid:       task.UUID,
		Status:     string(task.Status),
		CreateTime: task.CreateTime.Format(time.RFC3339),
	}, nil
}

func (s *GRPCServer) AsyncAnalyzeBatch(ctx context.Context, req *pb.AsyncAnalyzeBatchRequest) (*pb.AsyncAnalyzeBatchResponse, error) {
	ar := asyncAnalyzeBatchReqFromGRPC(req)
	tasks, err := s.service.SubmitAsyncBatchTask(ctx, ar)
	if err != nil {
		if strings.Contains(err.Error(), "Redis required") {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, grpcStatusFromError(err)
	}
	return &pb.AsyncAnalyzeBatchResponse{
		TaskID:        req.TaskID,
		AcceptedCount: int32(len(tasks)),
		RejectedCount: int32(len(req.Scripts) - len(tasks)),
		Status:        "pending",
	}, nil
}

// ExtractAsync 处理异步文件提取请求
func (s *GRPCServer) ExtractAsync(ctx context.Context, req *pb.ExtractAsyncRequest) (*pb.ExtractAsyncResponse, error) {
	er := extractAsyncReqFromGRPC(req)

	if err := validateExtractReq(er); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	task, err := s.service.SubmitExtractAsyncTask(ctx, er)
	if err != nil {
		if strings.Contains(err.Error(), "pool full") {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		if strings.Contains(err.Error(), "Redis required") {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.ExtractAsyncResponse{
		TaskID:     task.TaskID,
		Uuid:       task.UUID,
		Status:     string(task.Status),
		CreateTime: task.CreateTime.Format(time.RFC3339),
	}, nil
}

func (s *GRPCServer) GetTaskStatus(ctx context.Context, req *pb.TaskStatusRequest) (*pb.TaskStatusResponse, error) {
	task, err := s.service.GetTaskStatus(ctx, req.Uuid)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &pb.TaskStatusResponse{
		TaskID:      task.TaskID,
		Uuid:        task.UUID,
		PcapID:      task.PcapID,
		PcapPath:    task.PcapPath,
		ScriptID:    task.ScriptID,
		ScriptPath:  task.ScriptPath,
		Status:      string(task.Status),
		CreateTime:  task.CreateTime.Format(time.RFC3339),
		StartTime:   task.StartTime.Format(time.RFC3339),
		EndTime:     task.EndTime.Format(time.RFC3339),
		Duration:    task.Duration,
		HitCount:    int32(task.HitCount),
		NoticeCount: int32(task.NoticeCount),
		IntelCount:  int32(task.IntelCount),
		Error:       task.Error,
		Output:      task.Output,
		Retries:     int32(task.Retries),
	}, nil
}

func (s *GRPCServer) GetParentTaskStatus(ctx context.Context, req *pb.ParentTaskStatusRequest) (*pb.ParentTaskStatusResponse, error) {
	parentStatus, err := s.service.GetParentTaskStatus(ctx, req.TaskID)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	subTasks := make([]*pb.SubTaskSummary, len(parentStatus.SubTasks))
	for i, task := range parentStatus.SubTasks {
		subTasks[i] = &pb.SubTaskSummary{
			Uuid:        task.UUID,
			ScriptID:    task.ScriptID,
			ScriptPath:  task.ScriptPath,
			Status:      string(task.Status),
			Duration:    task.Duration,
			HitCount:    int32(task.HitCount),
			NoticeCount: int32(task.NoticeCount),
			IntelCount:  int32(task.IntelCount),
			Error:       task.Error,
		}
	}

	return &pb.ParentTaskStatusResponse{
		TaskID:       parentStatus.TaskID,
		TotalCount:   int32(parentStatus.TotalCount),
		PendingCount: int32(parentStatus.PendingCount),
		RunningCount: int32(parentStatus.RunningCount),
		SuccessCount: int32(parentStatus.SuccessCount),
		FailedCount:  int32(parentStatus.FailedCount),
		TimeoutCount: int32(parentStatus.TimeoutCount),
		HitCount:     int32(parentStatus.HitCount),
		NoticeCount:  int32(parentStatus.NoticeCount),
		IntelCount:   int32(parentStatus.IntelCount),
		Status:       parentStatus.Status,
		SubTasks:     subTasks,
	}, nil
}

func (s *GRPCServer) ListScripts(ctx context.Context, req *pb.ListScriptsRequest) (*pb.ListScriptsResponse, error) {
	scripts := s.service.ListScripts(ListScriptsRequest{
		Name:        req.GetName(),
		EnabledOnly: req.GetEnabledOnly(),
	})
	resp := &pb.ListScriptsResponse{Scripts: make([]*pb.ScriptInfo, len(scripts))}
	for i, script := range scripts {
		resp.Scripts[i] = scriptInfoToPB(script)
	}
	return resp, nil
}

func (s *GRPCServer) GetScript(ctx context.Context, req *pb.GetScriptRequest) (*pb.ScriptInfo, error) {
	script, err := s.service.GetScript(req.GetScriptID())
	if err != nil {
		return nil, grpcStatusFromError(err)
	}
	return scriptInfoToPB(script), nil
}

func (s *GRPCServer) ReloadScripts(ctx context.Context, req *pb.ReloadScriptsRequest) (*pb.ReloadScriptsResponse, error) {
	reload, err := s.service.ReloadScripts()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	resp := &pb.ReloadScriptsResponse{
		Total:   int32(reload.Total),
		Valid:   int32(reload.Valid),
		Invalid: int32(reload.Invalid),
		Scripts: make([]*pb.ScriptInfo, len(reload.Scripts)),
	}
	for i, script := range reload.Scripts {
		resp.Scripts[i] = scriptInfoToPB(script)
	}
	return resp, nil
}

func (s *GRPCServer) GetTaskHits(ctx context.Context, req *pb.GetTaskHitsRequest) (*pb.GetTaskHitsResponse, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}

	hits, err := s.service.GetTaskHits(ctx, req.GetUuid(), req.GetTaskID(), req.GetSourceType(), limit)
	if err != nil {
		if strings.Contains(err.Error(), "not initialized") {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.NotFound, err.Error())
	}

	pbHits := make([]*pb.HitEvent, 0, len(hits))
	for _, hit := range hits {
		pbHits = append(pbHits, &pb.HitEvent{
			EventID:    hit.EventID,
			EventType:  hit.EventType,
			EventTime:  hit.EventTime,
			TaskID:     hit.TaskID,
			Uuid:       hit.UUID,
			PcapID:     hit.PcapID,
			PcapPath:   hit.PcapPath,
			ScriptID:   hit.ScriptID,
			ScriptPath: hit.ScriptPath,
			Verdict:    hit.Verdict,
			SourceType: hit.SourceType,
			RuleType:   hit.RuleType,
			RuleName:   hit.RuleName,
			Message:    hit.Message,
			Indicator:  hit.Indicator,
			SrcIp:      hit.SrcIp,
			SrcPort:    int32(hit.SrcPort),
			DstIp:      hit.DstIp,
			DstPort:    int32(hit.DstPort),
			Proto:      hit.Proto,
			Uid:        hit.UID,
		})
	}

	return &pb.GetTaskHitsResponse{
		Uuid:       req.GetUuid(),
		TaskID:     req.GetTaskID(),
		TotalCount: int32(len(pbHits)),
		Hits:       pbHits,
	}, nil
}

func scriptInfoToPB(script ScriptInfo) *pb.ScriptInfo {
	return &pb.ScriptInfo{
		ScriptID:         script.ScriptID,
		ScriptName:       script.ScriptName,
		ScriptPath:       script.ScriptPath,
		ExpCodeType:      script.ExpCodeType,
		Size:             script.Size,
		BehaviorType:     script.BehaviorType,
		BehaviorCategory: script.BehaviorCategory,
		Description:      script.Description,
		AttackFeature:    script.AttackFeature,
		Checksum:         script.Checksum,
		UpdatedAt:        script.UpdatedAt,
		Enabled:          script.Enabled,
		Valid:            script.Valid,
		Error:            script.Error,
		NoticeTypes:      script.NoticeTypes,
	}
}

func grpcStatusFromError(err error) error {
	switch {
	case errors.Is(err, ErrScriptNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrScriptInvalid),
		strings.Contains(err.Error(), "scriptPath mismatch"),
		strings.Contains(err.Error(), "required"),
		strings.Contains(err.Error(), "missing"),
		strings.Contains(err.Error(), "invalid"):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func analyzeReqFromGRPC(req *pb.AnalyzeRequest) AnalyzeReq {
	return AnalyzeReq{
		TaskID:     req.TaskID,
		UUID:       req.Uuid,
		OnlyNotice: req.OnlyNotice,
		PcapID:     req.PcapID,
		PcapPath:   req.PcapPath,
		ScriptID:   req.ScriptID,
		ScriptPath: req.ScriptPath,
	}
}

func asyncAnalyzeReqFromGRPC(req *pb.AsyncAnalyzeRequest) AnalyzeReq {
	return AnalyzeReq{
		TaskID:     req.TaskID,
		UUID:       req.Uuid,
		OnlyNotice: req.OnlyNotice,
		PcapID:     req.PcapID,
		PcapPath:   req.PcapPath,
		ScriptID:   req.ScriptID,
		ScriptPath: req.ScriptPath,
	}
}

func asyncAnalyzeBatchReqFromGRPC(req *pb.AsyncAnalyzeBatchRequest) AnalyzeBatchReq {
	scripts := make([]ScriptTaskReq, 0, len(req.Scripts))
	for _, script := range req.Scripts {
		scripts = append(scripts, ScriptTaskReq{
			UUID:       script.Uuid,
			ScriptID:   script.ScriptID,
			ScriptPath: script.ScriptPath,
			RunMode:    script.RunMode,
			Weight:     int(script.Weight),
		})
	}
	return AnalyzeBatchReq{
		TaskID:     req.TaskID,
		OnlyNotice: req.OnlyNotice,
		PcapID:     req.PcapID,
		PcapPath:   req.PcapPath,
		Scripts:    scripts,
	}
}

func extractReqFromGRPC(req *pb.ExtractRequest) ExtractReq {
	return ExtractReq{
		TaskID:               req.TaskID,
		UUID:                 req.Uuid,
		PcapID:               req.PcapID,
		PcapPath:             req.PcapPath,
		ScriptPath:           req.ScriptPath,
		OutputDir:            req.OutputDir,
		ExtractedFileMinSize: int(req.ExtractedFileMinSize),
		ExtractedFileMaxSize: int(req.ExtractedFileMaxSize),
	}
}

func extractAsyncReqFromGRPC(req *pb.ExtractAsyncRequest) ExtractReq {
	return ExtractReq{
		TaskID:               req.TaskID,
		UUID:                 req.Uuid,
		PcapID:               req.PcapID,
		PcapPath:             req.PcapPath,
		ScriptPath:           req.ScriptPath,
		OutputDir:            req.OutputDir,
		ExtractedFileMinSize: int(req.ExtractedFileMinSize),
		ExtractedFileMaxSize: int(req.ExtractedFileMaxSize),
	}
}
