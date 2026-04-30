package main

import (
	"strconv"
	"time"
)

type offlineTaskKind string

const (
	offlineTaskScan     offlineTaskKind = "MALICIOUS_SCAN"
	offlineTaskExtract  offlineTaskKind = "FILE_EXTRACT"
	extractTaskScriptID                 = "EXTRACT_TASK"
)

type offlineTaskSpec struct {
	kind                 offlineTaskKind
	taskID               string
	uuid                 string
	pcapID               string
	pcapPath             string
	scriptID             string
	scriptPath           string
	onlyNotice           bool
	outputDir            string
	extractedFileMinSize int
	extractedFileMaxSize int
}

func newOfflineScanTask(req AnalyzeReq) offlineTaskSpec {
	return offlineTaskSpec{
		kind:                 offlineTaskScan,
		taskID:               req.TaskID,
		uuid:                 req.UUID,
		pcapID:               req.PcapID,
		pcapPath:             req.PcapPath,
		scriptID:             req.ScriptID,
		scriptPath:           req.ScriptPath,
		onlyNotice:           req.OnlyNotice,
		extractedFileMinSize: req.ExtractedFileMinSize,
	}
}

func newOfflineExtractTask(req ExtractReq) offlineTaskSpec {
	return offlineTaskSpec{
		kind:                 offlineTaskExtract,
		taskID:               req.TaskID,
		uuid:                 req.UUID,
		pcapID:               req.PcapID,
		pcapPath:             req.PcapPath,
		scriptID:             extractTaskScriptID,
		scriptPath:           resolveExtractScriptPath(req.ScriptPath),
		outputDir:            req.OutputDir,
		extractedFileMinSize: req.ExtractedFileMinSize,
		extractedFileMaxSize: req.ExtractedFileMaxSize,
	}
}

func newOfflineTaskFromStored(task *Task) offlineTaskSpec {
	spec := offlineTaskSpec{
		kind:                 offlineTaskScan,
		taskID:               task.TaskID,
		uuid:                 task.UUID,
		pcapID:               task.PcapID,
		pcapPath:             task.PcapPath,
		scriptID:             task.ScriptID,
		scriptPath:           task.ScriptPath,
		onlyNotice:           task.OnlyNotice,
		outputDir:            task.OutputDir,
		extractedFileMinSize: task.ExtractedFileMinSize,
		extractedFileMaxSize: task.ExtractedFileMaxSize,
	}

	if task.OutputDir != "" {
		spec.kind = offlineTaskExtract
		spec.scriptID = extractTaskScriptID
		spec.scriptPath = resolveExtractScriptPath(task.ScriptPath)
		spec.onlyNotice = false
	}

	return spec
}

func (t offlineTaskSpec) taskType() string {
	return string(t.kind)
}

func (t offlineTaskSpec) zeekEnv(kafkaBrokers string) map[string]string {
	env := map[string]string{
		"TASK_ID":             t.taskID,
		"UUID":                t.uuid,
		"PCAP_ID":             t.pcapID,
		"PCAP_PATH":           t.pcapPath,
		"SCRIPT_ID":           t.scriptID,
		"SCRIPT_PATH":         t.scriptPath,
		"EXTRACTED_FILE_PATH": t.outputDir,
		"ANALYSIS_MODE":       "offline",
		"KAFKA_BROKERS":       kafkaBrokers,
	}

	if t.kind == offlineTaskExtract {
		env["MIN_FILE_SIZE_KB"] = strconv.Itoa(t.extractedFileMinSize)
		env["MAX_FILE_SIZE_MB"] = strconv.Itoa(t.extractedFileMaxSize)
		env["ENABLE_OFFLINE_INTEL_REPLAY"] = "false"
		return env
	}

	env["ONLY_NOTICE"] = strconv.FormatBool(t.onlyNotice)
	env["EXTRACTED_FILE_MIN_SIZE"] = strconv.Itoa(t.extractedFileMinSize)
	env["ENABLE_OFFLINE_INTEL_REPLAY"] = "true"
	return env
}

func (t offlineTaskSpec) zeekRunOptions(s *Service) zeekRunOptions {
	opts := zeekRunOptions{
		taskID:     t.taskID,
		uuid:       t.uuid,
		taskType:   t.taskType(),
		pcapID:     t.pcapID,
		pcapPath:   t.pcapPath,
		scriptID:   t.scriptID,
		scriptPath: t.scriptPath,
		outputDir:  t.outputDir,
		env:        t.zeekEnv(s.getConfig().Kafka.Brokers),
	}

	return opts
}

func (t offlineTaskSpec) newTaskRecord() *Task {
	scriptID := t.scriptID
	onlyNotice := t.onlyNotice

	if t.kind == offlineTaskExtract {
		scriptID = extractTaskScriptID
		onlyNotice = false
	}

	return &Task{
		TaskID:               t.taskID,
		UUID:                 t.uuid,
		PcapID:               t.pcapID,
		PcapPath:             t.pcapPath,
		ScriptID:             scriptID,
		ScriptPath:           t.scriptPath,
		OnlyNotice:           onlyNotice,
		OutputDir:            t.outputDir,
		ExtractedFileMinSize: t.extractedFileMinSize,
		ExtractedFileMaxSize: t.extractedFileMaxSize,
		Status:               TaskStatusPending,
		CreateTime:           time.Now(),
		MaxRetries:           3,
	}
}
