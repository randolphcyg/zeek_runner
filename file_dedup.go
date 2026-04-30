package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
)

type FileRecord struct {
	Hash      string    `json:"hash"`
	FilePath  string    `json:"filePath"`
	FileName  string    `json:"fileName"`
	FUID      string    `json:"fuid"`
	OriginalFileName string `json:"originalFileName"`
	FileSize  int64     `json:"fileSize"`
	MimeType  string    `json:"mimeType"`
	FirstSeen time.Time `json:"firstSeen"`
	RefCount  int       `json:"refCount"`
	SourceURL string    `json:"sourceUrl"`
	TaskID    string    `json:"taskID"`
}

type FileDedupManager struct {
	redis      *redis.Client
	prefix     string
	expiration time.Duration
}

func NewFileDedupManager(redisAddr, redisPassword string, redisDB int, poolCfg *RedisPoolConfig) *FileDedupManager {
	poolSize := 10
	minIdleConns := 0
	maxRetries := 3
	dialTimeout := 5 * time.Second
	readTimeout := 3 * time.Second
	writeTimeout := 3 * time.Second
	poolTimeout := 4 * time.Second
	var maxLifetime, maxIdleTime time.Duration

	if poolCfg != nil {
		if poolCfg.PoolSize > 0 {
			poolSize = poolCfg.PoolSize
		}
		if poolCfg.MinIdleConns > 0 {
			minIdleConns = poolCfg.MinIdleConns
		}
		if poolCfg.MaxRetries > 0 {
			maxRetries = poolCfg.MaxRetries
		}
		if poolCfg.DialTimeout > 0 {
			dialTimeout = poolCfg.DialTimeout
		}
		if poolCfg.ReadTimeout > 0 {
			readTimeout = poolCfg.ReadTimeout
		}
		if poolCfg.WriteTimeout > 0 {
			writeTimeout = poolCfg.WriteTimeout
		}
		if poolCfg.PoolTimeout > 0 {
			poolTimeout = poolCfg.PoolTimeout
		}
		maxLifetime = poolCfg.MaxLifetime
		maxIdleTime = poolCfg.MaxIdleTime
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:            redisAddr,
		Password:        redisPassword,
		DB:              redisDB,
		PoolSize:        poolSize,
		MinIdleConns:    minIdleConns,
		MaxRetries:      maxRetries,
		DialTimeout:     dialTimeout,
		ReadTimeout:     readTimeout,
		WriteTimeout:    writeTimeout,
		PoolTimeout:     poolTimeout,
		ConnMaxLifetime: maxLifetime,
		ConnMaxIdleTime: maxIdleTime,
	})

	return &FileDedupManager{
		redis:      rdb,
		prefix:     "zeek:file:",
		expiration: 24 * time.Hour, // 缩短为 1 天，只保证单个任务周期内去重
	}
}

func (fdm *FileDedupManager) hashKey(hash string) string {
	return fdm.prefix + "hash:" + hash
}

func (fdm *FileDedupManager) taskFileKey(taskID, hash string) string {
	return fdm.prefix + "task:" + taskID + ":hash:" + hash
}

func (fdm *FileDedupManager) pathKey(filePath string) string {
	return fdm.prefix + "path:" + filePath
}

func (fdm *FileDedupManager) CalculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CheckDuplicateInTask 检查任务内是否重复（而不是全局）
func (fdm *FileDedupManager) CheckDuplicateInTask(ctx context.Context, taskID, hash string) (*FileRecord, bool, error) {
	key := fdm.taskFileKey(taskID, hash)
	data, err := fdm.redis.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("redis error: %w", err)
	}

	var record FileRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal record: %w", err)
	}

	return &record, true, nil
}

func (fdm *FileDedupManager) RegisterFileInTask(ctx context.Context, record *FileRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	// 任务内去重 key
	taskFileKey := fdm.taskFileKey(record.TaskID, record.Hash)
	// 全局路径 key（用于清理）
	pathKey := fdm.pathKey(record.FilePath)

	pipe := fdm.redis.Pipeline()
	pipe.Set(ctx, taskFileKey, data, fdm.expiration)
	pipe.Set(ctx, pathKey, record.Hash, fdm.expiration)
	_, err = pipe.Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to register file: %w", err)
	}

	slog.Info("file registered in task", "hash", record.Hash[:16], "path", record.FilePath, "taskID", record.TaskID)
	return nil
}

func (fdm *FileDedupManager) ProcessExtractedFile(ctx context.Context, filePath, sourceURL, taskID string) (*FileRecord, bool, error) {
	hash, err := fdm.CalculateFileHash(filePath)
	if err != nil {
		return nil, false, err
	}

	// ✅ 只检查任务内是否重复
	existingRecord, isDuplicate, err := fdm.CheckDuplicateInTask(ctx, taskID, hash)
	if err != nil {
		return nil, false, err
	}

	if isDuplicate {
		slog.Info("duplicate file in task detected",
			"hash", hash[:16],
			"newPath", filePath,
			"existingPath", existingRecord.FilePath,
			"taskID", taskID,
		)

		// 任务内重复：增加引用计数
		if err := fdm.IncrementRefCount(ctx, taskID, hash); err != nil {
			slog.Warn("failed to increment ref count", "hash", hash[:16], "err", err)
		}
		existingRecord.RefCount++
		return existingRecord, true, nil
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, false, err
	}

	record := &FileRecord{
		Hash:             hash,
		FilePath:         filePath,
		FileName:         filepath.Base(filePath),
		FUID:             extractFUID(filepath.Base(filePath)),
		OriginalFileName: extractOriginalFileName(filepath.Base(filePath)),
		FileSize:         fileInfo.Size(),
		FirstSeen:        time.Now(),
		RefCount:         1,
		SourceURL:        sourceURL,
		TaskID:           taskID,
	}

	if err := fdm.RegisterFileInTask(ctx, record); err != nil {
		return nil, false, err
	}

	return record, false, nil
}

func (fdm *FileDedupManager) IncrementRefCount(ctx context.Context, taskID, hash string) error {
	key := fdm.taskFileKey(taskID, hash)
	data, err := fdm.redis.Get(ctx, key).Bytes()
	if err != nil {
		return fmt.Errorf("file not found in task: %s", hash)
	}

	var record FileRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}

	record.RefCount++
	recordJSON, _ := json.Marshal(record)
	return fdm.redis.Set(ctx, key, recordJSON, fdm.expiration).Err()
}

func (fdm *FileDedupManager) GetFileStats(ctx context.Context, hash string) (*FileRecord, error) {
	// 这个方法不再使用，因为现在是任务内去重
	return nil, fmt.Errorf("deprecated: use task-specific methods")
}

func (fdm *FileDedupManager) HealthCheck(ctx context.Context) error {
	return fdm.redis.Ping(ctx).Err()
}

func (fdm *FileDedupManager) Close() error {
	return fdm.redis.Close()
}
