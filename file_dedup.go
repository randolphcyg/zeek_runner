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

func NewFileDedupManager(redisAddr, redisPassword string, redisDB int) *FileDedupManager {
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
		PoolSize: 10,
	})

	return &FileDedupManager{
		redis:      rdb,
		prefix:     "zeek:file:",
		expiration: 7 * 24 * time.Hour,
	}
}

func (fdm *FileDedupManager) hashKey(hash string) string {
	return fdm.prefix + "hash:" + hash
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

func (fdm *FileDedupManager) CheckDuplicate(ctx context.Context, hash string) (*FileRecord, bool, error) {
	key := fdm.hashKey(hash)
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

func (fdm *FileDedupManager) RegisterFile(ctx context.Context, record *FileRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	hashKey := fdm.hashKey(record.Hash)
	pathKey := fdm.pathKey(record.FilePath)

	pipe := fdm.redis.Pipeline()
	pipe.Set(ctx, hashKey, data, fdm.expiration)
	pipe.Set(ctx, pathKey, record.Hash, fdm.expiration)
	_, err = pipe.Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to register file: %w", err)
	}

	slog.Info("file registered", "hash", record.Hash[:16], "path", record.FilePath)
	return nil
}

func (fdm *FileDedupManager) IncrementRefCount(ctx context.Context, hash string) error {
	key := fdm.hashKey(hash)
	data, err := fdm.redis.Get(ctx, key).Bytes()
	if err != nil {
		return fmt.Errorf("file not found: %s", hash)
	}

	var record FileRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}

	record.RefCount++
	recordJSON, _ := json.Marshal(record)
	return fdm.redis.Set(ctx, key, recordJSON, fdm.expiration).Err()
}

func (fdm *FileDedupManager) ProcessExtractedFile(ctx context.Context, filePath, sourceURL, taskID string) (*FileRecord, bool, error) {
	hash, err := fdm.CalculateFileHash(filePath)
	if err != nil {
		return nil, false, err
	}

	existingRecord, isDuplicate, err := fdm.CheckDuplicate(ctx, hash)
	if err != nil {
		return nil, false, err
	}

	if isDuplicate {
		slog.Info("duplicate file detected",
			"hash", hash[:16],
			"newPath", filePath,
			"existingPath", existingRecord.FilePath,
			"refCount", existingRecord.RefCount+1,
		)

		if err := os.Remove(filePath); err != nil {
			slog.Warn("failed to remove duplicate file", "path", filePath, "err", err)
		} else {
			slog.Info("duplicate file removed", "path", filePath)
		}

		if err := fdm.IncrementRefCount(ctx, hash); err != nil {
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
		Hash:      hash,
		FilePath:  filePath,
		FileName:  filepath.Base(filePath),
		FileSize:  fileInfo.Size(),
		FirstSeen: time.Now(),
		RefCount:  1,
		SourceURL: sourceURL,
		TaskID:    taskID,
	}

	if err := fdm.RegisterFile(ctx, record); err != nil {
		return nil, false, err
	}

	return record, false, nil
}

func (fdm *FileDedupManager) GetFileStats(ctx context.Context, hash string) (*FileRecord, error) {
	key := fdm.hashKey(hash)
	data, err := fdm.redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("file not found: %s", hash)
	}

	var record FileRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

func (fdm *FileDedupManager) HealthCheck(ctx context.Context) error {
	return fdm.redis.Ping(ctx).Err()
}

func (fdm *FileDedupManager) Close() error {
	return fdm.redis.Close()
}
