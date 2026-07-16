package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"zeek_runner/internal/upgradebehavior"
)

// behaviorEngineVersion 是采集侧行为识别引擎版本，随 Kafka 事件下发供消费侧校验。
const behaviorEngineVersion = "1.0.0"

// behaviorEngine 封装规则集加载、ruleset_sha256 计算与 BehaviorMatcher 创建。
// 规则加载失败必须拒绝就绪，不可静默使用空规则。
type behaviorEngine struct {
	matcher         *upgradebehavior.BehaviorMatcher
	ruleSet         *upgradebehavior.RuleSet
	rulesetSHA      string
	engineVer       string
	rulesPath       string
	archiver        *payloadArchiver
	archiveEnbl     bool
	mu              sync.RWMutex
	disabledVendors map[string]struct{}
}

// behaviorEngineConfig 是构造 behaviorEngine 所需的配置。
type behaviorEngineConfig struct {
	RulesPath        string // 行为识别规则 YAML 的绝对路径
	ArchiveDir       string // 归档目录
	ArchiveKeyHex    string // AES-256 密钥的十六进制字符串
	ArchiveEnabled   bool   // 是否启用归档
	ArchiveRetention int    // 归档保留天数
}

// newBehaviorEngine 加载规则集并构造引擎。
// 规则加载失败时返回错误，调用方必须据此拒绝就绪。
func newBehaviorEngine(cfg behaviorEngineConfig) (*behaviorEngine, error) {
	if cfg.RulesPath == "" {
		return nil, errors.New("behavior rules path is empty: refusing to start without rules")
	}
	data, err := os.ReadFile(cfg.RulesPath)
	if err != nil {
		return nil, fmt.Errorf("read behavior catalog %s: %w", cfg.RulesPath, err)
	}
	ruleSet, err := upgradebehavior.LoadRuleSetFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("load behavior ruleset: %w", err)
	}
	if len(ruleSet.Rules) == 0 {
		return nil, errors.New("behavior catalog is empty: refusing to start with empty ruleset")
	}

	// 计算 ruleset_sha256：基于规则集原始 YAML 字节内容。
	sum := sha256.Sum256(data)
	rulesetSHA := hex.EncodeToString(sum[:])

	matcher := upgradebehavior.NewRuntimeBehaviorMatcher(ruleSet)

	engine := &behaviorEngine{
		matcher:         matcher,
		ruleSet:         ruleSet,
		rulesetSHA:      rulesetSHA,
		engineVer:       behaviorEngineVersion,
		rulesPath:       cfg.RulesPath,
		archiveEnbl:     cfg.ArchiveEnabled,
		disabledVendors: make(map[string]struct{}),
	}

	// 初始化归档器（仅在启用时）
	if cfg.ArchiveEnabled && cfg.ArchiveDir != "" {
		retention := archiveRetention
		if cfg.ArchiveRetention > 0 {
			retention = time.Duration(cfg.ArchiveRetention) * 24 * time.Hour
		}
		archiver, err := newPayloadArchiver(cfg.ArchiveDir, cfg.ArchiveKeyHex, retention)
		if err != nil {
			slog.Warn("archive init failed, archiving disabled", "err", err)
		} else {
			engine.archiver = archiver
			if !archiver.encryptionAvailable() {
				slog.Warn("archive encryption unavailable: archives will be marked failed, no plaintext fallback")
			}
		}
	}

	slog.Info("behavior engine initialized",
		"rules", len(ruleSet.Rules),
		"ruleset_sha256", rulesetSHA,
		"engine_version", behaviorEngineVersion,
		"rules_path", cfg.RulesPath,
		"archive_enabled", engine.archiver != nil,
		"archive_encryption_available", engine.archiver != nil && engine.archiver.encryptionAvailable(),
	)
	return engine, nil
}

// ApplyDisabledVendors 原子更新运行时厂商策略。它不修改规则 YAML 或 ruleset SHA，
// 只移除被禁用厂商的规则；全局规则始终保留。
func (eng *behaviorEngine) ApplyDisabledVendors(vendorIDs []string) (int, []string, error) {
	if eng == nil || eng.ruleSet == nil || eng.matcher == nil {
		return 0, nil, errors.New("behavior engine is not initialized")
	}
	disabled := make(map[string]struct{}, len(vendorIDs))
	for _, vendorID := range vendorIDs {
		if vendorID != "" {
			disabled[vendorID] = struct{}{}
		}
	}
	filtered := make([]upgradebehavior.BehaviorRule, 0, len(eng.ruleSet.Rules))
	for _, rule := range eng.ruleSet.Rules {
		if rule.VendorID != "" {
			if _, blocked := disabled[rule.VendorID]; blocked {
				continue
			}
		}
		filtered = append(filtered, rule)
	}
	ruleSet, err := upgradebehavior.CompileRuntimeRuleSet(eng.ruleSet.Version, filtered, eng.ruleSet.VendorDomains)
	if err != nil {
		return 0, nil, fmt.Errorf("compile effective behavior rules: %w", err)
	}
	eng.matcher.UpdateRuleSet(ruleSet)
	eng.matcher.UpdateDisabledVendors(vendorIDs)
	eng.mu.Lock()
	eng.disabledVendors = disabled
	eng.mu.Unlock()
	result := make([]string, 0, len(disabled))
	for vendorID := range disabled {
		result = append(result, vendorID)
	}
	sort.Strings(result)
	return len(filtered), result, nil
}
