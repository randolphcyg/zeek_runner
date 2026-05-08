package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const scriptExpCodeType = "zeek"

var (
	scriptIDPattern = regexp.MustCompile(`(?m)^\s*const\s+SCRIPT_ID\s*=\s*"([^"]+)"\s*;?`)
	metaPatterns    = map[string]*regexp.Regexp{
		"behaviorType":     regexp.MustCompile(`(?m)^\s*#\s*行为类型：\s*(.+?)\s*$`),
		"behaviorCategory": regexp.MustCompile(`(?m)^\s*#\s*行为分类：\s*(.+?)\s*$`),
		"description":      regexp.MustCompile(`(?m)^\s*#\s*行为描述：\s*(.+?)\s*$`),
		"attackFeature":    regexp.MustCompile(`(?m)^\s*#\s*攻击特征：\s*(.+?)\s*$`),
	}
)

var (
	ErrScriptNotFound = errors.New("script not found")
	ErrScriptInvalid  = errors.New("script invalid")
)

type ListScriptsRequest struct {
	Name        string `json:"name"`
	EnabledOnly bool   `json:"enabledOnly"`
}

type ScriptInfo struct {
	ScriptID         string `json:"scriptID"`
	ScriptName       string `json:"scriptName"`
	ScriptPath       string `json:"scriptPath"`
	ExpCodeType      string `json:"expCodeType"`
	Size             string `json:"size"`
	BehaviorType     string `json:"behaviorType"`
	BehaviorCategory string `json:"behaviorCategory"`
	Description      string `json:"description"`
	AttackFeature    string `json:"attackFeature"`
	Checksum         string `json:"checksum"`
	UpdatedAt        string `json:"updatedAt"`
	Enabled          bool   `json:"enabled"`
	Valid            bool   `json:"valid"`
	Error            string `json:"error"`
}

type ReloadScriptsResponse struct {
	Total   int          `json:"total"`
	Valid   int          `json:"valid"`
	Invalid int          `json:"invalid"`
	Scripts []ScriptInfo `json:"scripts"`
}

type scriptRegistry struct {
	root    string
	mu      sync.RWMutex
	scripts []ScriptInfo
	byID    map[string]ScriptInfo
}

func newScriptRegistry(root string) (*scriptRegistry, error) {
	registry := &scriptRegistry{root: root}
	_, err := registry.Reload()
	return registry, err
}

func (r *scriptRegistry) Reload() (ReloadScriptsResponse, error) {
	scripts, byID, err := scanScriptRoot(r.root)
	if err != nil {
		return ReloadScriptsResponse{}, err
	}

	r.mu.Lock()
	r.scripts = scripts
	r.byID = byID
	r.mu.Unlock()

	return reloadResponseFromScripts(scripts), nil
}

func (r *scriptRegistry) List(req ListScriptsRequest) []ScriptInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	name := strings.ToLower(strings.TrimSpace(req.Name))
	scripts := make([]ScriptInfo, 0, len(r.scripts))
	for _, script := range r.scripts {
		if req.EnabledOnly && (!script.Enabled || !script.Valid) {
			continue
		}
		if name != "" {
			if !strings.Contains(strings.ToLower(script.ScriptID), name) &&
				!strings.Contains(strings.ToLower(script.ScriptName), name) {
				continue
			}
		}
		scripts = append(scripts, script)
	}
	return scripts
}

func (r *scriptRegistry) Get(scriptID string) (ScriptInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	script, ok := r.byID[strings.TrimSpace(scriptID)]
	if !ok {
		return ScriptInfo{}, fmt.Errorf("%w: %s", ErrScriptNotFound, scriptID)
	}
	return script, nil
}

func (r *scriptRegistry) Resolve(scriptID, scriptPath string) (ScriptInfo, error) {
	script, err := r.Get(scriptID)
	if err != nil {
		return ScriptInfo{}, err
	}
	if !script.Valid || !script.Enabled {
		if script.Error != "" {
			return ScriptInfo{}, fmt.Errorf("%w: %s", ErrScriptInvalid, script.Error)
		}
		return ScriptInfo{}, fmt.Errorf("%w: %s", ErrScriptInvalid, scriptID)
	}
	if strings.TrimSpace(scriptPath) != "" {
		if !sameCleanPath(script.ScriptPath, scriptPath) {
			return ScriptInfo{}, fmt.Errorf("scriptPath mismatch for scriptID %s: managed path is %s", scriptID, script.ScriptPath)
		}
	}
	return script, nil
}

func scanScriptRoot(root string) ([]ScriptInfo, map[string]ScriptInfo, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, fmt.Errorf("scan script root %s: %w", root, err)
	}

	scripts := make([]ScriptInfo, 0, len(entries))
	positionsByID := map[string][]int{}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".zeek" {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := parseScriptInfo(path)
		if err != nil {
			info = ScriptInfo{
				ScriptName:  strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())),
				ScriptPath:  filepath.ToSlash(filepath.Clean(path)),
				ExpCodeType: scriptExpCodeType,
				Enabled:     false,
				Valid:       false,
				Error:       err.Error(),
			}
		}
		scripts = append(scripts, info)
		if info.ScriptID != "" {
			positionsByID[info.ScriptID] = append(positionsByID[info.ScriptID], len(scripts)-1)
		}
	}

	for scriptID, positions := range positionsByID {
		if len(positions) <= 1 {
			continue
		}
		for _, idx := range positions {
			scripts[idx].Valid = false
			scripts[idx].Enabled = false
			scripts[idx].Error = fmt.Sprintf("duplicate SCRIPT_ID %q", scriptID)
		}
	}

	sort.Slice(scripts, func(i, j int) bool {
		if scripts[i].ScriptID == scripts[j].ScriptID {
			return scripts[i].ScriptPath < scripts[j].ScriptPath
		}
		return scripts[i].ScriptID < scripts[j].ScriptID
	})

	byID := make(map[string]ScriptInfo)
	for _, script := range scripts {
		if script.ScriptID != "" {
			byID[script.ScriptID] = script
		}
	}

	return scripts, byID, nil
}

func parseScriptInfo(path string) (ScriptInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ScriptInfo{}, err
	}
	stat, err := os.Stat(path)
	if err != nil {
		return ScriptInfo{}, err
	}

	content := string(data)
	hash := sha256.Sum256(data)
	script := ScriptInfo{
		ScriptName:  strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		ScriptPath:  filepath.ToSlash(filepath.Clean(path)),
		ExpCodeType: scriptExpCodeType,
		Size:        humanSize(stat.Size()),
		Checksum:    hex.EncodeToString(hash[:]),
		UpdatedAt:   stat.ModTime().Format(time.RFC3339),
		Enabled:     true,
		Valid:       true,
	}

	if match := scriptIDPattern.FindStringSubmatch(content); len(match) == 2 {
		script.ScriptID = strings.TrimSpace(match[1])
	} else {
		script.Valid = false
		script.Enabled = false
		script.Error = "missing SCRIPT_ID"
	}

	script.BehaviorType = extractScriptMetadata(content, "behaviorType")
	script.BehaviorCategory = extractScriptMetadata(content, "behaviorCategory")
	script.Description = extractScriptMetadata(content, "description")
	script.AttackFeature = extractScriptMetadata(content, "attackFeature")

	return script, nil
}

func extractScriptMetadata(content, key string) string {
	pattern := metaPatterns[key]
	if pattern == nil {
		return ""
	}
	match := pattern.FindStringSubmatch(content)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func reloadResponseFromScripts(scripts []ScriptInfo) ReloadScriptsResponse {
	resp := ReloadScriptsResponse{
		Total:   len(scripts),
		Scripts: append([]ScriptInfo(nil), scripts...),
	}
	for _, script := range scripts {
		if script.Valid {
			resp.Valid++
		} else {
			resp.Invalid++
		}
	}
	return resp
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func sameCleanPath(a, b string) bool {
	cleanA := filepath.ToSlash(filepath.Clean(a))
	cleanB := filepath.ToSlash(filepath.Clean(b))
	return cleanA == cleanB
}
