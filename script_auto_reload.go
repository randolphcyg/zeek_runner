package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

func (s *Service) StartScriptAutoReload(ctx context.Context) {
	cfg := s.getConfig()
	if !cfg.Zeek.AutoReloadScripts {
		slog.Info("script auto reload disabled")
		return
	}

	debounce, err := parsePositiveDuration(cfg.Zeek.ScriptReloadDebounce, "zeek scriptReloadDebounce")
	if err != nil {
		slog.Warn("invalid script reload debounce, using default", "value", cfg.Zeek.ScriptReloadDebounce, "err", err)
		debounce = 2 * time.Second
	}
	interval, err := parsePositiveDuration(cfg.Zeek.ScriptReloadInterval, "zeek scriptReloadInterval")
	if err != nil {
		slog.Warn("invalid script reload interval, using default", "value", cfg.Zeek.ScriptReloadInterval, "err", err)
		interval = 60 * time.Second
	}

	slog.Info("script auto reload started",
		"root", cfg.Zeek.ScriptRoot,
		"debounce", debounce.String(),
		"interval", interval.String(),
	)

	go s.runScriptAutoReload(ctx, cfg.Zeek.ScriptRoot, debounce, interval)
}

func (s *Service) runScriptAutoReload(ctx context.Context, root string, debounce time.Duration, interval time.Duration) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("script watcher unavailable; polling fallback remains active", "err", err)
		s.runScriptReloadPoller(ctx, interval)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(root); err != nil {
		slog.Warn("script watcher failed to watch root; polling fallback remains active", "root", root, "err", err)
	} else {
		slog.Info("script watcher attached", "root", root)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var debounceTimer *time.Timer
	var debounceC <-chan time.Time
	scheduleReload := func(reason string) {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(debounce)
			debounceC = debounceTimer.C
		} else {
			if !debounceTimer.Stop() {
				select {
				case <-debounceTimer.C:
				default:
				}
			}
			debounceTimer.Reset(debounce)
		}
		slog.Debug("script reload scheduled", "reason", reason)
	}

	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			slog.Info("script auto reload stopped", "root", root)
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if isScriptReloadEvent(event) {
				scheduleReload(event.Op.String())
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("script watcher error", "err", err)
		case <-debounceC:
			debounceC = nil
			s.reloadScriptsFromAutoReload("file_event", true)
		case <-ticker.C:
			s.reloadScriptsFromAutoReload("polling", false)
		}
	}
}

func (s *Service) runScriptReloadPoller(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("script reload poller stopped")
			return
		case <-ticker.C:
			s.reloadScriptsFromAutoReload("polling", false)
		}
	}
}

func (s *Service) reloadScriptsFromAutoReload(reason string, logUnchanged bool) {
	before := s.scriptRegistryFingerprint()
	resp, err := s.ReloadScripts()
	if err != nil {
		slog.Warn("script auto reload failed", "reason", reason, "err", err)
		return
	}
	after := s.scriptRegistryFingerprint()
	if before == after && !logUnchanged {
		return
	}
	slog.Info("script auto reload completed",
		"reason", reason,
		"changed", before != after,
		"total", resp.Total,
		"valid", resp.Valid,
		"invalid", resp.Invalid,
	)
}

func (s *Service) scriptRegistryFingerprint() string {
	registry := s.getScriptRegistry()
	if registry == nil {
		return ""
	}
	scripts := registry.List(ListScriptsRequest{})
	parts := make([]string, 0, len(scripts))
	for _, script := range scripts {
		parts = append(parts, strings.Join([]string{
			script.ScriptID,
			script.ScriptPath,
			script.Checksum,
			script.UpdatedAt,
			boolFingerprint(script.Enabled),
			boolFingerprint(script.Valid),
			script.Error,
		}, "\x00"))
	}
	return strings.Join(parts, "\x01")
}

func boolFingerprint(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func isScriptReloadEvent(event fsnotify.Event) bool {
	if filepath.Ext(event.Name) != ".zeek" {
		return false
	}
	return event.Has(fsnotify.Create) ||
		event.Has(fsnotify.Write) ||
		event.Has(fsnotify.Remove) ||
		event.Has(fsnotify.Rename)
}
