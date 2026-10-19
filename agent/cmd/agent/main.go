package main

import (
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/detect"
	"github.com/siem-platform/agent/internal/enrollment"
	"github.com/siem-platform/agent/internal/fim"
	"github.com/siem-platform/agent/internal/firewall"
	"github.com/siem-platform/agent/internal/heartbeat"
	"github.com/siem-platform/agent/internal/hygiene"
	"github.com/siem-platform/agent/internal/netwatch"
	"github.com/siem-platform/agent/internal/procexec"
	"github.com/siem-platform/agent/internal/tailer"
	"github.com/siem-platform/agent/internal/task"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	enrollToken := cfg.Agent.EnrollmentToken
	if enrollToken == "" {
		enrollToken = os.Getenv("AGENT_ENROLLMENT_TOKEN")
	}
	if enrollToken == "" {
		enrollToken = "bootstrap-token"
	}

	if cfg.Agent.Token == "" {
		if err := enrollment.Enroll(cfg, *configPath, enrollToken); err != nil {
			slog.Error("enrollment failed", "err", err)
			os.Exit(1)
		}
	}

	buf := buffer.New(cfg.Agent.BufferSize)
	c := client.New(cfg.Server.URL, cfg.Agent.Token)
	mgr := tailer.NewManager(buf)

	spill, err := buffer.OpenSpill(cfg.Buffer.SpillPath)
	if err != nil {
		slog.Warn("disk spill unavailable; undelivered events will be lost on restart", "err", err)
		spill = nil
	} else {
		defer spill.Close()
	}

	// seed initial sources from config
	initialSources := make([]heartbeat.LogSource, len(cfg.Logs))
	for i, l := range cfg.Logs {
		initialSources[i] = heartbeat.LogSource{Path: l.Path, LogType: l.Type, IsEnabled: true}
	}
	mgr.Update(initialSources)

	// fsnotify for bootstrap fields only (agent.name, agent.group, server.url)
	if err := config.Watch(*configPath, func(newCfg *config.Config) {
		cfg.Agent.Name = newCfg.Agent.Name
		cfg.Agent.Group = newCfg.Agent.Group
		cfg.Server.URL = newCfg.Server.URL
		c.BaseURL = newCfg.Server.URL
	}); err != nil {
		slog.Warn("config watcher failed to start", "err", err)
	}

	// IT hygiene collection loop
	hygiene.Start(cfg, c)

	// File Integrity Monitoring
	fimWatcher := fim.Start(cfg, c)

	// Task runner for live response / Velociraptor-style artifacts
	fwEngine := firewall.New(firewall.Options{
		Enabled:      cfg.Firewall.Enabled,
		Backend:      cfg.Firewall.Backend,
		DryRun:       cfg.Firewall.DryRun,
		ProtectedIPs: cfg.Firewall.ProtectedIPs,
		StatePath:    cfg.Firewall.StatePath,
		ServerURL:    cfg.Server.URL,
		Buffer:       buf,
	})
	taskRunner := task.NewRunner(cfg, c, fwEngine)

	var detector *detect.Engine
	if cfg.Detect.Enabled {
		rules, err := detect.ApplyEnabled(detect.DefaultRules(), cfg.Detect.Rules)
		if err != nil {
			slog.Warn("local detection disabled: bad rule configuration", "err", err)
		} else {
			detector = detect.New(detect.Options{
				Rules:           rules,
				Buffer:          buf,
				Blocker:         detect.NewFirewallBlocker(fwEngine),
				MaxBlocked:      cfg.Detect.MaxBlocked,
				MaxBlocksPerMin: cfg.Detect.MaxBlocksPerMin,
			})
			slog.Info("local detection enabled", "rules", detector.EnabledRules())
		}
	}

	// Process-exec telemetry via eBPF (best-effort: needs CAP_BPF/CAP_SYS_ADMIN
	// and a BTF-enabled kernel; logs a warning and continues without it otherwise)
	if procMon, err := procexec.Start(buf); err != nil {
		slog.Warn("procexec monitor unavailable, continuing without it", "err", err)
	} else {
		defer procMon.Stop()
	}

	// Network syscall telemetry (connect/accept/bind/DNS) with an `ss` snapshot
	// fallback when eBPF is unavailable.
	if cfg.Netwatch.Enabled {
		if netMon, err := netwatch.Start(buf); err != nil {
			slog.Warn("netwatch eBPF unavailable, continuing", "err", err)
			if cfg.Netwatch.SnapshotFallback {
				snap := netwatch.StartSnapshotter(buf)
				defer snap.Stop()
				slog.Info("netwatch running in snapshot mode", "interval", "10s")
			}
		} else {
			defer netMon.Stop()
		}
	}

	// heartbeat loop — drives log source + FIM path updates + task dispatch
	go heartbeat.Loop(cfg, buf, c,
		func(resp heartbeat.HeartbeatResponse) {
			mgr.Update(resp.LogSources)
			fimWatcher.UpdatePaths(resp.FimPaths)
			fwEngine.RefreshGuard(cfg.Server.URL)

			if len(resp.Firewall) > 0 || fwEngine.BlockedEntries() > 0 {
				rules := make([]firewall.ServerRule, 0, len(resp.Firewall))
				for _, r := range resp.Firewall {
					rules = append(rules, firewall.ServerRule{
						ID:         r.ID,
						Action:     r.Action,
						CIDR:       r.CIDR,
						Proto:      r.Proto,
						Port:       r.Port,
						Direction:  r.Direction,
						TTLSeconds: r.TTLSeconds,
						Reason:     r.Reason,
					})
				}
				added, removed, rejected := fwEngine.Sync(rules)
				if len(rejected) > 0 {
					slog.Warn("firewall rules rejected by guard", "rejected", rejected, "added", added, "removed", removed)
				}
			}
		},
		func(tasks []heartbeat.AgentTask) {
			for _, t := range tasks {
				taskRunner.Dispatch(task.TaskDef{
					ID:       t.ID,
					TaskType: t.TaskType,
					Params:   t.Params,
				})
			}
		},
	)

	// sender loop
	go senderLoop(buf, c, cfg, spill, detector)

	// periodic buffer diagnostics
	go func() {
		for {
			time.Sleep(10 * time.Second)
			length, pushed, popped := buf.Stats()
			slog.Info("buffer stats", "len", length, "pushed", pushed, "popped", popped)
		}
	}()

	// signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	slog.Info("shutting down")
	mgr.StopAll()
	flushBuffer(buf, c, cfg)
}

func senderLoop(buf *buffer.Buffer, c *client.Client, cfg *config.Config, spill *buffer.Spill, detector *detect.Engine) {
	backoff := time.Second
	wasOffline := false
	replaySpill(buf, spill)

	for {
		entry, ok := buf.Pop()
		if !ok {
			backoff = time.Second
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logType, rawMessage := tailer.Decode(entry)

		// Local detection observes every event exactly once, before delivery:
		// it must keep working while the server is unreachable.
		if detector != nil {
			detector.Emit(detector.Observe(logType, rawMessage))
		}

		payload := map[string]interface{}{
			"agent_id":    cfg.Agent.ID,
			"agent_token": cfg.Agent.Token,
			"log_type":    logType,
			"raw_message": rawMessage,
			"received_at": time.Now().UTC().Format(time.RFC3339Nano),
			"hostname":    mustHostname(),
		}
		resp, err := c.Post("/api/ingest/log", payload)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			if resp != nil {
				resp.Body.Close()
			}
			buf.Push(entry) // re-queue
			spill.Append(entry)
			wasOffline = true
			slog.Warn("send failed, backing off", "backoff", backoff, "err", err)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			slog.Error("log rejected by server, dropping entry", "status", resp.StatusCode, "body", string(body), "log_type", logType)
		}
		resp.Body.Close()

		// A successful delivery after a failure means connectivity is back:
		// drain the disk spill so offline events are not stranded until the
		// next restart.
		if wasOffline {
			wasOffline = false
			replaySpill(buf, spill)
		}
		backoff = time.Second
	}
}

func replaySpill(buf *buffer.Buffer, spill *buffer.Spill) {
	if spill == nil {
		return
	}
	undelivered := spill.Drain()
	for _, entry := range undelivered {
		buf.Push(entry)
	}
	if n := len(undelivered); n > 0 {
		slog.Info("replayed undelivered entries", "count", n)
	}
}

func flushBuffer(buf *buffer.Buffer, c *client.Client, cfg *config.Config) {
	slog.Info("flushing buffer", "len", buf.Len())
	for {
		entry, ok := buf.Pop()
		if !ok {
			break
		}
		logType, rawMessage := tailer.Decode(entry)
		payload := map[string]interface{}{
			"agent_id":    cfg.Agent.ID,
			"agent_token": cfg.Agent.Token,
			"log_type":    logType,
			"raw_message": rawMessage,
			"received_at": time.Now().UTC().Format(time.RFC3339Nano),
			"hostname":    mustHostname(),
		}
		c.Post("/api/ingest/log", payload) //nolint:errcheck
	}
}

func mustHostname() string {
	h, _ := os.Hostname()
	return h
}
