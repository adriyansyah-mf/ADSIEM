package main

import (
	"context"
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
	"github.com/siem-platform/agent/internal/enrollment"
	"github.com/siem-platform/agent/internal/fim"
	"github.com/siem-platform/agent/internal/heartbeat"
	"github.com/siem-platform/agent/internal/hygiene"
	"github.com/siem-platform/agent/internal/procexec"
	"github.com/siem-platform/agent/internal/task"
	"github.com/siem-platform/agent/internal/tailer"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "dev"

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to config file")
	install := flag.Bool("install", false, "install the agent as a Windows service (Windows only)")
	uninstall := flag.Bool("uninstall", false, "remove the Windows service (Windows only)")
	doConfigure := flag.Bool("configure", false, "write -server/-key/-name into the config file and exit (used by the MSI)")
	var opts configureOptions
	flag.StringVar(&opts.server, "server", "", "with -configure: SIEM server URL")
	flag.StringVar(&opts.key, "key", "", "with -configure: enrollment key (clears any previous enrollment)")
	flag.StringVar(&opts.name, "name", "", "with -configure: agent name (default: hostname)")
	flag.StringVar(&opts.auditing, "enable-auditing", "", "with -configure on Windows: 1 to turn on logon/process/account auditing and PowerShell script block logging")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if *doConfigure {
		if err := configure(*configPath, opts); err != nil {
			slog.Error("configure failed", "err", err)
			os.Exit(1)
		}
		slog.Info("configured", "config", *configPath)
		return
	}
	if *install || *uninstall {
		if err := manageService(*install, *configPath); err != nil {
			slog.Error("service command failed", "err", err)
			os.Exit(1)
		}
		return
	}
	// Started by the Windows Service Control Manager: it decides when to stop.
	if runAsService(func(stop <-chan struct{}) { run(*configPath, stop) }) {
		return
	}

	stop := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		close(stop)
	}()
	run(*configPath, stop)
}

// run starts every agent subsystem and blocks until stop is closed.
func run(configPath string, stop <-chan struct{}) {
	heartbeat.AgentVersion = Version
	enrollment.AgentVersion = Version
	slog.Info("siem-agent starting", "version", Version)

	cfg, err := config.Load(configPath)
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
		if err := enrollment.Enroll(cfg, configPath, enrollToken); err != nil {
			slog.Error("enrollment failed", "err", err)
			os.Exit(1)
		}
	}

	buf := buffer.New(cfg.Agent.BufferSize)
	c := client.New(cfg.Server.URL, cfg.Agent.Token)
	mgr := tailer.NewManager(buf)

	// seed initial sources from config
	initialSources := make([]heartbeat.LogSource, len(cfg.Logs))
	for i, l := range cfg.Logs {
		initialSources[i] = heartbeat.LogSource{Path: l.Path, LogType: l.Type, IsEnabled: true}
	}
	mgr.Update(initialSources)

	// fsnotify for bootstrap fields only (agent.name, agent.group, server.url)
	if err := config.Watch(configPath, func(newCfg *config.Config) {
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

	// Legacy task runner (isolate/block-IP and pre-flow collections, via heartbeat)
	taskRunner := task.NewRunner(cfg, c)

	// Live-response flows: long-polls the server and runs artifact plugins
	flowCtx, stopFlows := context.WithCancel(context.Background())
	defer stopFlows()
	go task.NewFlowRunner(c).Run(flowCtx)

	// Process-exec telemetry via eBPF (best-effort: needs CAP_BPF/CAP_SYS_ADMIN
	// and a BTF-enabled kernel; logs a warning and continues without it otherwise)
	if procMon, err := procexec.Start(buf); err != nil {
		slog.Warn("procexec monitor unavailable, continuing without it", "err", err)
	} else {
		defer procMon.Stop()
	}

	// heartbeat loop — drives log source + FIM path updates + task dispatch
	go heartbeat.Loop(cfg, buf, c,
		func(resp heartbeat.HeartbeatResponse) {
			mgr.Update(resp.LogSources)
			fimWatcher.UpdatePaths(resp.FimPaths)
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
	go senderLoop(buf, c, cfg)

	// periodic buffer diagnostics
	go func() {
		for {
			time.Sleep(10 * time.Second)
			length, pushed, popped := buf.Stats()
			slog.Info("buffer stats", "len", length, "pushed", pushed, "popped", popped)
		}
	}()

	<-stop
	slog.Info("shutting down")
	stopFlows()
	mgr.StopAll()
	flushBuffer(buf, c, cfg)
}

func senderLoop(buf *buffer.Buffer, c *client.Client, cfg *config.Config) {
	backoff := time.Second
	for {
		entry, ok := buf.Pop()
		if !ok {
			backoff = time.Second
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logType, location, rawMessage := tailer.Decode(entry)
		payload := map[string]interface{}{
			"agent_id":    cfg.Agent.ID,
			"agent_token": cfg.Agent.Token,
			"log_type":    logType,
			"raw_message": rawMessage,
			"location":    location,
			"received_at": time.Now().UTC().Format(time.RFC3339Nano),
			"hostname":    mustHostname(),
		}
		resp, err := c.Post("/api/ingest/log", payload)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			if resp != nil {
				resp.Body.Close()
			}
			buf.Push(entry) // re-queue
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
		backoff = time.Second
	}
}

func flushBuffer(buf *buffer.Buffer, c *client.Client, cfg *config.Config) {
	slog.Info("flushing buffer", "len", buf.Len())
	for {
		entry, ok := buf.Pop()
		if !ok {
			break
		}
		logType, location, rawMessage := tailer.Decode(entry)
		payload := map[string]interface{}{
			"agent_id":    cfg.Agent.ID,
			"agent_token": cfg.Agent.Token,
			"log_type":    logType,
			"raw_message": rawMessage,
			"location":    location,
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
