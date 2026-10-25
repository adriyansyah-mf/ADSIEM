package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
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
	"github.com/siem-platform/agent/internal/winsensor"
	"github.com/siem-platform/agent/internal/yarascan"
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
	verifyUninstall := flag.Bool("verify-uninstall", false,
		"exit 0 only if -token (or $SIEM_UNINSTALL_TOKEN) is this agent's uninstall token; used by the MSI and .deb/.rpm removal")
	uninstallToken := flag.String("token", "", "with -verify-uninstall: the uninstall token")
	var ev evidenceCommand
	flag.BoolVar(&ev.list, "evidence-list", false, "list held and quarantined durable evidence (agent stopped, as root/Administrator)")
	flag.StringVar(&ev.release, "evidence-release", "", "event ID: deliver held or quarantined evidence again (needs -reason)")
	flag.StringVar(&ev.discard, "evidence-discard", "", "event ID: drop held or quarantined evidence (needs -reason)")
	flag.BoolVar(&ev.salvage, "evidence-salvage", false, "replace a journal that no longer opens (corrupt) with its readable undelivered evidence and cursors; keeps the old one (needs -reason)")
	flag.StringVar(&ev.reason, "reason", "", "with -evidence-release/-evidence-discard: why, kept in the journal audit")
	flag.BoolVar(&ev.yes, "yes", false, "with -evidence-release: release held evidence despite the duplicate risk")
	flag.Parse()

	if ev.requested() {
		cfg, err := config.Load(*configPath)
		if err == nil {
			err = runEvidenceCommand(cfg, ev, os.Stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "siem-agent:", err)
			os.Exit(2)
		}
		return
	}

	if *verifyUninstall {
		token := *uninstallToken
		if token == "" {
			token = os.Getenv("SIEM_UNINSTALL_TOKEN")
		}
		if err := heartbeat.VerifyUninstallToken(*configPath, token); err != nil {
			fmt.Fprintln(os.Stderr, "siem-agent:", err)
			os.Exit(3)
		}
		return
	}

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
		setStopReason(signalStopReason())
		close(stop)
	}()
	run(*configPath, stop)
}

// stopReason says why run's stop channel was closed: "service_stop" (someone
// stopped the agent — alerted on) or "system_shutdown" (the host is going down).
var stopReason atomic.Value

func setStopReason(reason string) { stopReason.Store(reason) }

func getStopReason() string {
	if r, ok := stopReason.Load().(string); ok {
		return r
	}
	return "service_stop"
}

// run starts every agent subsystem and blocks until stop is closed.
func run(configPath string, stop <-chan struct{}) {
	heartbeat.AgentVersion = Version
	heartbeat.ConfigPath = configPath
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

	// Windows: only SYSTEM may stop / reconfigure / delete the service (no-op elsewhere)
	if err := protectService(cfg.AntiTamper.UnlockService); err != nil {
		slog.Warn("could not set the service's tamper protection", "err", err)
	}

	c := client.New(cfg.Server.URL, cfg.Agent.Token)
	// evidence.enabled: durable journal + receipt-aware sender. Otherwise the
	// legacy memory queue, sender and disk spill. The two never mix.
	var durable *durableRuntime
	var buf *buffer.Buffer
	var spill *buffer.Spill
	if cfg.Evidence.Enabled {
		durable = openDurable(cfg, mustHostname())
		buf = durable.buf
		heartbeat.EvidenceHealth = durable.report                                // before the heartbeat loop starts
		durable.importLegacy(cfg.Buffer.SpillPath, cfg.Agent.ID, mustHostname()) // before any producer starts
	} else {
		buf = buffer.New(cfg.Agent.BufferSize)
		if spill, err = buffer.OpenSpill(cfg.Buffer.SpillPath); err != nil {
			slog.Warn("disk spill unavailable; undelivered events will be lost on restart", "err", err)
			spill = nil
		} else {
			defer spill.Close()
		}
	}
	mgr := tailer.NewManager(buf)
	if durable != nil && durable.journal != nil {
		mgr = tailer.NewDurableManager(durable.journal, durable.publisher) // files resume from durable cursors
	}

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
	if durable != nil {
		durable.setDetector(detector) // observes admissions instead of sends
	}

	// Live-response flows: long-polls the server and runs artifact plugins
	flowCtx, stopFlows := context.WithCancel(context.Background())
	defer stopFlows()
	flows := task.NewFlowRunner(c)
	if cfg.LiveResponse.DisableCommands {
		flows.Plugins = task.WithoutCommands(flows.Plugins)
		slog.Info("live response: operator-approved commands disabled by config")
	}
	go flows.Run(flowCtx)

	// Process-exec telemetry via eBPF (best-effort: needs CAP_BPF/CAP_SYS_ADMIN
	// and a BTF-enabled kernel; logs a warning and continues without it otherwise)
	// Producers are stopped explicitly at shutdown, before the durable journal closes.
	var stopProducers []func()
	if procMon, err := procexec.Start(buf); err != nil {
		slog.Warn("procexec monitor unavailable, continuing without it", "err", err)
	} else {
		stopProducers = append(stopProducers, procMon.Stop)
	}

	// Network syscall telemetry (connect/accept/bind/DNS) with an `ss` snapshot
	// fallback when eBPF is unavailable.
	if cfg.Netwatch.Enabled {
		if netMon, err := netwatch.Start(buf); err != nil {
			slog.Warn("netwatch eBPF unavailable, continuing", "err", err)
			if cfg.Netwatch.SnapshotFallback {
				snap := netwatch.StartSnapshotter(buf, cfg.Server.URL)
				stopProducers = append(stopProducers, snap.Stop)
				slog.Info("netwatch running in snapshot mode (new connections only)", "interval", "10s")
			}
		} else {
			stopProducers = append(stopProducers, netMon.Stop)
		}
	}

	// Windows process / network / DNS telemetry from ETW, without Sysmon
	// (etw.mode: auto runs it unless Sysmon is installed).
	if runtime.GOOS == "windows" && cfg.ETW.Mode != "off" {
		if cfg.ETW.Mode == "auto" && winsensor.SysmonInstalled() {
			slog.Info("ETW sensor off: Sysmon is installed (set etw.mode: on to run both)")
		} else if sensor, err := winsensor.Start(buf); err != nil {
			slog.Warn("ETW sensor unavailable, continuing without it", "err", err)
		} else {
			stopProducers = append(stopProducers, sensor.Stop)
			slog.Info("ETW sensor running", "telemetry", "process, network, dns")
		}
	}

	// On-access YARA scanning of risky directories with the server's rules
	yaraScanner := yarascan.New(yarascan.Options{
		Roots:       cfg.Yara.WatchPaths,
		MaxFileSize: cfg.Yara.MaxFileSizeMB << 20,
		Push:        func(logType, line string) { buf.Push(tailer.Encode(logType, line)) },
	})
	go yaraScanner.SyncLoop(flowCtx, c)
	if !cfg.Yara.Disabled {
		go func() {
			if err := yaraScanner.Run(flowCtx); err != nil {
				slog.Warn("yara on-access scanning unavailable", "err", err)
			}
		}()
	}

	// heartbeat loop — drives log source + FIM path updates + task dispatch
	go heartbeat.Loop(cfg, buf, c,
		func(resp heartbeat.HeartbeatResponse) {
			mgr.Update(resp.LogSources)
			fimWatcher.UpdatePaths(resp.FimPaths)
			yaraScanner.Want(resp.YaraRulesHash)
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

	if durable != nil {
		durable.startSender(c, heartbeat.SupportsEvidenceV2, heartbeat.EvidenceBatchMax)
	} else {
		go senderLoop(buf, c, cfg, spill, detector)
	}

	// periodic buffer diagnostics
	go func() {
		for {
			time.Sleep(10 * time.Second)
			length, pushed, popped := buf.Stats()
			slog.Info("buffer stats", "len", length, "pushed", pushed, "popped", popped)
		}
	}()

	<-stop
	slog.Info("shutting down", "reason", getStopReason())
	heartbeat.SendStopping(cfg, c, getStopReason())
	stopFlows()
	mgr.StopAll()
	for i := len(stopProducers) - 1; i >= 0; i-- {
		stopProducers[i]()
	}
	if durable != nil {
		durable.shutdown() // the journal keeps what was not acknowledged
	} else {
		flushBuffer(buf, c, cfg)
	}
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
		logType, location, rawMessage := tailer.Decode(entry)

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
