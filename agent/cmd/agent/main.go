package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
	"github.com/siem-platform/agent/internal/fullscan"
	"github.com/siem-platform/agent/internal/heartbeat"
	"github.com/siem-platform/agent/internal/hygiene"
	"github.com/siem-platform/agent/internal/linsensor"
	"github.com/siem-platform/agent/internal/malhash"
	"github.com/siem-platform/agent/internal/memscan"
	"github.com/siem-platform/agent/internal/mlscan"
	"github.com/siem-platform/agent/internal/mlscore"
	"github.com/siem-platform/agent/internal/netwatch"
	"github.com/siem-platform/agent/internal/notify"
	"github.com/siem-platform/agent/internal/policy"
	"github.com/siem-platform/agent/internal/prevent"
	"github.com/siem-platform/agent/internal/procexec"
	"github.com/siem-platform/agent/internal/ransomguard"
	"github.com/siem-platform/agent/internal/scriptscan"
	"github.com/siem-platform/agent/internal/tailer"
	"github.com/siem-platform/agent/internal/task"
	"github.com/siem-platform/agent/internal/unpack"
	"github.com/siem-platform/agent/internal/webblock"
	"github.com/siem-platform/agent/internal/winsensor"
	"github.com/siem-platform/agent/internal/yarascan"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z"
var Version = "dev"

func main() {
	// The execution-prevention fanotify helper is this binary started again
	// (see internal/prevent/fanhelper_linux.go); it does nothing else.
	if prevent.IsHelper() {
		os.Exit(prevent.RunHelper())
	}
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
	webblockCleanup := flag.Bool("webblock-cleanup", false,
		"remove web protection (hosts block, trust-store CA and its key, saved list) and exit; works with the agent stopped, needs no network (used by package removal)")
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

	if *webblockCleanup {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
		// The hosts block and the trust store entry are removed whatever
		// happens to the config; without one the default state dir is used.
		var stateDir string
		cfg, cfgErr := config.Load(*configPath)
		if cfgErr == nil {
			stateDir = task.StateDir(cfg)
		} else {
			slog.Error("webblock cleanup: could not load the config; using the default state directory", "err", cfgErr)
			d, err := config.DefaultStateDir()
			if err != nil {
				slog.Error("webblock cleanup: no default state directory; removing the hosts block and trust store entry only", "err", err)
			}
			stateDir = d
		}
		if err := webblock.Cleanup(stateDir); err != nil || cfgErr != nil {
			os.Exit(1)
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
	heartbeat.Updater = newUpdater(cfg, c) // before the heartbeat loop starts
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
		buf.SetUrgent(isUrgentEntry)
		if spill, err = buffer.OpenSpill(cfg.Buffer.SpillPath); err != nil {
			slog.Warn("disk spill unavailable; undelivered events will be lost on restart", "err", err)
			spill = nil
		} else {
			defer spill.Close()
		}
	}
	// Windows: pop-ups for signed-in users when malware is found or stopped
	// (after the legacy import above, so old entries do not pop up again).
	// The group policy from the server (protections on/off, exclusions),
	// applied to each protection as it starts and on every change.
	polStore := policy.Open(filepath.Join(task.StateDir(cfg), policy.FileName))
	// Script content (Windows: AMSI; Linux: interpreters' code) scanned with
	// the YARA rules; its rules are attached once the YARA scanner exists.
	scripts := &scriptscan.Scanner{
		Push: func(logType, line string) { buf.Push(tailer.Encode(logType, line)) },
		Action: func() string {
			if a := polStore.Current().Settings.ScriptScan; a != "" {
				return a
			}
			return "detect"
		},
		Excluded: func(image, name, sha string) bool {
			return polStore.Current().Settings.Excluded(policy.ScopeScript,
				policy.Match{Image: image, Path: name, SHA256: sha})
		},
		Kill: scriptscan.KillProcess,
		Self: uint32(os.Getpid()),
	}
	var notifier *notify.Notifier
	if n := notify.New(); n != nil && !cfg.Notify.Disabled {
		notifier = n
		buf.SetObserver(func(entry string) {
			logType, _, line := tailer.Decode(entry)
			n.Observe(logType, line)
		})
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

	// Execution prevention: the server's rules, enforced on Linux by the BPF
	// LSM and/or a fanotify helper (before the program runs), on Windows by
	// terminating a matching process as soon as the ETW sensor reports its
	// start; rules default to detect-only.
	var preventer *prevent.Manager
	if (runtime.GOOS == "linux" || runtime.GOOS == "windows") && !cfg.Prevention.Disabled {
		if pm, err := prevent.Start(prevent.Options{
			Push: func(logType, line string) { buf.Push(tailer.Encode(logType, line)) },
		}); err != nil {
			slog.Warn("execution prevention unavailable", "err", err)
		} else {
			defer pm.Close()
			go pm.Run(flowCtx, c)
			preventer = pm
		}
	}

	// Process-exec telemetry via eBPF (best-effort: needs CAP_BPF/CAP_SYS_ADMIN
	// and a BTF-enabled kernel; logs a warning and continues without it otherwise)
	// Producers are stopped explicitly at shutdown, before the durable journal closes.
	var stopProducers []func()
	if procMon, err := procexec.StartWith(buf, func(ex procexec.Exec) { scripts.OfferExec(ex.PID, ex.Image, ex.Args) }); err != nil {
		slog.Warn("procexec monitor unavailable, continuing without it", "err", err)
	} else {
		stopProducers = append(stopProducers, procMon.Stop)
	}

	// Ransomware protection: canary files everywhere; on Linux also the
	// bulk-encryption heuristics fed by the sensor below.
	var onFile func(linsensor.FileEvent)
	var guard *ransomguard.Guard
	if !cfg.Ransomware.Disabled {
		opts := ransomguard.Options{
			Push:          func(logType, line string) { buf.Push(tailer.Encode(logType, line)) },
			CanaryDirs:    cfg.Ransomware.CanaryDirs,
			CanaryNames:   cfg.Ransomware.CanaryNames,
			CanaryVisible: cfg.Ransomware.CanaryVisible,
			AllowImages:   cfg.Ransomware.AllowImages,
			Kill:          !cfg.Ransomware.ReportOnly,
		}
		isolate := func() error { _, err := fwEngine.Isolate(); return err }
		if cfg.Ransomware.Isolate {
			opts.Isolate = isolate
		}
		opts.IsolateFunc = isolate
		guard = ransomguard.New(opts)
		go guard.Run(flowCtx)
		onFile = guard.Observe
	}

	// File, kernel module, ptrace, privilege, memfd/fileless and exit
	// telemetry (Linux eBPF; best-effort like procexec)
	if runtime.GOOS == "linux" && !cfg.LinuxSensor.Disabled {
		if sensor, err := linsensor.Start(linsensor.Options{
			Push:     func(logType, line string) { buf.Push(tailer.Encode(logType, line)) },
			OnFile:   onFile,
			Disabled: cfg.LinuxSensor.DisabledEvents,
		}); err != nil {
			slog.Warn("linux sensor unavailable, continuing without it", "err", err)
		} else {
			stopProducers = append(stopProducers, sensor.Stop)
		}
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
		} else if sensor, err := winsensor.StartWith(buf, winsensor.Options{
			Disabled: cfg.ETW.DisabledEvents, OnFile: windowsFileFeed(onFile),
			OnProcess: windowsProcessFeed(preventer),
			OnScript: func(a winsensor.AMSIScript) {
				scripts.Offer(scriptscan.Script{PID: a.PID, Image: a.Image, App: a.App, Name: a.Name, Content: a.Content})
			}}); err != nil {
			slog.Warn("ETW sensor unavailable, continuing without it", "err", err)
		} else {
			stopProducers = append(stopProducers, sensor.Stop)
			slog.Info("ETW sensor running", "telemetry", "process, network, dns, file, image, access, thread",
				"disabled", cfg.ETW.DisabledEvents)
			if !slices.Contains(cfg.ETW.DisabledEvents, winsensor.GroupRegistry) {
				reg := winsensor.StartRegistry(buf)
				stopProducers = append(stopProducers, reg.Close)
				slog.Info("registry persistence watcher running")
			}
		}
	}

	// Writable+executable private memory (injected code) in every process
	if !cfg.MemorySweep.Disabled && (runtime.GOOS == "linux" || runtime.GOOS == "windows") {
		sweeper := &memscan.Sweeper{
			Push:     func(logType, line string) { buf.Push(tailer.Encode(logType, line)) },
			Interval: time.Duration(cfg.MemorySweep.IntervalMinutes) * time.Minute,
		}
		go sweeper.Run(flowCtx)
	}

	// Known-malware hashes (server: MalwareBazaar feed, analysts, critical
	// YARA matches): checked on every exec by the prevention engine and on
	// every file the on-access scanner reads; block mode kills / quarantines.
	push := func(logType, line string) { buf.Push(tailer.Encode(logType, line)) }
	malStore := malhash.Open(filepath.Join(task.StateDir(cfg), malhash.FileName))
	// a file found inside an archive ("outer|inner") quarantines the archive
	quarantine := func(path string) error { return task.QuarantineFile(unpack.Outer(path)) }
	malFiles := &malhash.FileChecker{Store: malStore, Push: push, Quarantine: quarantine}
	malStore.OnChange = func(set *malhash.Set) {
		if preventer != nil {
			preventer.SetKnownMalware(set, malStore.File())
		}
	}
	if preventer != nil && malStore.Current().Active() {
		preventer.SetKnownMalware(malStore.Current(), malStore.File())
	}
	go malStore.SyncLoop(flowCtx, c)

	// Web protection: the server's blocklist becomes a hosts block pointing at
	// a local block page (see internal/webblock).
	webStateDir := task.StateDir(cfg)
	webStore := webblock.Open(webblock.ListPath(webStateDir))
	webHost := mustHostname()
	webCtl := &webblock.Controller{
		Hosts:     webblock.NewHostsFile(),
		Authority: &webblock.TrustStore{Dir: webStateDir},
		Server:    &webblock.Server{Push: push, Hostname: webHost},
		Hostname:  webHost,
		StateDir:  webStateDir,
	}
	heartbeat.WebBlockHealth = func() any { return webCtl.Health() }
	// OnChange applies the store's newest list, never an older one that lost
	// a race with it.
	webStore.OnChange = func(*webblock.List) { webCtl.ApplyCurrent(webStore.Current) }
	// The first Apply may run trust tools for minutes: never hold up startup
	// (Health reports the last finished Apply meanwhile).
	go webCtl.ApplyCurrent(webStore.Current)
	go webStore.SyncLoop(flowCtx, c)
	go webCtl.Run(flowCtx, webStore)
	malFiles.Excluded = func(path, sha string) bool {
		return polStore.Current().Settings.Excluded(policy.ScopeMalware, policy.Match{Path: path, Image: path, SHA256: sha})
	}
	polStore.OnChange(func(p *policy.Policy) { applyPolicy(p.Settings, preventer, notifier, guard) })
	go polStore.SyncLoop(flowCtx, c)

	// Static ML on the files the on-access scanner reads: models trained on
	// EMBER2024 for PE and ELF files, plus ELF heuristics (group policy
	// ml_action).
	var mlFiles func(path, sha string, data []byte, trigger string) bool
	if model, err := mlscore.Default(); err != nil {
		slog.Warn("static ML model unavailable", "err", err)
	} else {
		elfModel, err := mlscore.DefaultELF()
		if err != nil {
			slog.Warn("static ML model for ELF unavailable: heuristics only", "err", err)
		}
		ml := &mlscan.Checker{Model: model, ELF: elfModel, Push: push, Quarantine: quarantine,
			Mode: func(path, sha string) string {
				s := polStore.Current().Settings
				if s.Excluded(policy.ScopeML, policy.Match{Path: path, Image: path, SHA256: sha}) {
					return mlscan.ModeOff
				}
				return s.MLAction
			},
			Known: func(sha string) bool {
				_, ok := malStore.Current().Lookup(sha)
				return ok
			},
		}
		mlFiles = ml.Check
	}

	// On-access YARA scanning of risky directories with the server's rules
	yaraScanner := yarascan.New(yarascan.Options{
		Roots:       cfg.Yara.WatchPaths,
		MaxFileSize: cfg.Yara.MaxFileSizeMB << 20,
		Push:        push,
		OnHash:      malFiles.Check,
		// variants of known malware (TLSH), then the static ML check
		OnData: func(path, sha string, data []byte, trigger string) bool {
			hit := malFiles.CheckData(path, sha, data, trigger)
			if mlFiles != nil && mlFiles(path, sha, data, trigger) {
				hit = true
			}
			return hit
		},
		Skip: func(path string) bool {
			s := polStore.Current().Settings
			return !s.YaraOnAccess || s.Excluded(policy.ScopeYara, policy.Match{Path: path, Image: path})
		},
	})
	go yaraScanner.SyncLoop(flowCtx, c)

	// Quick / full / custom scans of the disk: on request (task file_scan)
	// and on the group policy's schedule, through the same engines.
	stateDir := task.StateDir(cfg)
	scanOpts := func(kind string, paths []string, requested string) fullscan.Options {
		return fullscan.Options{Kind: kind, Paths: paths, MaxFileSize: cfg.Yara.MaxFileSizeMB << 20, Push: push,
			Requested: requested,
			Skip: func(path string) bool {
				if strings.HasPrefix(path, stateDir) || task.IsQuarantined(path) {
					return true
				}
				return polStore.Current().Settings.Excluded(policy.ScopeYara, policy.Match{Path: path, Image: path})
			}}
	}
	taskRunner.FileScan = func(kind string, paths []string, requested string) (any, error) {
		return fullscan.Run(flowCtx, yaraScanner, scanOpts(kind, paths, requested))
	}
	go fullscan.Schedule(flowCtx, filepath.Join(stateDir, "file_scan_schedule.json"),
		func() (string, string) {
			s := polStore.Current().Settings
			return s.QuickScanTime, s.FullScanSchedule
		},
		func(kind string) {
			if _, err := fullscan.Run(flowCtx, yaraScanner, scanOpts(kind, nil, "schedule")); err != nil {
				slog.Warn("scheduled file scan not run", "kind", kind, "err", err)
			}
		})
	scripts.Yara = yaraScanner
	go scripts.Run(flowCtx)
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
			malStore.Want(resp.MalwareHashesVersion)
			webStore.Want(resp.WebBlocklistVersion)
			polStore.Want(resp.PolicyVersion)
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

	senderCtx, stopSender := context.WithCancel(context.Background())
	defer stopSender()
	senderDone := make(chan struct{})
	if durable != nil {
		durable.startSender(c, heartbeat.SupportsEvidenceV2, heartbeat.EvidenceBatchMax)
		close(senderDone)
	} else {
		go func() {
			defer close(senderDone)
			senderLoop(senderCtx, buf, c, cfg, spill, detector)
		}()
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
	webCtl.Stop() // removes the block page redirect; the hosts block keeps names refused
	mgr.StopAll()
	for i := len(stopProducers) - 1; i >= 0; i-- {
		stopProducers[i]()
	}
	if durable != nil {
		durable.shutdown() // the journal keeps what was not acknowledged
	} else {
		// The sender stops first (an in-flight entry goes back to the
		// buffer), then one bounded flush: systemd kills the agent after
		// TimeoutStopSec (30 s), and what is left goes to the disk spill
		// for the next start instead of being lost.
		stopSender()
		<-senderDone
		ctx, cancel := context.WithTimeout(context.Background(), shutdownFlush)
		flushBuffer(ctx, buf, c, cfg, spill)
		cancel()
	}
}

// shutdownFlush bounds the last flush, inside systemd's 30 s stop timeout.
const shutdownFlush = 15 * time.Second

// sendEntry posts one buffered entry. ok is false when it should be retried
// (network error, 5xx, or ctx ended mid-request); a 4xx rejection is
// dropped and logged, which counts as sent.
func sendEntry(ctx context.Context, entry string, c *client.Client, cfg *config.Config) (ok bool, err error) {
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
	resp, err := c.PostContext(ctx, "/api/ingest/log", payload)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return deliveryResult(resp, logType)
}

// deliveryResult: 5xx, and 401/403 (this agent's token is refused: dropping
// would throw away everything, and retrying at once floods the server) are
// retried with a backoff; other refusals drop the entry.
func deliveryResult(resp *http.Response, what string) (bool, error) {
	switch {
	case resp.StatusCode >= 500:
		return false, fmt.Errorf("server status %d", resp.StatusCode)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, fmt.Errorf("server refused this agent's token (status %d); re-enroll the agent", resp.StatusCode)
	case resp.StatusCode >= 300:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		slog.Error("log rejected by server, dropping", "status", resp.StatusCode, "body", string(body), "log_type", what)
	}
	return true, nil
}

// sendBatch sends entries in one POST /api/ingest/logs.
func sendBatch(ctx context.Context, entries []string, c *client.Client, cfg *config.Config) (bool, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	host := mustHostname()
	batch := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		logType, location, rawMessage := tailer.Decode(entry)
		batch = append(batch, map[string]any{
			"agent_id": cfg.Agent.ID, "log_type": logType, "raw_message": rawMessage, "location": location,
			"received_at": now, "hostname": host,
		})
	}
	resp, err := c.PostContext(ctx, "/api/ingest/logs", map[string]any{"entries": batch})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return deliveryResult(resp, fmt.Sprintf("batch of %d", len(entries)))
}

// wait sleeps d or until ctx ends; false when ctx ended.
func wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// urgentLogTypes jump the legacy queue: a detection must reach the server
// before the telemetry backlog ahead of it.
var urgentLogTypes = map[string]bool{
	malhash.LogType: true, webblock.LogType: true, yarascan.LogType: true, prevent.LogType: true, prevent.WindowsLogType: true,
	ransomguard.LogType: true, mlscan.LogType: true, "local_detection": true, "linux_sensor_health": true,
	scriptscan.LogType: true,
}

func isUrgentEntry(entry string) bool {
	logType, _, _ := tailer.Decode(entry)
	return urgentLogTypes[logType]
}

// maxBatchBytes bounds one POST /api/ingest/logs (nginx takes 10 MB).
const maxBatchBytes = 2 << 20

// logBatchMax is what the server's heartbeat advertised (tests replace it).
var logBatchMax = heartbeat.LogBatchMax

func senderLoop(ctx context.Context, buf *buffer.Buffer, c *client.Client, cfg *config.Config, spill *buffer.Spill, detector *detect.Engine) {
	backoff := time.Second
	wasOffline := false
	replaySpill(buf, spill)

	for ctx.Err() == nil {
		batchMax := logBatchMax()
		n := batchMax
		if n <= 0 {
			n = 1 // older server: one line per POST /api/ingest/log
		}
		entries := buf.PopN(n, maxBatchBytes)
		if len(entries) == 0 {
			backoff = time.Second
			wait(ctx, 100*time.Millisecond)
			continue
		}

		// Local detection observes every event exactly once, before delivery:
		// it must keep working while the server is unreachable.
		if detector != nil {
			for _, entry := range entries {
				logType, _, rawMessage := tailer.Decode(entry)
				detector.Emit(detector.Observe(logType, rawMessage))
			}
		}

		var sent bool
		var err error
		if batchMax <= 0 {
			sent, err = sendEntry(ctx, entries[0], c, cfg)
		} else {
			sent, err = sendBatch(ctx, entries, c, cfg)
		}
		if !sent {
			for _, entry := range entries {
				buf.Requeue(entry) // also when shutdown cancelled the request
			}
			if ctx.Err() != nil {
				return
			}
			for _, entry := range entries {
				spill.Append(entry)
			}
			wasOffline = true
			slog.Warn("send failed, backing off", "backoff", backoff, "entries", len(entries), "err", err)
			if !wait(ctx, backoff) {
				return
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}

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
		buf.Requeue(entry) // seen (and notified) before the restart
	}
	if n := len(undelivered); n > 0 {
		slog.Info("replayed undelivered entries", "count", n)
	}
}

// flushBuffer sends what is buffered until ctx ends, retrying failures with
// a backoff; whatever is left then goes to the spill (when there is one), so
// the next start sends it.
func flushBuffer(ctx context.Context, buf *buffer.Buffer, c *client.Client, cfg *config.Config, spill *buffer.Spill) {
	slog.Info("flushing buffer", "len", buf.Len())
	backoff := 200 * time.Millisecond
	for ctx.Err() == nil {
		entry, ok := buf.Pop()
		if !ok {
			return
		}
		if sent, _ := sendEntry(ctx, entry, c, cfg); sent {
			backoff = 200 * time.Millisecond
			continue
		}
		buf.Requeue(entry)
		if !wait(ctx, backoff) {
			break
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
	kept := 0
	for {
		entry, ok := buf.Pop()
		if !ok {
			break
		}
		spill.Append(entry)
		kept++
	}
	if kept > 0 {
		if spill == nil {
			slog.Warn("shutdown flush ran out of time; no spill configured, buffered entries are lost", "lost", kept)
		} else {
			slog.Warn("shutdown flush ran out of time; buffered entries kept in the spill for the next start", "kept", kept)
		}
	}
}

func mustHostname() string {
	h, _ := os.Hostname()
	return h
}

// windowsProcessFeed hands the ETW sensor's process starts to execution
// prevention; nil when prevention is off.
// applyPolicy hands the group policy to the protections running here (nil
// ones did not start: their local config turned them off, which stays).
func applyPolicy(s policy.Settings, pm *prevent.Manager, n *notify.Notifier, g *ransomguard.Guard) {
	if pm != nil {
		pm.SetGate(!s.PreventionEnabled, append(s.For(policy.ScopePrevention), s.For(policy.ScopeMalware)...))
	}
	n.SetEnabled(s.NotifyUser)
	if g != nil {
		g.SetRuntime(ransomguard.Runtime{
			Off: s.RansomwareMode == "off", Kill: s.RansomwareMode != "report", Isolate: s.RansomwareIsolate,
			Excluded: func(image string) bool {
				return s.Excluded(policy.ScopeRansomware, policy.Match{Image: image})
			},
		})
	}
}

func windowsProcessFeed(pm *prevent.Manager) func(winsensor.ProcessStart) {
	if pm == nil {
		return nil
	}
	return func(p winsensor.ProcessStart) {
		pm.ObserveExec(prevent.ProcessStart{PID: p.PID, PPID: p.PPID, Image: p.Image, ParentImage: p.ParentImage})
	}
}

// windowsFileFeed adapts the ETW sensor's file events to the anti-ransomware
// guard's (linsensor.FileEvent); nil when the guard is off.
func windowsFileFeed(onFile func(linsensor.FileEvent)) func(winsensor.FileEvent) {
	if onFile == nil {
		return nil
	}
	return func(e winsensor.FileEvent) {
		onFile(linsensor.FileEvent{Time: e.Time, PID: e.PID, PPID: e.PPID, Image: e.Image,
			Comm: filepath.Base(e.Image), Action: e.Action, Path: e.Path, From: e.From})
	}
}
