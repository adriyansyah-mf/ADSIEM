package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Overlay is the part of config.yaml the server may set per group. Every
// field is a pointer: nil means "keep the local value", while an explicit
// false, 0 or [] overrides it. Only whitelisted fields exist here, so any
// other field the server sends is dropped when the JSON is decoded.
type Overlay struct {
	Server      *ServerOverlay      `json:"server,omitempty"`
	Agent       *AgentOverlay       `json:"agent,omitempty"`
	FIM         *FimOverlay         `json:"fim,omitempty"`
	Firewall    *FirewallOverlay    `json:"firewall,omitempty"`
	Netwatch    *NetwatchOverlay    `json:"netwatch,omitempty"`
	ETW         *ETWOverlay         `json:"etw,omitempty"`
	Detect      *DetectOverlay      `json:"detect,omitempty"`
	LinuxSensor *LinuxSensorOverlay `json:"linux_sensor,omitempty"`
	Ransomware  *RansomwareOverlay  `json:"ransomware,omitempty"`
	Yara        *YaraOverlay        `json:"yara,omitempty"`
	MemorySweep *MemorySweepOverlay `json:"memory_sweep,omitempty"`
	Evidence    *EvidenceOverlay    `json:"evidence,omitempty"`
	Prevention  *DisabledOverlay    `json:"prevention,omitempty"`
	Notify      *DisabledOverlay    `json:"notify,omitempty"`
	ProjectScan *DisabledOverlay    `json:"project_scan,omitempty"`
	Update      *DisabledOverlay    `json:"update,omitempty"`
}

type ServerOverlay struct {
	URL               *string `json:"url,omitempty"`
	HeartbeatInterval *int    `json:"heartbeat_interval,omitempty"`
}

type AgentOverlay struct {
	BufferSize *int `json:"buffer_size,omitempty"`
}

type FimOverlay struct {
	Enabled *bool `json:"enabled,omitempty"`
}

type FirewallOverlay struct {
	Enabled                             *bool     `json:"enabled,omitempty"`
	Backend                             *string   `json:"backend,omitempty"`
	DryRun                              *bool     `json:"dry_run,omitempty"`
	ProtectedIPs                        *[]string `json:"protected_ips,omitempty"`
	IsolationReleaseAfterOfflineMinutes *int      `json:"isolation_release_after_offline_minutes,omitempty"`
}

type NetwatchOverlay struct {
	Enabled          *bool `json:"enabled,omitempty"`
	SnapshotFallback *bool `json:"snapshot_fallback,omitempty"`
}

type ETWOverlay struct {
	Mode           *string   `json:"mode,omitempty"`
	DisabledEvents *[]string `json:"disabled_events,omitempty"`
}

type DetectOverlay struct {
	Enabled         *bool     `json:"enabled,omitempty"`
	Rules           *[]string `json:"rules,omitempty"`
	MaxBlocked      *int      `json:"max_blocked,omitempty"`
	MaxBlocksPerMin *int      `json:"max_blocks_per_minute,omitempty"`
}

type LinuxSensorOverlay struct {
	Disabled       *bool     `json:"disabled,omitempty"`
	DisabledEvents *[]string `json:"disabled_events,omitempty"`
}

type RansomwareOverlay struct {
	Disabled      *bool     `json:"disabled,omitempty"`
	CanaryDirs    *[]string `json:"canary_dirs,omitempty"`
	CanaryNames   *[]string `json:"canary_names,omitempty"`
	CanaryVisible *bool     `json:"canary_visible,omitempty"`
	AllowImages   *[]string `json:"allow_images,omitempty"`
}

type YaraOverlay struct {
	WatchPaths    *[]string `json:"watch_paths,omitempty"`
	MaxFileSizeMB *int64    `json:"max_file_size_mb,omitempty"`
}

type MemorySweepOverlay struct {
	Disabled        *bool `json:"disabled,omitempty"`
	IntervalMinutes *int  `json:"interval_minutes,omitempty"`
}

type EvidenceOverlay struct {
	Enabled       *bool  `json:"enabled,omitempty"`
	MaxBytes      *int64 `json:"max_bytes,omitempty"`
	SegmentBytes  *int64 `json:"segment_bytes,omitempty"`
	ReservedBytes *int64 `json:"reserved_bytes,omitempty"`
	MaxEventBytes *int   `json:"max_event_bytes,omitempty"`
}

// DisabledOverlay serves the sections whose only overlay field is disabled.
type DisabledOverlay struct {
	Disabled *bool `json:"disabled,omitempty"`
}

func set[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

func setList(dst *[]string, src *[]string) {
	if src != nil {
		*dst = append([]string{}, *src...)
	}
}

// ApplyOverlay writes every non-nil overlay field into cfg and returns what
// it refused. A nil overlay changes nothing. server.url is only taken when it
// is https and keeps the host of the URL cfg had before the overlay.
func ApplyOverlay(cfg *Config, o *Overlay) (warnings []string) {
	if o == nil {
		return nil
	}
	if s := o.Server; s != nil {
		if s.URL != nil {
			if w := checkServerURL(cfg.Server.URL, *s.URL); w != "" {
				warnings = append(warnings, w)
			} else {
				cfg.Server.URL = *s.URL
			}
		}
		set(&cfg.Server.HeartbeatInterval, s.HeartbeatInterval)
	}
	if a := o.Agent; a != nil {
		set(&cfg.Agent.BufferSize, a.BufferSize)
	}
	if f := o.FIM; f != nil {
		set(&cfg.FIM.Enabled, f.Enabled)
	}
	if f := o.Firewall; f != nil {
		set(&cfg.Firewall.Enabled, f.Enabled)
		set(&cfg.Firewall.Backend, f.Backend)
		set(&cfg.Firewall.DryRun, f.DryRun)
		setList(&cfg.Firewall.ProtectedIPs, f.ProtectedIPs)
		set(&cfg.Firewall.IsolationReleaseAfterOfflineMinutes, f.IsolationReleaseAfterOfflineMinutes)
	}
	if n := o.Netwatch; n != nil {
		set(&cfg.Netwatch.Enabled, n.Enabled)
		set(&cfg.Netwatch.SnapshotFallback, n.SnapshotFallback)
	}
	if e := o.ETW; e != nil {
		set(&cfg.ETW.Mode, e.Mode)
		setList(&cfg.ETW.DisabledEvents, e.DisabledEvents)
	}
	if d := o.Detect; d != nil {
		set(&cfg.Detect.Enabled, d.Enabled)
		setList(&cfg.Detect.Rules, d.Rules)
		set(&cfg.Detect.MaxBlocked, d.MaxBlocked)
		set(&cfg.Detect.MaxBlocksPerMin, d.MaxBlocksPerMin)
	}
	if l := o.LinuxSensor; l != nil {
		set(&cfg.LinuxSensor.Disabled, l.Disabled)
		setList(&cfg.LinuxSensor.DisabledEvents, l.DisabledEvents)
	}
	if r := o.Ransomware; r != nil {
		set(&cfg.Ransomware.Disabled, r.Disabled)
		setList(&cfg.Ransomware.CanaryDirs, r.CanaryDirs)
		setList(&cfg.Ransomware.CanaryNames, r.CanaryNames)
		set(&cfg.Ransomware.CanaryVisible, r.CanaryVisible)
		setList(&cfg.Ransomware.AllowImages, r.AllowImages)
	}
	if y := o.Yara; y != nil {
		setList(&cfg.Yara.WatchPaths, y.WatchPaths)
		set(&cfg.Yara.MaxFileSizeMB, y.MaxFileSizeMB)
	}
	if m := o.MemorySweep; m != nil {
		set(&cfg.MemorySweep.Disabled, m.Disabled)
		set(&cfg.MemorySweep.IntervalMinutes, m.IntervalMinutes)
	}
	if e := o.Evidence; e != nil {
		set(&cfg.Evidence.Enabled, e.Enabled)
		set(&cfg.Evidence.MaxBytes, e.MaxBytes)
		set(&cfg.Evidence.SegmentBytes, e.SegmentBytes)
		set(&cfg.Evidence.ReservedBytes, e.ReservedBytes)
		set(&cfg.Evidence.MaxEventBytes, e.MaxEventBytes)
	}
	if p := o.Prevention; p != nil {
		set(&cfg.Prevention.Disabled, p.Disabled)
	}
	if n := o.Notify; n != nil {
		set(&cfg.Notify.Disabled, n.Disabled)
	}
	if p := o.ProjectScan; p != nil {
		set(&cfg.ProjectScan.Disabled, p.Disabled)
	}
	if u := o.Update; u != nil {
		set(&cfg.Update.Disabled, u.Disabled)
	}
	return warnings
}

// checkServerURL returns a warning when next may not replace cur.
func checkServerURL(cur, next string) string {
	host := ""
	if u, err := url.Parse(cur); err == nil {
		host = u.Hostname()
	}
	n, err := url.Parse(next)
	if err != nil || n.Scheme != "https" || host == "" || !strings.EqualFold(n.Hostname(), host) {
		return fmt.Sprintf("server.url: host must stay %s", host)
	}
	return ""
}
