//go:build windows

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "SIEMAgent"
	serviceDisplayName = "SIEM Platform Agent"
	serviceDescription = "Ships Windows Event Log and file logs to the SIEM platform and runs live-response collections."
	logRotateBytes     = 50 << 20
)

func dataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "SIEMAgent")
}

func defaultConfigPath() string { return filepath.Join(dataDir(), "config.yaml") }

type agentService struct{ run func(stop <-chan struct{}) }

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		s.run(stop)
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				select {
				case <-done:
				case <-time.After(20 * time.Second): // final buffer flush gets this long
				}
				return false, 0
			}
		case <-done: // run returned on its own (e.g. bad config): let the SCM restart us
			return false, 1
		}
	}
}

// runAsService runs the agent under the Service Control Manager when started
// as a service, logging to %ProgramData%\SIEMAgent\agent.log (stdout goes nowhere).
func runAsService(run func(stop <-chan struct{})) bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	if err := os.MkdirAll(dataDir(), 0o755); err == nil {
		logPath := filepath.Join(dataDir(), "agent.log")
		if fi, err := os.Stat(logPath); err == nil && fi.Size() > logRotateBytes {
			_ = os.Rename(logPath, logPath+".1")
		}
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			slog.SetDefault(slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo})))
		}
	}
	if err := svc.Run(serviceName, &agentService{run: run}); err != nil {
		slog.Error("service run failed", "err", err)
	}
	return true
}

// manageService installs (auto-start, restart on failure) or removes the service.
func manageService(install bool, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	if !install {
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("service %s is not installed", serviceName)
		}
		defer s.Close()
		_, _ = s.Control(svc.Stop)
		if err := s.Delete(); err != nil {
			return err
		}
		fmt.Println("service removed")
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists; run -uninstall first", serviceName)
	}
	absConfig, _ := filepath.Abs(configPath)
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	}, "-config", absConfig)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)
	fmt.Printf("service %s installed (config %s); start it with: sc start %s\n", serviceName, absConfig, serviceName)
	return nil
}
