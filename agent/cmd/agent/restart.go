package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/policy"
)

// restartRequested is set once restartAfter has decided to restart the
// agent into a new dashboard config. run then exits with restartExitCode
// after its normal shutdown, so the service manager starts it again.
var restartRequested atomic.Bool

// restartExitCode makes the service manager restart the agent (systemd
// Restart=always, the Windows SCM recovery action) without a clean stop.
const restartExitCode = 3

// inServiceManager is underServiceManager; tests replace it.
var inServiceManager = underServiceManager

// restartAfter closes stop after d so run shuts down and restarts. It acts
// at most once per process. Outside a service manager nothing would start
// the agent again, so it only logs and calls required, which puts it in the
// config error the heartbeat reports.
func restartAfter(stop chan<- struct{}, d time.Duration, required func()) {
	if !inServiceManager() {
		slog.Warn("config changed: restart required")
		required()
		return
	}
	if !restartRequested.CompareAndSwap(false, true) {
		return
	}
	slog.Info("config changed: restarting", "in", d)
	time.Sleep(d)
	close(stop)
}

// restartJitter spreads the restarts of a group over 0-60 s.
func restartJitter() time.Duration {
	return rand.N(60 * time.Second)
}

// probeServer checks that url answers the agent: a fetch of the policy with
// the agent token, over the same verified TLS as every other agent request
// (client.Client). The server serves the policy on POST only, as
// policy.Store.Sync fetches it, so the probe posts too. The heartbeat is not
// used: two heartbeat sessions look like a stolen token.
func probeServer(c *client.Client) func(url string) error {
	return func(url string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resp, err := client.New(url, c.Token()).PostContext(ctx, policy.Path, map[string]any{})
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("%s: %s", policy.Path, resp.Status)
		}
		return nil
	}
}
