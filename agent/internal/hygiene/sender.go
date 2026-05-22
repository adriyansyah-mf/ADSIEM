package hygiene

import (
	"log/slog"
	"os"
	"time"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
)

// Start launches a background goroutine that collects and ships hygiene reports.
func Start(cfg *config.Config, c *client.Client) {
	go func() {
		// stagger first report so enrollment has settled
		time.Sleep(30 * time.Second)
		for {
			hostname, _ := os.Hostname()
			if hostname == "" {
				hostname = cfg.Agent.Name
			}
			report, err := Collect(cfg.Agent.ID, hostname)
			if err != nil {
				slog.Warn("hygiene collect failed", "err", err)
			} else {
				if err := c.PostWithRetry("/api/hygiene", report, 3); err != nil {
					slog.Warn("hygiene send failed", "err", err)
				} else {
					slog.Info("hygiene reported", "score", report.Score, "issues", len(report.Issues), "packages", len(report.Packages))
				}
			}
			time.Sleep(5 * time.Minute)
		}
	}()
}
