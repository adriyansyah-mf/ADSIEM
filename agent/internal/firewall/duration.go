package firewall

import "time"

func secondsToDuration(sec int) time.Duration {
	return time.Duration(sec) * time.Second
}
