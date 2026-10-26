//go:build !linux

package prevent

import "errors"

// HelperEnv marks the fanotify helper process (Linux only).
const HelperEnv = "SIEM_AGENT_FANOTIFY_HELPER"

func IsHelper() bool { return false }
func RunHelper() int { return 1 }

func startEngines(func(Decision)) (engines, error) {
	return nil, errors.New("prevent: execution prevention is Linux only")
}
