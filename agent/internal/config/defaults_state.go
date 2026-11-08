package config

// DefaultStateDir is the state directory used when the config sets none
// (Linux /var/lib/siem-agent, Windows %ProgramData%\SIEMAgent). Tools that
// must work without a readable config (-webblock-cleanup) use it.
func DefaultStateDir() (string, error) { return defaultStateDir() }
