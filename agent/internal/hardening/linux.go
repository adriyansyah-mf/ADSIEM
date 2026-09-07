package hardening

const (
	loginDefsPath   = "/etc/login.defs"
	shadowPath      = "/etc/shadow"
	passwdPath      = "/etc/passwd"
	sshdConfigPath  = "/etc/ssh/sshd_config"
	ipForwardPath   = "/proc/sys/net/ipv4/ip_forward"
	aslrPath        = "/proc/sys/kernel/randomize_va_space"
	ptraceScopePath = "/proc/sys/kernel/yama/ptrace_scope"
	suidDumpPath    = "/proc/sys/fs/suid_dumpable"
	mountsPath      = "/proc/mounts"
)

var pamPasswordPaths = []string{"/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}
var pamAuthPaths = []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"}

// Collect runs every v1 Linux hardening check and returns the aggregate
// report. openPorts is the same port list the hygiene collector already
// gathered — passed in rather than re-scanned here to avoid duplicating
// /proc/net/tcp parsing in two packages.
func Collect(openPorts []PortInfo) *Report {
	r := &Report{}
	r.Checks = append(r.Checks,
		checkPasswordMaxAge(loginDefsPath),
		checkPasswordComplexity(pamPasswordPaths),
		checkAccountLockout(pamAuthPaths),
		checkNoEmptyPasswords(shadowPath),
		checkNoDuplicateRootUID(passwdPath),
		checkFirewallActive(),
		checkIPForwardDisabled(ipForwardPath),
		checkNoLegacyServices(openPorts),
		checkSSHNoRootLogin(sshdConfigPath),
		checkSSHNoPasswordAuth(sshdConfigPath),
		checkSSHProtocol2(sshdConfigPath),
		checkSSHMaxAuthTries(sshdConfigPath),
		checkKernelASLR(aslrPath),
		checkKernelPtraceScope(ptraceScopePath),
		checkKernelCoreDumpRestricted(suidDumpPath),
		checkTmpNoExec(mountsPath),
	)
	return r
}
