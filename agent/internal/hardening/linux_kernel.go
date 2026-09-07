package hardening

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func checkKernelASLR(path string) Check {
	const id = "kernel-aslr-enabled"
	const category = "kernel"
	const title = "Full ASLR is enabled (kernel.randomize_va_space=2)"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read randomize_va_space sysctl"}
	}
	val := strings.TrimSpace(string(data))
	if val == "2" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "kernel.randomize_va_space=2"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "kernel.randomize_va_space=" + val + " (expected 2)"}
}

func checkKernelPtraceScope(path string) Check {
	const id = "kernel-ptrace-restricted"
	const category = "kernel"
	const title = "Ptrace scope restricts cross-process debugging (kernel.yama.ptrace_scope>=1)"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "Yama LSM not present on this kernel"}
	}
	val := strings.TrimSpace(string(data))
	n, err := strconv.Atoi(val)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusError, Detail: "unexpected value: " + val}
	}
	if n >= 1 {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "kernel.yama.ptrace_scope=" + val}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "kernel.yama.ptrace_scope=0 (unrestricted)"}
}

func checkKernelCoreDumpRestricted(path string) Check {
	const id = "kernel-coredump-restricted"
	const category = "kernel"
	const title = "Core dumps from setuid programs are restricted (fs.suid_dumpable=0)"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read suid_dumpable sysctl"}
	}
	val := strings.TrimSpace(string(data))
	if val == "0" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "fs.suid_dumpable=0"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "fs.suid_dumpable=" + val + " (expected 0)"}
}

func checkTmpNoExec(mountsPath string) Check {
	const id = "fs-tmp-noexec"
	const category = "kernel"
	const title = "/tmp, if its own mount, is mounted noexec,nosuid"

	f, err := os.Open(mountsPath)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read mounts table"}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[1] != "/tmp" {
			continue
		}
		opts := strings.Split(fields[3], ",")
		hasNoExec, hasNoSuid := false, false
		for _, o := range opts {
			if o == "noexec" {
				hasNoExec = true
			}
			if o == "nosuid" {
				hasNoSuid = true
			}
		}
		if hasNoExec && hasNoSuid {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "/tmp mounted with " + fields[3]}
		}
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "/tmp mounted without noexec,nosuid: " + fields[3]}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "/tmp is not a separate mount on this host"}
}
