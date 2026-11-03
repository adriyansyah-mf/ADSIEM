//go:build !windows

package fullscan

import (
	"bufio"
	"os"
	"strings"
)

func quickRoots() []string {
	return []string{
		"/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv/www",
		"/usr/local/bin", "/usr/local/sbin", "/opt",
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
		"/var/spool/cron", "/etc/systemd/system", "/etc/init.d", "/etc/rc.local", "/etc/ld.so.preload",
		"/root", "/home/*/Downloads", "/home/*/Desktop", "/home/*/.local/bin", "/home/*/.config/autostart",
		"/home/*/.config/systemd", "/home/*/.ssh",
	}
}

func fullRoots() []string { return []string{"/"} }

// pseudo and remote file systems a full scan does not enter
var skipTypes = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "pstore": true, "bpf": true, "mqueue": true,
	"hugetlbfs": true, "configfs": true, "fusectl": true, "autofs": true, "binfmt_misc": true, "efivarfs": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "9p": true, "fuse.sshfs": true,
	"fuse.gvfsd-fuse": true, "fuse.rclone": true, "ceph": true, "glusterfs": true, "overlay": true, "squashfs": true,
	"nsfs": true, "ramfs": true, "rpc_pipefs": true,
}

// skippedMounts: mount points of skipped file systems (/proc/self/mountinfo).
func skippedMounts() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// id parent major:minor root mountpoint options ... - fstype source superopts
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, x := range fields {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 5 || sep < 0 || sep+1 >= len(fields) {
			continue
		}
		mp := strings.ReplaceAll(fields[4], `\040`, " ")
		if skipTypes[fields[sep+1]] && mp != "/" {
			out[mp] = true
		}
	}
	return out
}

func skipDir(path string) bool {
	switch path {
	case "/proc", "/sys", "/dev", "/run":
		return true
	}
	return false
}
