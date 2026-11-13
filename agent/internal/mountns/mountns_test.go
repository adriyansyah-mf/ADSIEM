package mountns

import "testing"

// Lines from a real host (otakunesia, 2026-11-13): apache2 runs with systemd
// PrivateTmp, and a miner it dropped in /var/tmp lived on the host under
// /var/tmp/systemd-private-...-apache2.service-KsXgSN/tmp.
const apacheMountinfo = `275 55 8:3 / / rw,relatime shared:40 master:1 - xfs /dev/sda3 rw
399 275 0:35 / /tmp rw,nosuid,nodev shared:362 master:17 - tmpfs tmpfs rw
408 275 0:42 / /dev ro,nosuid,noexec shared:365 - tmpfs tmpfs rw
427 275 0:45 / /proc rw,nosuid,nodev,noexec,relatime shared:376 - proc proc rw
347 399 0:35 /systemd-private-deb92f7e7a104342829d585a47744552-apache2.service-ykN6vy/tmp /tmp rw,nosuid,nodev shared:363 master:17 - tmpfs tmpfs rw
463 275 8:3 /var/tmp/systemd-private-deb92f7e7a104342829d585a47744552-apache2.service-KsXgSN/tmp /var/tmp rw,relatime shared:382 master:1 - xfs /dev/sda3 rw
`

const hostMountinfo = `28 33 0:25 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
29 33 0:26 / /proc rw,nosuid,nodev,noexec,relatime shared:11 - proc proc rw
33 2 8:3 / / rw,relatime shared:1 - xfs /dev/sda3 rw
45 33 0:35 / /tmp rw,nosuid,nodev shared:17 - tmpfs tmpfs rw
53 33 8:2 / /boot/efi rw,relatime shared:85 - vfat /dev/sda2 rw
`

// A container: its root is an overlay the host mounts under /var/lib/docker.
const containerMountinfo = `900 800 0:120 / / rw,relatime - overlay overlay rw,lowerdir=...
901 900 0:121 / /proc rw - proc proc rw
`

const dockerHostMountinfo = `33 2 8:3 / / rw,relatime shared:1 - xfs /dev/sda3 rw
700 33 0:120 / /var/lib/docker/overlay2/3f1c/merged rw,relatime - overlay overlay rw
`

func TestTranslate(t *testing.T) {
	apache, host := parseMountinfo([]byte(apacheMountinfo)), parseMountinfo([]byte(hostMountinfo))
	container, dockerHost := parseMountinfo([]byte(containerMountinfo)), parseMountinfo([]byte(dockerHostMountinfo))
	cases := []struct {
		name     string
		ns, host []mount
		in, want string
		ok       bool
	}{
		{"PrivateTmp /var/tmp", apache, host, "/var/tmp/.7625e6d2e",
			"/var/tmp/systemd-private-deb92f7e7a104342829d585a47744552-apache2.service-KsXgSN/tmp/.7625e6d2e", true},
		{"PrivateTmp /tmp, mounted over another /tmp", apache, host, "/tmp/x/y.sh",
			"/tmp/systemd-private-deb92f7e7a104342829d585a47744552-apache2.service-ykN6vy/tmp/x/y.sh", true},
		{"the mount point itself", apache, host, "/var/tmp",
			"/var/tmp/systemd-private-deb92f7e7a104342829d585a47744552-apache2.service-KsXgSN/tmp", true},
		{"shared root file system", apache, host, "/var/www/html/dvwa/f.php", "/var/www/html/dvwa/f.php", true},
		{"prefix is not a parent", apache, host, "/var/tmpfoo", "/var/tmpfoo", true},
		{"not mounted on the host", apache, host, "/dev/shm/x", "", false},
		{"container overlay", container, dockerHost, "/usr/bin/xmrig",
			"/var/lib/docker/overlay2/3f1c/merged/usr/bin/xmrig", true},
		{"relative path", apache, host, "tmp/x", "", false},
	}
	for _, c := range cases {
		got, ok := translate(c.in, c.ns, c.host)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: translate(%q) = %q, %v; want %q, %v", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseMountinfoUnescapes(t *testing.T) {
	m := parseMountinfo([]byte(`1 0 8:3 /a\040b /mnt/my\040dir\134x rw - xfs /dev/sda3 rw` + "\n" + "short line\n"))
	if len(m) != 1 || m[0].root != "/a b" || m[0].point != `/mnt/my dir\x` || m[0].dev != "8:3" {
		t.Fatalf("got %+v", m)
	}
	if got := unescape(`/x\04`); got != `/x\04` {
		t.Fatalf("a truncated escape stays as it is: %q", got)
	}
}
