package credwatch

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct{ path, kind string }{
		{`C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data`, BrowserPasswords},
		{`C:\Users\alice\AppData\Local\Google\Chrome\User Data\Profile 2\Network\Cookies`, BrowserCookies},
		{`C:\Users\alice\AppData\Local\Google\Chrome\User Data\Local State`, BrowserKey},
		{`C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Web Data`, BrowserPasswords},
		{`C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log`, WalletExtension},
		{`C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\chrome-extension_bfnaelmomeimhlpmgjnjophhpkkoljpa_0.indexeddb.leveldb\000005.ldb`, WalletExtension},
		{`C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\x1y2.default-release\logins.json`, BrowserPasswords},
		{`C:\Users\alice\AppData\Roaming\Exodus\exodus.wallet\seed.seco`, WalletFile},
		{`C:\Users\alice\.ssh\id_ed25519`, SSHKey},
		{`C:\Users\alice\.aws\credentials`, CloudCredentials},
		{"/home/bob/.config/google-chrome/Default/Login Data", BrowserPasswords},
		{"/home/bob/.config/BraveSoftware/Brave-Browser/Default/Network/Cookies", BrowserCookies},
		{"/home/bob/.config/chromium/Local State", BrowserKey},
		{"/home/bob/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log", WalletExtension},
		{"/home/bob/.mozilla/firefox/abcd.default-release/key4.db", BrowserPasswords},
		{"/home/bob/.ssh/id_rsa", SSHKey},
		{"/home/bob/.config/solana/id.json", WalletFile},
		{"/home/bob/.ethereum/keystore/UTC--2026-01-01", WalletFile},
		{"/home/bob/.kube/config", CloudCredentials},
		{"/home/bob/.git-credentials", TokenFile},
		{"/home/bob/.npmrc", TokenFile},
		{"/root/.gnupg/private-keys-v1.d/ABCD.key", GPGKey},
	}
	for _, c := range cases {
		if k, ok := Classify(c.path); !ok || k != c.kind {
			t.Errorf("%s: %q %v, want %q", c.path, k, ok, c.kind)
		}
	}
	for _, p := range []string{
		`C:\Users\alice\.ssh\id_ed25519.pub`, `C:\Users\alice\.ssh\known_hosts`, "/home/bob/.ssh/config",
		`C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Preferences`,
		`C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\aapocclcgogkmnckokdopfmhonfmgoek\000003.log`,
		"/home/bob/project/Login Data", "/usr/lib/x86_64-linux-gnu/libc.so.6", `C:\Windows\System32\kernel32.dll`,
		"/home/bob/.config/google-chrome/Default/History",
	} {
		if k, ok := Classify(p); ok {
			t.Errorf("%s: classified %q", p, k)
		}
	}
}

func TestExpected(t *testing.T) {
	yes := [][2]string{
		{BrowserPasswords, `C:\Program Files\Google\Chrome\Application\chrome.exe`},
		{BrowserCookies, "/opt/google/chrome/chrome"},
		{BrowserKey, "/usr/lib/firefox/firefox-bin"},
		{WalletExtension, `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`},
		{SSHKey, "/usr/bin/ssh"},
		{SSHKey, `C:\Program Files\Git\usr\bin\ssh.exe`},
		{CloudCredentials, "/usr/local/bin/aws"},
		{TokenFile, "/usr/bin/git"},
		{BrowserPasswords, `C:\Windows\System32\SearchProtocolHost.exe`},
		{SSHKey, "/usr/bin/restic"},
		{BrowserPasswords, "/opt/google/chrome-beta/chrome-beta"},
	}
	for _, c := range yes {
		if !Expected(c[0], c[1]) {
			t.Errorf("%s by %s: not expected", c[0], c[1])
		}
	}
	no := [][2]string{
		{BrowserPasswords, "/usr/bin/node"},
		{BrowserKey, `C:\Users\alice\AppData\Local\Temp\x.exe`},
		{WalletExtension, "/usr/bin/python3.11"},
		{SSHKey, `C:\Program Files\nodejs\node.exe`},
		{CloudCredentials, "/usr/bin/python3"},
		{BrowserPasswords, "/usr/bin/ssh"}, // owns keys, not browser data
		{BrowserPasswords, ""},
	}
	for _, c := range no {
		if Expected(c[0], c[1]) {
			t.Errorf("%s by %s: expected", c[0], c[1])
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	if !l.Allow(1, SSHKey) || l.Allow(1, SSHKey) || !l.Allow(1, BrowserKey) || !l.Allow(2, SSHKey) {
		t.Fatal("first per (pid, kind) only")
	}
	now = now.Add(2 * time.Minute)
	if !l.Allow(1, SSHKey) {
		t.Fatal("again after the window")
	}
}

func TestLine(t *testing.T) {
	got := Line(BrowserPasswords, `C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data`, `C:\x\"n".exe`, 7, 3, `CORP\a`)
	want := `event=credential_access store=browser_passwords target="C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" image="C:\\x\\\"n\".exe" pid=7 ppid=3 user="CORP\\a"`
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}
