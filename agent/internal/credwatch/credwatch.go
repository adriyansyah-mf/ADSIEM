// Package credwatch reports programs opening credential stores they do not
// own: a browser's saved passwords, cookies and master key, crypto wallet
// extensions and wallet files, SSH private keys, cloud and registry tokens.
// Infostealers and the second stage of a "coding test" from a fake recruiter
// (a developer runs the project; its code collects these and sends them out)
// read exactly these files, while the programs that own them (the browser,
// ssh, the cloud CLI) are expected to.
//
// The sensors feed it: Windows from the Kernel-File opens winsensor already
// receives, Linux from fanotify marks on the stores (watch_linux.go). Lines
// have log type credential_access on both (decoders/credential_access.yaml).
package credwatch

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// LogType of the lines (decoders/credential_access.yaml).
const LogType = "credential_access"

// Kinds of store.
const (
	BrowserPasswords = "browser_passwords"
	BrowserCookies   = "browser_cookies"
	BrowserKey       = "browser_master_key" // Chromium's Local State: decrypts the two above
	WalletExtension  = "wallet_extension"
	WalletFile       = "wallet_file"
	SSHKey           = "ssh_key"
	CloudCredentials = "cloud_credentials"
	TokenFile        = "token_file" // .git-credentials, .npmrc, .netrc, .pypirc
	GPGKey           = "gpg_key"
)

// norm: forward slashes, lower case (Windows paths fold case; the Linux
// names matched are lower case or matched lower-cased on purpose).
func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

var chromiumRoots = []string{
	"/appdata/local/google/chrome/user data/", "/appdata/local/microsoft/edge/user data/",
	"/appdata/local/bravesoftware/brave-browser/user data/", "/appdata/local/vivaldi/user data/",
	"/appdata/local/chromium/user data/", "/appdata/roaming/opera software/opera stable/",
	"/appdata/local/yandex/yandexbrowser/user data/",
	"/.config/google-chrome/", "/.config/google-chrome-beta/", "/.config/chromium/",
	"/.config/bravesoftware/brave-browser/", "/.config/microsoft-edge/", "/.config/vivaldi/", "/.config/opera/",
}

var firefoxRoots = []string{"/appdata/roaming/mozilla/firefox/profiles/", "/.mozilla/firefox/", "/snap/firefox/common/.mozilla/firefox/"}

// WalletExtensions are browser extension ids of crypto wallets (their data
// lives under Local Extension Settings/<id> and IndexedDB/chrome-extension_<id>_0).
var WalletExtensions = map[string]string{
	"nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask", "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
	"hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet", "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
	"fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet", "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
	"mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet", "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
	"dmkamcknogkgcdfhhbddcghachkejeap": "Keplr", "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
	"aeachknmefphepccionboohckonoeemg": "Coin98", "bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
	"fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin", "ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask (Edge)",
	"jblndlipeogpafnldhgmapagcccfchpi": "Kaikas", "nphplpgoakhhjchkkhmiggakijnkhfnd": "TON Wallet",
}

var walletFiles = []string{
	"/appdata/roaming/exodus/exodus.wallet/", "/.config/exodus/exodus.wallet/",
	"/appdata/roaming/electrum/wallets/", "/.electrum/wallets/",
	"/appdata/roaming/ethereum/keystore/", "/.ethereum/keystore/",
	"/appdata/roaming/atomic/local storage/", "/.config/atomic/local storage/",
	"/.config/solana/id.json", "/appdata/roaming/bitcoin/wallets/", "/.bitcoin/wallets/",
	"/appdata/roaming/bitcoin/wallet.dat", "/.bitcoin/wallet.dat",
}

var cloudFiles = []string{
	"/.aws/credentials", "/.aws/sso/cache/", "/.azure/msal_token_cache", "/.azure/accesstokens.json",
	"/.config/gcloud/credentials.db", "/.config/gcloud/access_tokens.db",
	"/.config/gcloud/application_default_credentials.json",
	"/appdata/roaming/gcloud/credentials.db", "/appdata/roaming/gcloud/application_default_credentials.json",
	"/.kube/config", "/.docker/config.json",
}

var tokenFiles = []string{"/.git-credentials", "/.npmrc", "/.netrc", "/_netrc", "/.pypirc", "/.config/gh/hosts.yml",
	"/appdata/roaming/github cli/hosts.yml"}

// Classify returns the kind of credential store path is in, if any.
func Classify(path string) (kind string, ok bool) {
	p := norm(path)
	if !strings.Contains(p, "/.") && !strings.Contains(p, "/appdata/") && !strings.Contains(p, "/snap/") {
		return "", false // fast path: every store is in a dot folder or AppData
	}
	for _, r := range chromiumRoots {
		i := strings.Index(p, r)
		if i < 0 {
			continue
		}
		rest := p[i+len(r):]
		switch {
		case rest == "local state":
			return BrowserKey, true
		case strings.HasSuffix(rest, "/login data"), strings.HasSuffix(rest, "/login data for account"),
			strings.HasSuffix(rest, "/web data"):
			return BrowserPasswords, true
		case strings.HasSuffix(rest, "/network/cookies"), strings.HasSuffix(rest, "/cookies"):
			return BrowserCookies, true
		}
		for _, marker := range []string{"/local extension settings/", "/indexeddb/chrome-extension_", "/sync extension settings/"} {
			if j := strings.Index(rest, marker); j >= 0 {
				id := rest[j+len(marker):]
				if len(id) >= 32 {
					if _, ok := WalletExtensions[id[:32]]; ok {
						return WalletExtension, true
					}
				}
			}
		}
		return "", false
	}
	for _, r := range firefoxRoots {
		if i := strings.Index(p, r); i >= 0 {
			switch {
			case strings.HasSuffix(p, "/logins.json"), strings.HasSuffix(p, "/key4.db"):
				return BrowserPasswords, true
			case strings.HasSuffix(p, "/cookies.sqlite"):
				return BrowserCookies, true
			}
			return "", false
		}
	}
	for _, w := range walletFiles {
		if strings.Contains(p, w) {
			return WalletFile, true
		}
	}
	if i := strings.Index(p, "/.ssh/"); i >= 0 {
		name := p[i+len("/.ssh/"):]
		if strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub") && !strings.Contains(name, "/") {
			return SSHKey, true
		}
		return "", false
	}
	for _, c := range cloudFiles {
		if strings.Contains(p, c) {
			return CloudCredentials, true
		}
	}
	for _, t := range tokenFiles {
		if strings.HasSuffix(p, t) {
			return TokenFile, true
		}
	}
	if strings.Contains(p, "/.gnupg/private-keys-v1.d/") {
		return GPGKey, true
	}
	return "", false
}

// program: the lower-cased file name without .exe.
func program(image string) string {
	if i := strings.LastIndexAny(image, `/\`); i >= 0 {
		image = image[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(image), ".exe")
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

var browsers = set("chrome", "msedge", "brave", "opera", "vivaldi", "chromium", "chromium-browser", "google-chrome",
	"google-chrome-stable", "microsoft-edge", "microsoft-edge-stable", "yandex", "firefox", "firefox-esr",
	"firefox-bin", "librewolf", "chrome_crashpad_handler", "msedge_crashpad_handler", "elevation_service",
	"chrome_pwa_launcher", "googleupdate", "microsoftedgeupdate")

// owners: who is expected to open a kind of store.
var owners = map[string]map[string]bool{
	BrowserPasswords: browsers, BrowserCookies: browsers, BrowserKey: browsers, WalletExtension: browsers,
	WalletFile: set("exodus", "electrum", "atomic wallet", "atomic", "geth", "solana", "solana-keygen", "bitcoin-qt",
		"bitcoind", "anchor"),
	SSHKey: set("ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp", "git", "git-remote-https", "gpg-agent",
		"putty", "pageant", "plink", "winscp", "mobaxterm", "termius", "code", "cursor", "rsync", "ansible"),
	CloudCredentials: set("aws", "az", "gcloud", "kubectl", "docker", "docker-credential-desktop",
		"docker-credential-osxkeychain", "docker-credential-wincred", "helm", "terraform", "k9s", "lens", "eksctl",
		"kubelogin", "com.docker.backend", "docker desktop", "minikube", "kind"),
	TokenFile: set("git", "git-credential-manager", "git-credential-store", "gh", "npm", "pnpm", "yarn", "pip",
		"pip3", "twine", "curl", "wget", "code"),
	GPGKey: set("gpg", "gpg2", "gpg-agent", "gpgsm", "kleopatra"),
}

// readers: programs that read everything (indexers, backup, sync,
// antivirus) and are never reported.
var readers = set("searchindexer", "searchprotocolhost", "searchfilterhost", "msmpeng", "mssense", "mpdefendercoreservice",
	"baloo_file", "baloo_file_extractor", "tracker-miner-fs-3", "tracker-extract-3", "restic", "borg", "rsync",
	"duplicati", "rclone", "syncthing", "dropbox", "onedrive", "googledrivefs", "backblaze", "bzfilelist",
	"veeamagent", "clamd", "clamscan", "freshclam", "updatedb", "mlocate", "plocate", "deja-dup", "duplicity",
	"timeshift", "siem-agent", "explorer", "dllhost")

// Expected reports whether image owns (or, as an indexer or backup tool,
// reads everything including) a store of kind.
func Expected(kind, image string) bool {
	p := program(image)
	if p == "" {
		return false
	}
	if readers[p] || owners[kind][p] {
		return true
	}
	// versioned names: python3.11 never owns anything; chrome-beta, firefox-developer-edition do
	for b := range browsers {
		if (kind == BrowserPasswords || kind == BrowserCookies || kind == BrowserKey || kind == WalletExtension) &&
			strings.HasPrefix(p, b+"-") {
			return true
		}
	}
	return false
}

// Limiter reports one (process, kind) once per window: an infostealer reads
// a profile's files in a burst.
type Limiter struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
	now    func() time.Time
}

// NewLimiter with a window (0: 10 minutes).
func NewLimiter(window time.Duration) *Limiter {
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &Limiter{window: window, seen: map[string]time.Time{}, now: time.Now}
}

// Allow reports whether (pid, kind) is reported now.
func (l *Limiter) Allow(pid uint32, kind string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := fmt.Sprint(pid, "\x00", kind)
	if t, ok := l.seen[key]; ok && now.Sub(t) < l.window {
		return false
	}
	if len(l.seen) > 4096 {
		for k, t := range l.seen {
			if now.Sub(t) >= l.window {
				delete(l.seen, k)
			}
		}
		if len(l.seen) > 4096 {
			l.seen = map[string]time.Time{}
		}
	}
	l.seen[key] = now
	return true
}

func kv(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// Line formats one access as decoders/credential_access.yaml reads it.
func Line(kind, path, image string, pid, ppid uint32, user string) string {
	return fmt.Sprintf("event=credential_access store=%s target=%s image=%s pid=%d ppid=%d user=%s",
		kind, kv(path), kv(image), pid, ppid, kv(user))
}
