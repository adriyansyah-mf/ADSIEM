package credwatch

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Target is a path the Linux watcher marks: a directory (its files are
// watched, one level) or a single file.
type Target struct {
	Path string
	Dir  bool
}

var chromiumDirs = []string{".config/google-chrome", ".config/google-chrome-beta", ".config/chromium",
	".config/BraveSoftware/Brave-Browser", ".config/microsoft-edge", ".config/vivaldi", ".config/opera"}

var keyDirs = []string{".ssh", ".aws", ".aws/sso/cache", ".kube", ".docker", ".config/gcloud",
	".gnupg/private-keys-v1.d", ".config/solana", ".ethereum/keystore", ".electrum/wallets",
	".config/Exodus/exodus.wallet", ".config/atomic/Local Storage/leveldb", ".bitcoin", ".bitcoin/wallets", ".config/gh"}

var tokenNames = []string{".git-credentials", ".npmrc", ".netrc", ".pypirc"}

// Targets lists what exists to mark under one home directory.
func Targets(home string) []Target {
	var out []Target
	dir := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, Target{Path: p, Dir: true})
		}
	}
	file := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			out = append(out, Target{Path: p})
		}
	}
	for _, d := range keyDirs {
		dir(filepath.Join(home, d))
	}
	for _, f := range tokenNames {
		file(filepath.Join(home, f))
	}
	for _, c := range chromiumDirs {
		root := filepath.Join(home, c)
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		dir(root) // Local State
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			n := e.Name()
			if !e.IsDir() || (n != "Default" && !strings.HasPrefix(n, "Profile ")) {
				continue
			}
			prof := filepath.Join(root, n)
			dir(prof)                           // Login Data, Web Data, Cookies (older)
			dir(filepath.Join(prof, "Network")) // Cookies
			for id := range WalletExtensions {
				dir(filepath.Join(prof, "Local Extension Settings", id))
				dir(filepath.Join(prof, "IndexedDB", "chrome-extension_"+id+"_0.indexeddb.leveldb"))
			}
		}
	}
	for _, ff := range []string{".mozilla/firefox", "snap/firefox/common/.mozilla/firefox"} {
		root := filepath.Join(home, ff)
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if e.IsDir() && strings.Contains(e.Name(), ".") { // abcd1234.default-release
				dir(filepath.Join(root, e.Name()))
			}
		}
	}
	return out
}

// Homes reads the home directories of root and of login users (uid >= 1000)
// from a passwd file.
func Homes(passwd string) []string {
	f, err := os.Open(passwd)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil || (uid != 0 && (uid < 1000 || uid >= 65534)) {
			continue
		}
		home := parts[5]
		if home == "" || home == "/" || seen[home] {
			continue
		}
		if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
			continue
		}
		seen[home] = true
		out = append(out, home)
	}
	return out
}
