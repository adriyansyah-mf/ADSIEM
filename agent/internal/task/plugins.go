// agent/internal/task/plugins.go
package task

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Plugin collects rows for a live-response flow source. It must call emit once
// per row, stop as soon as emit returns an error, and check ctx in long loops
// so flow timeouts and cancels actually stop the work.
type Plugin func(ctx context.Context, args map[string]any, emit func(map[string]any) error) error

// Plugins is the registry the server compiles artifacts against
// (server-api/app/services/flow_artifacts.py PLUGINS must match).
var Plugins = map[string]Plugin{
	"info":        pluginInfo,
	"pslist":      pluginPslist,
	"netstat":     pluginNetstat,
	"users":       pluginUsers,
	"glob":        pluginGlob,
	"hash":        pluginHash,
	"read_file":   pluginReadFile,
	"persistence": pluginPersistence,
	"dmesg":       pluginDmesg,
	"open_files":  pluginOpenFiles,
	"yara":        pluginYara,
	"memyara":     pluginMemYara,
	"memrwx":      pluginMemRWX,
	// one file's features for malware triage and YARA drafting (plugins_filefeatures.go)
	"filefeatures": pluginFileFeatures,
	// operator-approved commands only, never in an artifact (plugins_exec.go)
	"exec": pluginExec,
	// Windows-only (plugins_windows*.go); elsewhere they say so
	"eventlog": unsupported("eventlog queries the Windows Event Log; on Linux search the logs in the SIEM"),
	"services": unsupported("services lists Windows services; on Linux use the persistence plugin (systemd units)"),
	"programs": unsupported("programs lists Windows installed programs; on Linux see Hygiene → packages"),
}

func unsupported(msg string) Plugin {
	return func(context.Context, map[string]any, func(map[string]any) error) error {
		return fmt.Errorf("%s", msg)
	}
}

// ─── Arg helpers ─────────────────────────────────────────────────

func argString(args map[string]any, key, def string) string {
	if v, ok := args[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return def
}

func argInt(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func argBool(args map[string]any, key string, def bool) bool {
	switch v := args[key].(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func argStrings(args map[string]any, key string) []string {
	switch v := args[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case []string:
		return v
	}
	return nil
}

// ─── info ────────────────────────────────────────────────────────

func pluginInfo(_ context.Context, _ map[string]any, emit func(map[string]any) error) error {
	hostname, _ := os.Hostname()
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	osRelease := ""
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				osRelease = strings.Trim(v, `"`)
			}
		}
	}
	uptime := 0
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			secs, _ := strconv.ParseFloat(f[0], 64)
			uptime = int(secs)
		}
	}
	return emit(map[string]any{
		"Hostname":  hostname,
		"OS":        runtime.GOOS,
		"OSRelease": osRelease,
		"Kernel":    strings.TrimSpace(string(kernel)),
		"Arch":      runtime.GOARCH,
		"UptimeSec": uptime,
	})
}

// ─── pslist ──────────────────────────────────────────────────────

func usernamesByUID() map[string]string {
	names := map[string]string{}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return names
	}
	for _, line := range strings.Split(string(data), "\n") {
		if parts := strings.Split(line, ":"); len(parts) >= 3 {
			names[parts[2]] = parts[0]
		}
	}
	return names
}

func pluginPslist(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
	procs, err := collectProcesses()
	if err != nil {
		return err
	}
	users := usernamesByUID()
	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			return err
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.PID))
		rss, _ := strconv.Atoi(p.VmRSSKB)
		if err := emit(map[string]any{
			"Pid":         p.PID,
			"Ppid":        p.PPID,
			"Name":        p.Name,
			"Exe":         exe,
			"CommandLine": p.Cmdline,
			"Uid":         p.UID,
			"Username":    users[p.UID],
			"State":       p.State,
			"Threads":     p.Threads,
			"RssKb":       rss,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ─── netstat ─────────────────────────────────────────────────────

func socketOwners(ctx context.Context) map[string][2]string {
	owners := map[string][2]string{} // inode → {pid, process}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				owners[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = [2]string{e.Name(), procName(pid)}
			}
		}
	}
	return owners
}

// parseProcAddr decodes /proc/net "0100007F:0016"-style addresses (IPv4 and IPv6).
func parseProcAddr(s string) (string, int) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return s, 0
	}
	port, _ := strconv.ParseInt(portHex, 16, 32)
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return ipHex, int(port)
	}
	// the kernel prints each 32-bit word in host (little-endian) order
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		for i := 0; i < 4; i++ {
			ip[w+i] = raw[w+3-i]
		}
	}
	return ip.String(), int(port)
}

func pluginNetstat(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
	owners := socketOwners(ctx)
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/net/" + proto)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // header
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				f.Close()
				return err
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			laddr, lport := parseProcAddr(fields[1])
			raddr, rport := parseProcAddr(fields[2])
			state := tcpState(fields[3])
			if strings.HasPrefix(proto, "udp") {
				state = map[string]string{"07": "UNCONN", "01": "ESTABLISHED"}[strings.ToUpper(fields[3])]
			}
			owner := owners[fields[9]]
			if err := emit(map[string]any{
				"Proto":      proto,
				"LocalAddr":  laddr,
				"LocalPort":  lport,
				"RemoteAddr": raddr,
				"RemotePort": rport,
				"State":      state,
				"Uid":        fields[7],
				"Inode":      fields[9],
				"Pid":        owner[0],
				"Process":    owner[1],
			}); err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}
	return nil
}

// ─── users ───────────────────────────────────────────────────────

func pluginUsers(_ context.Context, _ map[string]any, emit func(map[string]any) error) error {
	users, err := collectUsersList()
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := emit(map[string]any{
			"Username": u.Username, "Uid": u.UID, "Gid": u.GID,
			"Description": u.Info, "Home": u.HomeDir, "Shell": u.Shell,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ─── glob / hash ─────────────────────────────────────────────────

// globRegexp turns a glob into a regexp: `**` crosses directories, `*` and `?` don't.
func globRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			if i+2 < len(pattern) && pattern[i+1] == '*' && pattern[i+2] == '/' {
				b.WriteString("(?:.*/)?") // "**/": zero or more directories
				i += 2
			} else if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '{':
			// {exe,dll,ps1}: one of the comma-separated literals (no nesting)
			end := strings.IndexByte(pattern[i:], '}')
			if end < 0 {
				b.WriteString(regexp.QuoteMeta("{"))
				continue
			}
			alts := strings.Split(pattern[i+1:i+end], ",")
			for j, a := range alts {
				alts[j] = regexp.QuoteMeta(a)
			}
			b.WriteString("(?:" + strings.Join(alts, "|") + ")")
			i += end
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// globRoot is the longest leading directory of the pattern without wildcards.
func globRoot(pattern string) string {
	idx := strings.IndexAny(pattern, "*?{")
	if idx < 0 {
		return pattern
	}
	return filepath.Dir(pattern[:idx+1])
}

// Pseudo filesystems hold "regular" files whose reads block forever (/proc/kmsg)
// or never end; a walk only enters them when its root is inside one.
var pseudoFS = []string{"/proc", "/sys", "/dev"}

func skipPseudoFS(root, p string) bool {
	for _, dir := range pseudoFS {
		if p == dir && root != dir && !strings.HasPrefix(root, dir+"/") {
			return true
		}
	}
	return false
}

// ctxReader stops a long read (hashing a big file) once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// walkGlobs calls fn for every path matching any glob, each path at most once.
func walkGlobs(ctx context.Context, globs []string, fn func(path string, d fs.DirEntry) error) error {
	seen := map[string]bool{}
	for _, g := range globs {
		// Matching works on forward slashes, so C:\Users\*\Downloads\** works too.
		g = filepath.ToSlash(g)
		if !filepath.IsAbs(filepath.FromSlash(g)) {
			return fmt.Errorf("glob %q must be an absolute path", g)
		}
		re, err := globRegexp(g)
		if err != nil {
			return fmt.Errorf("bad glob %q: %w", g, err)
		}
		if runtime.GOOS == "windows" { // NTFS paths are case-insensitive
			re = regexp.MustCompile("(?i)" + re.String())
		}
		recursive := strings.Contains(g, "**")
		depth := strings.Count(g, "/")
		root := filepath.FromSlash(globRoot(g))
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != nil {
				return nil // unreadable entry: skip, keep walking
			}
			if d.IsDir() && skipPseudoFS(root, p) {
				return fs.SkipDir
			}
			sp := filepath.ToSlash(p)
			if !seen[p] && re.MatchString(sp) {
				seen[p] = true
				if err := fn(p, d); err != nil {
					return err
				}
			}
			// without ** nothing deeper than the pattern's own depth can match
			if d.IsDir() && p != root && !recursive && strings.Count(sp, "/") >= depth {
				return fs.SkipDir
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

var errStopWalk = fmt.Errorf("max results reached")

func pluginGlob(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	limit := argInt(args, "max_results", 10000)
	count := 0
	err := walkGlobs(ctx, argStrings(args, "globs"), func(p string, d fs.DirEntry) error {
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if err := emit(map[string]any{
			"Path": p, "Name": d.Name(), "Size": info.Size(), "Mode": info.Mode().String(),
			"Uid": fileOwnerUID(info), "ModTime": info.ModTime().UTC().Format("2006-01-02T15:04:05Z"), "IsDir": d.IsDir(),
		}); err != nil {
			return err
		}
		if count++; count >= limit {
			return errStopWalk
		}
		return nil
	})
	if err == errStopWalk {
		return nil
	}
	return err
}

func pluginHash(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	maxSize := int64(argInt(args, "max_size", 100*1024*1024))
	return walkGlobs(ctx, argStrings(args, "globs"), func(p string, d fs.DirEntry) error {
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSize {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		m, s1, s256 := md5.New(), sha1.New(), sha256.New()
		if _, err := io.Copy(io.MultiWriter(m, s1, s256), ctxReader{ctx, f}); err != nil {
			return ctx.Err() // nil for a plain read error: skip the file, keep going
		}
		return emit(map[string]any{
			"Path": p, "Size": info.Size(),
			"MD5":    hex.EncodeToString(m.Sum(nil)),
			"SHA1":   hex.EncodeToString(s1.Sum(nil)),
			"SHA256": hex.EncodeToString(s256.Sum(nil)),
		})
	})
}

// ─── read_file ───────────────────────────────────────────────────

func pluginReadFile(_ context.Context, args map[string]any, emit func(map[string]any) error) error {
	path := argString(args, "path", "")
	if path == "" {
		return fmt.Errorf("path is required")
	}
	maxBytes := int64(argInt(args, "max_bytes", 1024*1024))
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return emit(map[string]any{
		"Path":      path,
		"Size":      info.Size(),
		"Truncated": info.Size() > int64(len(data)),
		"SHA256":    hex.EncodeToString(sum[:]), // of the bytes returned
		"Encoding":  "base64",
		"Data":      base64.StdEncoding.EncodeToString(data),
	})
}

// ─── persistence / dmesg / open_files ────────────────────────────

func pluginPersistence(ctx context.Context, _ map[string]any, emit func(map[string]any) error) error {
	items, err := collectPersistenceCheck()
	if err != nil {
		return err
	}
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		modTime := ""
		if info, err := os.Stat(it.Path); err == nil {
			modTime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		if err := emit(map[string]any{
			"Category": it.Category, "Path": it.Path, "ModTime": modTime, "Content": it.Content,
		}); err != nil {
			return err
		}
	}
	return nil
}

func pluginDmesg(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	lines := argInt(args, "lines", 200)
	out, err := exec.CommandContext(ctx, "dmesg", "-T", "--level=err,warn,crit,alert,emerg").Output()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		data, ferr := os.ReadFile("/var/log/kern.log")
		if ferr != nil {
			return fmt.Errorf("dmesg unavailable (%v) and no /var/log/kern.log", err)
		}
		out = data
	}
	all := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	for _, line := range all {
		if line == "" {
			continue
		}
		if err := emit(map[string]any{"Line": line}); err != nil {
			return err
		}
	}
	return nil
}

func pluginOpenFiles(ctx context.Context, args map[string]any, emit func(map[string]any) error) error {
	files, err := collectOpenFiles(argInt(args, "limit", 2000))
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(map[string]any{"Pid": f.PID, "Process": f.Process, "Fd": f.FD, "Path": f.Path}); err != nil {
			return err
		}
	}
	return nil
}
