package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	tableName    = "siem_fw"
	setIPIn      = "blocked_v4_in"
	setIPOut     = "blocked_v4_out"
	setSvcIn     = "blocked_svc_in"
	setSvcOut    = "blocked_svc_out"
	chainIn      = "input"
	chainOut     = "output"
	nftBinary    = "nft"
	nftTimeoutMs = 10 * time.Second
)

type runner func(ctx context.Context, argv ...string) (string, error)

type NftBackend struct {
	run runner
}

func NewNft() *NftBackend {
	return &NftBackend{run: execNft}
}

func NewNftWithRunner(r runner) *NftBackend {
	return &NftBackend{run: r}
}

func (b *NftBackend) Name() string { return "nft" }

func (b *NftBackend) Available() bool {
	if _, err := exec.LookPath(nftBinary); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeoutMs)
	defer cancel()
	if _, err := b.run(ctx, "list", "tables"); err != nil {
		return false
	}
	return true
}

func (b *NftBackend) Ensure() error {
	stmts := []string{
		fmt.Sprintf("add table inet %s", tableName),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr ; flags timeout ; }", tableName, setIPIn),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr ; flags timeout ; }", tableName, setIPOut),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr . inet_proto . inet_service ; flags timeout ; }", tableName, setSvcIn),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr . inet_proto . inet_service ; flags timeout ; }", tableName, setSvcOut),
		fmt.Sprintf("add chain inet %s %s { type filter hook input priority 0 ; policy accept ; }", tableName, chainIn),
		fmt.Sprintf("add rule inet %s %s ct state established,related accept", tableName, chainIn),
		fmt.Sprintf("add rule inet %s %s ip saddr @%s drop", tableName, chainIn, setIPIn),
		fmt.Sprintf("add rule inet %s %s ip saddr . ip protocol . th dport @%s drop", tableName, chainIn, setSvcIn),
		fmt.Sprintf("add chain inet %s %s { type filter hook output priority 0 ; policy accept ; }", tableName, chainOut),
		fmt.Sprintf("add rule inet %s %s ct state established,related accept", tableName, chainOut),
		fmt.Sprintf("add rule inet %s %s ip daddr @%s drop", tableName, chainOut, setIPOut),
		fmt.Sprintf("add rule inet %s %s ip daddr . ip protocol . th dport @%s drop", tableName, chainOut, setSvcOut),
	}
	for _, s := range stmts {
		if err := b.ensureOne(s); err != nil {
			return fmt.Errorf("ensure: %s: %w", s, err)
		}
	}
	return nil
}

func (b *NftBackend) ensureOne(stmt string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeoutMs)
	defer cancel()
	_, err := b.run(ctx, "-f", "-", stmt)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "file exists") || strings.Contains(msg, "already exists") {
		return nil
	}
	return err
}

func (b *NftBackend) Apply(rule Rule) error {
	for _, argv := range nftApplyArgvs(rule) {
		if err := b.nftExec(argv...); err != nil {
			return fmt.Errorf("apply %s: %w", rule.ID, err)
		}
	}
	return nil
}

// Remove deletes the rule's element from every set it belongs in. A missing
// element is not an error: the rule expired, or it was applied before both
// directions were enforced and only sits in the input set.
func (b *NftBackend) Remove(rule Rule) error {
	for _, argv := range nftRemoveArgvs(rule) {
		err := b.nftExec(argv...)
		if err == nil {
			continue
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "no such") || strings.Contains(msg, "does not exist") {
			continue
		}
		return fmt.Errorf("remove %s: %w", rule.ID, err)
	}
	return nil
}

func (b *NftBackend) List() ([]Rule, error) {
	out, err := b.nftExecCapture("list", "table", "inet", tableName)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "no such") || strings.Contains(msg, "does not exist") {
			return nil, nil
		}
		return nil, fmt.Errorf("list table: %w", err)
	}
	return parseNftList(out), nil
}

func (b *NftBackend) Flush() error {
	err := b.nftExec("delete", "table", "inet", tableName)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no such") || strings.Contains(msg, "does not exist") {
		return nil
	}
	return err
}

func (b *NftBackend) nftExec(args ...string) error {
	_, err := b.nftExecCapture(args...)
	return err
}

func (b *NftBackend) nftExecCapture(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeoutMs)
	defer cancel()
	return b.run(ctx, args...)
}

func execNft(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, nftBinary, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		slog.Debug("nft failed", "args", args, "out", text, "err", err)
		return text, fmt.Errorf("nft %s: %s: %w", strings.Join(args, " "), text, err)
	}
	return text, nil
}

// setElements returns the element key of a block rule and the sets it goes in:
// inbound drops traffic from the address, outbound drops connections to it,
// and both goes in the input and the output set.
//
// The nft table only has drop sets, so an allow rule goes in none: whatever is
// not in a set is accepted by the chains' policy, and the guard already
// refuses to block protected addresses. Putting an allow rule in a drop set
// would block exactly the address it is meant to keep reachable (isolate
// allows the SIEM server with DirBoth).
func setElements(rule Rule) (key string, sets []string) {
	if rule.Action != ActionBlock {
		return "", nil
	}
	in, out := setIPIn, setIPOut
	key = rule.CIDR
	if rule.IsPortScoped() {
		proto := rule.Proto
		if proto == "any" {
			proto = "tcp"
		}
		key = fmt.Sprintf("%s . %s . %d", rule.CIDR, proto, rule.Port)
		in, out = setSvcIn, setSvcOut
	}
	switch rule.Direction {
	case DirInbound:
		return key, []string{in}
	case DirOutbound:
		return key, []string{out}
	default: // DirBoth
		return key, []string{in, out}
	}
}

func nftApplyArgvs(rule Rule) [][]string {
	key, sets := setElements(rule)
	argvs := make([][]string, 0, len(sets))
	for _, set := range sets {
		elem := "{ " + key + nftTimeoutSuffix(rule) + " }"
		argvs = append(argvs, []string{"add", "element", "inet", tableName, set, elem})
	}
	return argvs
}

func nftRemoveArgvs(rule Rule) [][]string {
	key, sets := setElements(rule)
	argvs := make([][]string, 0, len(sets))
	for _, set := range sets {
		argvs = append(argvs, []string{"delete", "element", "inet", tableName, set, "{ " + key + " }"})
	}
	return argvs
}

func nftTimeoutSuffix(rule Rule) string {
	secs := rule.TTLSeconds()
	if secs <= 0 {
		return ""
	}
	return " timeout " + strconv.Itoa(secs) + "s"
}
