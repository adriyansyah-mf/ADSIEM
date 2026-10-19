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
	if err := b.nftExec(nftApplyArgv(rule)...); err != nil {
		return fmt.Errorf("apply %s: %w", rule.ID, err)
	}
	return nil
}

func (b *NftBackend) Remove(rule Rule) error {
	err := b.nftExec(nftRemoveArgv(rule)...)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no such") || strings.Contains(msg, "does not exist") {
		return nil
	}
	return fmt.Errorf("remove %s: %w", rule.ID, err)
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

func setElement(rule Rule) (key string, set string) {
	inbound := rule.Direction == DirInbound || rule.Direction == DirBoth
	outboundOnly := rule.Direction == DirOutbound

	if rule.IsPortScoped() {
		proto := rule.Proto
		if proto == "any" {
			proto = "tcp"
		}
		key = fmt.Sprintf("%s . %s . %d", rule.CIDR, proto, rule.Port)
		if outboundOnly {
			return key, setSvcOut
		}
		return key, setSvcIn
	}

	if outboundOnly {
		return rule.CIDR, setIPOut
	}
	_ = inbound
	return rule.CIDR, setIPIn
}

func nftApplyArgv(rule Rule) []string {
	key, set := setElement(rule)
	elem := "{ " + key + nftTimeoutSuffix(rule) + " }"
	return []string{"add", "element", "inet", tableName, set, elem}
}

func nftRemoveArgv(rule Rule) []string {
	key, set := setElement(rule)
	return []string{"delete", "element", "inet", tableName, set, "{ " + key + " }"}
}

func nftTimeoutSuffix(rule Rule) string {
	secs := rule.TTLSeconds()
	if secs <= 0 {
		return ""
	}
	return " timeout " + strconv.Itoa(secs) + "s"
}
