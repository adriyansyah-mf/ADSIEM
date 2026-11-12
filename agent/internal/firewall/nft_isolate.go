package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// isolateTable holds the isolation: its own inet table (IPv4 and IPv6), base
// chains that drop by default and run before siem_fw's (priority -10), so the
// established/related accept there can't let an open C2 connection through.
// A packet must be accepted by every base chain on its hook, so this table
// alone decides while it exists.
const isolateTable = "siem_isolate"

// nftIsolateScript replaces the isolation table in one nft transaction
// (create-if-missing, delete, define): never half applied.
func nftIsolateScript(allow []string) string {
	v4, v6 := splitFamilies(allow)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", isolateTable, isolateTable)
	fmt.Fprintf(&b, "table inet %s {\n", isolateTable)
	writeSet(&b, "allow4", "ipv4_addr", v4)
	writeSet(&b, "allow6", "ipv6_addr", v6)
	b.WriteString(`	chain input {
		type filter hook input priority -10; policy drop;
		iif "lo" accept
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
	}
	chain output {
		type filter hook output priority -10; policy drop;
		oif "lo" accept
		ip daddr @allow4 accept
		ip6 daddr @allow6 accept
		udp sport 68 udp dport 67 accept
		udp sport 546 udp dport 547 accept
	}
}
`)
	return b.String()
}

func writeSet(b *strings.Builder, name, typ string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s; flags interval; auto-merge;\n", name, typ)
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

// splitFamilies sorts CIDRs and bare IPs into IPv4 and IPv6, dropping
// anything that isn't one.
func splitFamilies(allow []string) (v4, v6 []string) {
	for _, c := range allow {
		ip, n, err := parseTarget(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, n.String())
		} else if ip.To16() != nil {
			v6 = append(v6, n.String())
		}
	}
	return v4, v6
}

func (b *NftBackend) Isolate(allow []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeoutMs)
	defer cancel()
	return b.script(ctx, nftIsolateScript(allow))
}

func (b *NftBackend) Unisolate() error {
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeoutMs)
	defer cancel()
	return b.script(ctx, fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", isolateTable, isolateTable))
}

// execNftScript runs an nft script from stdin: one atomic transaction.
func execNftScript(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, nftBinary, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f -: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
