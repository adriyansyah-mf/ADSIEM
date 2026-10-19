package firewall

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Action string

const (
	ActionBlock Action = "block"
	ActionAllow Action = "allow"
)

type Direction string

const (
	DirInbound  Direction = "inbound"
	DirOutbound Direction = "outbound"
	DirBoth     Direction = "both"
)

type Rule struct {
	ID        string        `json:"id"`
	Action    Action        `json:"action"`
	CIDR      string        `json:"cidr"`
	Proto     string        `json:"proto"`
	Port      int           `json:"port"`
	Direction Direction     `json:"direction"`
	TTL       time.Duration `json:"ttl"`
	Reason    string        `json:"reason"`
	CreatedAt time.Time     `json:"created_at"`
}

func (r Rule) normalize() Rule {
	if r.Action == "" {
		r.Action = ActionBlock
	}
	if r.Proto == "" {
		r.Proto = "any"
	}
	r.Proto = strings.ToLower(r.Proto)
	if r.Direction == "" {
		r.Direction = DirBoth
	}
	if r.ID == "" {
		r.ID = r.Key()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	return r
}

func (r Rule) Validate() error {
	switch r.Action {
	case ActionBlock, ActionAllow:
	default:
		return fmt.Errorf("invalid action %q: want block or allow", r.Action)
	}

	ip, ipnet, err := net.ParseCIDR(r.CIDR)
	if err != nil {
		single := net.ParseIP(r.CIDR)
		if single == nil {
			return fmt.Errorf("invalid cidr %q", r.CIDR)
		}
		if single.To4() == nil {
			return fmt.Errorf("only IPv4 is supported, got %q", r.CIDR)
		}
	} else if ip.To4() == nil || ipnet.IP.To4() == nil {
		return fmt.Errorf("only IPv4 is supported, got %q", r.CIDR)
	}

	switch r.Proto {
	case "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("invalid proto %q: want any, tcp, udp or icmp", r.Proto)
	}

	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("invalid port %d: want 0-65535", r.Port)
	}
	if r.Port > 0 && (r.Proto == "any" || r.Proto == "icmp") {
		return fmt.Errorf("port %d requires proto tcp or udp", r.Port)
	}

	switch r.Direction {
	case DirInbound, DirOutbound, DirBoth:
	default:
		return fmt.Errorf("invalid direction %q", r.Direction)
	}

	if r.TTL < 0 {
		return fmt.Errorf("invalid ttl %s", r.TTL)
	}
	return nil
}

func (r Rule) Key() string {
	parts := []string{
		string(r.Action),
		r.CIDR,
		string(r.Direction),
	}
	if r.Port > 0 {
		parts = append(parts, r.Proto, fmt.Sprint(r.Port))
	}
	return strings.Join(parts, "|")
}

func (r Rule) IsPortScoped() bool {
	return r.Port > 0
}

func (r Rule) TTLSeconds() int {
	if r.TTL <= 0 {
		return 0
	}
	return int(r.TTL / time.Second)
}

func ParseRule(raw map[string]any) (Rule, error) {
	var r Rule

	if v, ok := raw["id"].(string); ok {
		r.ID = v
	}
	if v, ok := raw["action"].(string); ok {
		r.Action = Action(v)
	}
	if v, ok := raw["ip"].(string); ok && r.CIDR == "" {
		r.CIDR = v
	}
	if v, ok := raw["cidr"].(string); ok && v != "" {
		r.CIDR = v
	}
	if v, ok := raw["proto"].(string); ok {
		r.Proto = v
	}
	if v, ok := raw["direction"].(string); ok {
		r.Direction = Direction(v)
	}
	if v, ok := raw["reason"].(string); ok {
		r.Reason = v
	}
	if v, ok := raw["port"].(float64); ok {
		r.Port = int(v)
	}
	if v, ok := raw["duration_seconds"].(float64); ok {
		r.TTL = time.Duration(v) * time.Second
	}
	if v, ok := raw["ttl_seconds"].(float64); ok {
		r.TTL = time.Duration(v) * time.Second
	}

	if r.CIDR == "" {
		return Rule{}, fmt.Errorf("cidr or ip is required")
	}

	r = r.normalize()
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}
