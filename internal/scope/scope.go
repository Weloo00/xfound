package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Allowlist struct {
	entries []entry
}

type entry struct {
	raw      string
	exact    string
	wildcard string
	ip       net.IP
	cidr     *net.IPNet
}

func Load(path string) (Allowlist, error) {
	if path == "" {
		return Allowlist{}, fmt.Errorf("scope file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return Allowlist{}, err
	}
	defer f.Close()

	var entries []entry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		e, err := parseEntry(line)
		if err != nil {
			return Allowlist{}, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return Allowlist{}, err
	}
	if len(entries) == 0 {
		return Allowlist{}, fmt.Errorf("scope file %s has no allowlist entries", path)
	}
	return Allowlist{entries: entries}, nil
}

// SelfScope returns an Allowlist authorizing the given target apex and all of
// its subdomains. Used by `xfound hunt` so a single domain needs no scope file.
func SelfScope(target string) (Allowlist, error) {
	host := normalizeHost(target)
	if host == "" {
		return Allowlist{}, fmt.Errorf("invalid target %q", target)
	}
	return Allowlist{entries: []entry{
		{raw: host, exact: host},
		{raw: "*." + host, wildcard: host},
	}}, nil
}

func (a Allowlist) Allows(target string) bool {
	host := normalizeHost(target)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	for _, e := range a.entries {
		switch {
		case e.exact != "" && host == e.exact:
			return true
		case e.wildcard != "" && strings.HasSuffix(host, "."+e.wildcard):
			return true
		case e.ip != nil && ip != nil && e.ip.Equal(ip):
			return true
		case e.cidr != nil && ip != nil && e.cidr.Contains(ip):
			return true
		}
	}
	return false
}

func parseEntry(raw string) (entry, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if _, cidr, err := net.ParseCIDR(raw); err == nil {
		return entry{raw: raw, cidr: cidr}, nil
	}
	host := normalizeHost(raw)
	if host == "" {
		return entry{}, fmt.Errorf("invalid scope entry %q", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		return entry{raw: raw, ip: ip}, nil
	}
	if strings.HasPrefix(host, "*.") {
		base := strings.TrimPrefix(host, "*.")
		if base == "" {
			return entry{}, fmt.Errorf("invalid wildcard entry %q", raw)
		}
		return entry{raw: raw, wildcard: base}, nil
	}
	if strings.HasPrefix(host, ".") {
		base := strings.TrimPrefix(host, ".")
		if base == "" {
			return entry{}, fmt.Errorf("invalid wildcard entry %q", raw)
		}
		return entry{raw: raw, wildcard: base}, nil
	}
	return entry{raw: raw, exact: host}, nil
}

func NormalizeTarget(target string) string {
	return normalizeHost(target)
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Host
		}
	}
	if strings.Contains(raw, "/") {
		raw = strings.Split(raw, "/")[0]
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	raw = strings.TrimSuffix(raw, ".")
	raw = strings.Trim(raw, "[]")
	return raw
}
