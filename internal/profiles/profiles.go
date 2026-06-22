package profiles

import (
	"fmt"
	"sort"
	"time"
)

const (
	Fast   = "fast"
	Normal = "normal"
	Deep   = "deep"
)

type Profile struct {
	Name        string
	ToolBudgets map[string]time.Duration
}

func SupportedTools() []string {
	tools := []string{
		"altdns",
		"amass",
		"arjun",
		"bbht",
		"crtndstry",
		"dirsearch",
		"dnscan",
		"dnsgen",
		"dnsx",
		"ffuf",
		"gau",
		"gauplus",
		"gitdorker",
		"gobuster",
		"gospider",
		"hakrawler",
		"httpx",
		"JSParser",
		"jssecrets",
		"katana",
		"kiterunner",
		"lazyegg",
		"lazyrecon",
		"mantra",
		"massdns",
		"meg",
		"naabu",
		"nuclei",
		"paramspider",
		"puredns",
		"shodan",
		"shortscan",
		"shuffledns",
		"subfinder",
		"trufflehog",
		"waybackurls",
	}
	sort.Strings(tools)
	return tools
}

func Names() []string {
	return []string{Fast, Normal, Deep}
}

func Get(name string) (Profile, error) {
	switch name {
	case "", Normal:
		return build(Normal, 1), nil
	case Fast:
		return build(Fast, 0.35), nil
	case Deep:
		return build(Deep, 3), nil
	default:
		return Profile{}, fmt.Errorf("unknown profile %q (valid: fast, normal, deep)", name)
	}
}

func (p Profile) TimeoutFor(tool string) (time.Duration, bool) {
	d, ok := p.ToolBudgets[tool]
	return d, ok
}

func build(name string, scale float64) Profile {
	base := map[string]time.Duration{
		"subfinder":   8 * time.Minute,
		"amass":       18 * time.Minute,
		"crtndstry":   5 * time.Minute,
		"dnsgen":      5 * time.Minute,
		"dnsx":        8 * time.Minute,
		"puredns":     12 * time.Minute,
		"shuffledns":  12 * time.Minute,
		"massdns":     12 * time.Minute,
		"httpx":       10 * time.Minute,
		"waybackurls": 8 * time.Minute,
		"gau":         10 * time.Minute,
		"gauplus":     10 * time.Minute,
		"katana":      15 * time.Minute,
		"hakrawler":   10 * time.Minute,
		"gospider":    10 * time.Minute,
		"JSParser":    8 * time.Minute,
		"naabu":       12 * time.Minute,
		"nuclei":      20 * time.Minute,
		"ffuf":        12 * time.Minute,
		"gobuster":    12 * time.Minute,
		"dirsearch":   12 * time.Minute,
		"arjun":       10 * time.Minute,
		"paramspider": 10 * time.Minute,
		"trufflehog":  10 * time.Minute,
		"meg":         8 * time.Minute,
		"lazyrecon":   60 * time.Minute,
		"bbht":        60 * time.Minute,
		"altdns":      6 * time.Minute,
		"dnscan":      12 * time.Minute,
		"gitdorker":   8 * time.Minute,
		"jssecrets":   6 * time.Minute,
		"kiterunner":  15 * time.Minute,
		"lazyegg":     6 * time.Minute,
		"mantra":      6 * time.Minute,
		"shodan":      3 * time.Minute,
		"shortscan":   5 * time.Minute,
	}

	budgets := make(map[string]time.Duration, len(base))
	for tool, d := range base {
		scaled := time.Duration(float64(d) * scale)
		if scaled < time.Minute {
			scaled = time.Minute
		}
		budgets[tool] = scaled.Round(time.Second)
	}
	return Profile{Name: name, ToolBudgets: budgets}
}
