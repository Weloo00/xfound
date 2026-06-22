package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"recon-runner/internal/profiles"
	"recon-runner/internal/runner"
	"recon-runner/internal/scope"
	"recon-runner/internal/wordlists"
)

type ToolLocator interface {
	Path(name string) (string, bool)
}

type EnvLocator struct{}

func (EnvLocator) Path(name string) (string, bool) {
	path, err := exec.LookPath(name)
	return path, err == nil
}

type StaticLocator map[string]string

func (s StaticLocator) Path(name string) (string, bool) {
	path, ok := s[name]
	return path, ok && path != ""
}

type CommandRunner interface {
	Run(context.Context, runner.CommandSpec) runner.Result
}

type Manager struct {
	Locator  ToolLocator
	Executor CommandRunner
	// Progress, when set, receives friendly human-readable progress lines as
	// phases and tools run (CLI uses os.Stderr). Ignored for dry-runs.
	Progress io.Writer
}

func (m Manager) logf(format string, args ...any) {
	if m.Progress != nil {
		fmt.Fprintf(m.Progress, format+"\n", args...)
	}
}

type Options struct {
	Target        string
	ScopeFile     string
	ProfileName   string
	Profile       profiles.Profile
	Phase         string
	DryRun        bool
	Resume        bool
	OutputRoot    string
	WordlistsRoot string
	ToolsMapFile  string
	AutoScope     bool
}

type RunMetadata struct {
	Target      string            `json:"target"`
	Profile     string            `json:"profile"`
	OutputDir   string            `json:"output_dir"`
	StartedAt   time.Time         `json:"started_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	DryRun      bool              `json:"dry_run"`
	Phases      []PhaseRun        `json:"phases"`
	Results     []runner.Result   `json:"results"`
	DryRunPlan  []DryRunCommand   `json:"dry_run_plan,omitempty"`
	OutputCount map[string]int    `json:"output_counts"`
	Missing     map[string]string `json:"missing_tools,omitempty"`
	Skipped     map[string]string `json:"skipped_tools,omitempty"`
	Timeouts    map[string]string `json:"killed_on_timeout,omitempty"`
}

type PhaseRun struct {
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Reason     string            `json:"reason,omitempty"`
	Counts     map[string]int    `json:"counts,omitempty"`
	Tools      map[string]string `json:"tools,omitempty"`
}

type DryRunCommand struct {
	Phase    string `json:"phase"`
	Tool     string `json:"tool"`
	Command  string `json:"command"`
	Timeout  string `json:"timeout"`
	Optional bool   `json:"optional"`
}

type Layout struct {
	Root       string
	Target     string
	Subdomains string
	DNS        string
	Alive      string
	URLs       string
	JS         string
	Ports      string
	Nuclei     string
	Fuzz       string
	Meg        string
	Secrets    string
	API        string
	Takeover   string
	Intel      string
	Errors     string
	Logs       string
}

type PhasePlan struct {
	Name        string
	RequiredAny []string
	Commands    []runner.CommandSpec
	Post        func(Layout) error
}

func (m Manager) Run(ctx context.Context, opts Options) (*RunMetadata, error) {
	target := scope.NormalizeTarget(opts.Target)
	if target == "" {
		return nil, errors.New("target is required")
	}
	var allowlist scope.Allowlist
	var err error
	if opts.ScopeFile != "" {
		allowlist, err = scope.Load(opts.ScopeFile)
		if err != nil {
			return nil, err
		}
		if !allowlist.Allows(target) {
			return nil, fmt.Errorf("target %s is not allowlisted by %s", target, opts.ScopeFile)
		}
	} else if opts.AutoScope {
		allowlist, err = scope.SelfScope(target)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("a scope file (--scope) is required; or use `xfound hunt` for single-domain auto-scope")
	}
	_ = allowlist
	profile := opts.Profile
	if profile.Name == "" {
		profile, err = profiles.Get(opts.ProfileName)
		if err != nil {
			return nil, err
		}
	}
	layout := NewLayout(opts.OutputRoot, target)
	if err := ensureLayout(layout); err != nil {
		return nil, err
	}
	wlRoot := opts.WordlistsRoot
	if wlRoot == "" {
		wlRoot = "/root/tools/wordlists"
	}
	wl := wordlists.Classify(wlRoot, 8)
	phaseNames, err := selectedPhases(opts.Phase)
	if err != nil {
		return nil, err
	}

	meta := &RunMetadata{
		Target:      target,
		Profile:     profile.Name,
		OutputDir:   layout.Root,
		StartedAt:   time.Now().UTC(),
		DryRun:      opts.DryRun,
		OutputCount: map[string]int{},
		Missing:     map[string]string{},
		Skipped:     map[string]string{},
		Timeouts:    map[string]string{},
	}
	existing, _ := LoadMetadata(layout.Root)
	if existing != nil && opts.Resume {
		meta.StartedAt = existing.StartedAt
		meta.Results = append(meta.Results, existing.Results...)
	}
	locator := m.Locator
	if locator == nil {
		toolsMap, err := LoadToolsMap(opts.ToolsMapFile)
		if err != nil {
			return nil, err
		}
		if toolsMap != nil {
			locator = ChainLocator{toolsMap, EnvLocator{}}
		} else {
			locator = EnvLocator{}
		}
	}
	executor := m.Executor
	if executor == nil {
		executor = runner.Runner{}
	}

	if !opts.DryRun {
		m.logf("\n▶ %s  —  profile: %s  —  phases: %d", target, profile.Name, len(phaseNames))
		m.logf("  output: %s", layout.Root)
	}
	for i, phaseName := range phaseNames {
		plan, err := BuildPhase(phaseName, target, profile, layout, wl)
		if err != nil {
			return nil, err
		}
		phaseRun := PhaseRun{Name: phaseName, StartedAt: time.Now().UTC(), Tools: map[string]string{}}
		if opts.Resume && phaseComplete(existing, phaseName) {
			phaseRun.Status = "skipped"
			phaseRun.Reason = "resume: phase already completed"
			phaseRun.FinishedAt = time.Now().UTC()
			phaseRun.Counts = collectCounts(layout)
			meta.Phases = append(meta.Phases, phaseRun)
			meta.OutputCount = phaseRun.Counts
			if !opts.DryRun {
				m.logf("\n[%d/%d] %-11s ↩ already done (resume) — skipping", i+1, len(phaseNames), phaseName)
			}
			continue
		}
		if !opts.DryRun {
			m.logf("\n[%d/%d] %-11s starting…", i+1, len(phaseNames), phaseName)
		}

		var phaseResults []runner.Result
		for _, spec := range plan.Commands {
			spec.Timeout = toolTimeout(profile, spec.Tool)
			spec.TimeoutLabel = spec.Timeout.String()
			if path, ok := locator.Path(spec.Tool); ok {
				spec.Path = path
			} else if spec.Path == "" {
				spec.Path = spec.Tool
			}

			if opts.DryRun {
				meta.DryRunPlan = append(meta.DryRunPlan, DryRunCommand{
					Phase:    spec.Phase,
					Tool:     spec.Tool,
					Command:  runner.Render(spec),
					Timeout:  spec.TimeoutLabel,
					Optional: spec.Optional,
				})
				phaseRun.Tools[spec.Tool] = "planned"
				continue
			}

			if _, ok := locator.Path(spec.Tool); !ok {
				res := runner.SkipResult(spec, "tool not installed")
				phaseResults = append(phaseResults, res)
				phaseRun.Tools[spec.Tool] = "missing"
				meta.Missing[spec.Tool] = spec.Phase
				m.logf("  · %-12s — not installed, skipping", spec.Tool)
				continue
			}
			if spec.RequiresFile != "" && !fileExists(spec.RequiresFile) {
				res := runner.SkipResult(spec, "required input file is missing: "+spec.RequiresFile)
				phaseResults = append(phaseResults, res)
				phaseRun.Tools[spec.Tool] = "skipped"
				meta.Skipped[spec.Tool] = res.SkipReason
				m.logf("  · %-12s — no input yet, skipping", spec.Tool)
				continue
			}
			m.logf("  • %-12s running… (max %s)", spec.Tool, spec.TimeoutLabel)
			res := executor.Run(ctx, spec)
			phaseResults = append(phaseResults, res)
			switch {
			case res.TimedOut:
				phaseRun.Tools[spec.Tool] = "timeout"
				meta.Timeouts[spec.Tool] = spec.Phase
				m.logf("  ⧖ %-12s — hit time limit, moving on", spec.Tool)
			case res.Skipped:
				phaseRun.Tools[spec.Tool] = "skipped"
				meta.Skipped[spec.Tool] = res.SkipReason
				m.logf("  · %-12s — skipped (%s)", spec.Tool, res.SkipReason)
			case res.ExitCode == 0:
				phaseRun.Tools[spec.Tool] = "ok"
				m.logf("  ✓ %-12s — done%s", spec.Tool, lineSuffix(spec.StdoutFile))
			default:
				phaseRun.Tools[spec.Tool] = "failed"
				m.logf("  ✗ %-12s — failed (exit %d, see %s)", spec.Tool, res.ExitCode, filepath.Base(spec.StderrFile))
			}
		}
		meta.Results = append(meta.Results, phaseResults...)

		if !opts.DryRun && plan.Post != nil {
			if err := plan.Post(layout); err != nil {
				phaseRun.Status = "failed"
				phaseRun.Reason = err.Error()
			}
		}
		if phaseRun.Status == "" {
			phaseRun.Status, phaseRun.Reason = phaseStatus(plan, phaseResults, opts.DryRun)
		}
		phaseRun.FinishedAt = time.Now().UTC()
		phaseRun.Counts = collectCounts(layout)
		meta.Phases = append(meta.Phases, phaseRun)
		meta.OutputCount = phaseRun.Counts
		meta.UpdatedAt = time.Now().UTC()
		if err := SaveMetadata(layout.Root, meta); err != nil {
			return nil, err
		}
		if !opts.DryRun {
			took := phaseRun.FinishedAt.Sub(phaseRun.StartedAt).Round(time.Second)
			m.logf("  └ %s in %s", phaseRun.Status, took)
		}
		if !opts.DryRun && phaseRun.Status == "failed" && len(plan.RequiredAny) > 0 {
			m.logf("\n✗ Stopping: required phase %q failed. Fix the tool above and re-run (it resumes).", phaseName)
			break
		}
	}
	meta.UpdatedAt = time.Now().UTC()
	meta.OutputCount = collectCounts(layout)
	if !opts.DryRun {
		m.logf("\n✔ Done in %s. Highlights:", meta.UpdatedAt.Sub(meta.StartedAt).Round(time.Second))
		for _, k := range []string{"subdomains", "dns_resolved", "alive_urls", "urls", "js_urls", "ports", "nuclei", "takeover"} {
			if v := meta.OutputCount[k]; v > 0 {
				m.logf("    %-13s %d", k, v)
			}
		}
		m.logf("  results: %s", layout.Root)
		m.logf("  view later: xfound status --target %s", target)
	}
	if len(meta.Missing) == 0 {
		meta.Missing = nil
	}
	if len(meta.Skipped) == 0 {
		meta.Skipped = nil
	}
	if len(meta.Timeouts) == 0 {
		meta.Timeouts = nil
	}
	return meta, SaveMetadata(layout.Root, meta)
}

func BuildPhase(name, target string, profile profiles.Profile, layout Layout, wl wordlists.Inventory) (PhasePlan, error) {
	errFile := func(tool string) string {
		return filepath.Join(layout.Errors, name+"-"+tool+".stderr.log")
	}
	logFile := func(tool string) string {
		return filepath.Join(layout.Logs, name+"-"+tool+".stdout.log")
	}
	spec := func(tool string, args []string, stdout string, optional bool, requires string) runner.CommandSpec {
		return runner.CommandSpec{
			Phase:        name,
			Tool:         tool,
			Path:         tool,
			Args:         args,
			StdoutFile:   stdout,
			StderrFile:   errFile(tool),
			Timeout:      toolTimeout(profile, tool),
			TimeoutLabel: toolTimeout(profile, tool).String(),
			Optional:     optional,
			RequiresFile: requires,
		}
	}

	subAll := filepath.Join(layout.Subdomains, "all.txt")
	perms := filepath.Join(layout.DNS, "permutations.txt")
	resolved := filepath.Join(layout.DNS, "resolved.txt")
	aliveURLs := filepath.Join(layout.Alive, "urls.txt")
	allURLs := filepath.Join(layout.URLs, "all.txt")
	webWordlist := wl.First("web-content")
	paramWordlist := wl.First("params")
	resolvers := wl.First("resolvers")
	dnsWordlist := wl.First("dns")
	if paramWordlist == "" {
		paramWordlist = webWordlist
	}
	jsURLs := filepath.Join(layout.JS, "js-urls.txt")

	switch name {
	case "subdomains":
		// amass is intentionally NOT run here — it is slow and routinely hits its
		// timeout; run it manually (e.g. `amass enum -passive -d <target>`) and
		// drop the output into subdomains/amass.txt to have it merged on re-run.
		cmds := []runner.CommandSpec{
			spec("subfinder", []string{"-d", target, "-silent"}, filepath.Join(layout.Subdomains, "subfinder.txt"), true, ""),
			spec("shodan", []string{"domain", target}, filepath.Join(layout.Subdomains, "shodan-raw.txt"), true, ""),
		}
		if dnsWordlist != "" {
			cmds = append(cmds, spec("dnscan", []string{"-d", target, "-w", dnsWordlist, "-o", filepath.Join(layout.Subdomains, "dnscan.txt")}, logFile("dnscan"), true, dnsWordlist))
		}
		return PhasePlan{
			Name:        name,
			RequiredAny: []string{"subfinder"},
			Commands:    cmds,
			Post: func(l Layout) error {
				// shodan domain output needs the host column joined to the apex.
				_ = extractShodanDomain(filepath.Join(l.Subdomains, "shodan-raw.txt"), filepath.Join(l.Subdomains, "shodan.txt"), target)
				// amass.txt is merged if present (drop in manual amass output).
				return appendUnique(filepath.Join(l.Subdomains, "all.txt"), filepath.Join(l.Subdomains, "subfinder.txt"), filepath.Join(l.Subdomains, "amass.txt"), filepath.Join(l.Subdomains, "crtndstry.txt"), filepath.Join(l.Subdomains, "dnscan.txt"), filepath.Join(l.Subdomains, "shodan.txt"))
			},
		}, nil
	case "ct":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("crtndstry", []string{"-d", target}, filepath.Join(layout.Subdomains, "crtndstry.txt"), true, ""),
			},
			Post: func(l Layout) error {
				return appendUnique(filepath.Join(l.Subdomains, "all.txt"), filepath.Join(l.Subdomains, "all.txt"), filepath.Join(l.Subdomains, "crtndstry.txt"))
			},
		}, nil
	case "dnsgen":
		cmds := []runner.CommandSpec{
			spec("dnsgen", []string{subAll}, filepath.Join(layout.DNS, "dnsgen.txt"), true, subAll),
		}
		if dnsWordlist != "" {
			cmds = append(cmds, spec("altdns", []string{"-i", subAll, "-w", dnsWordlist, "-o", filepath.Join(layout.DNS, "altdns.txt")}, logFile("altdns"), true, subAll))
		}
		return PhasePlan{
			Name:     name,
			Commands: cmds,
			Post: func(l Layout) error {
				out := filepath.Join(l.DNS, "permutations.txt")
				gen := filepath.Join(l.DNS, "dnsgen.txt")
				alt := filepath.Join(l.DNS, "altdns.txt")
				if lineCount(gen) > 0 || lineCount(alt) > 0 {
					return appendUnique(out, gen, alt, filepath.Join(l.Subdomains, "all.txt"))
				}
				return appendUnique(out, filepath.Join(l.Subdomains, "all.txt"))
			},
		}, nil
	case "resolve":
		cmds := []runner.CommandSpec{
			spec("dnsx", []string{"-l", perms, "-silent", "-a", "-resp"}, filepath.Join(layout.DNS, "dnsx.txt"), true, perms),
			spec("puredns", []string{"resolve", perms, "-w", filepath.Join(layout.DNS, "puredns.txt")}, logFile("puredns"), true, perms),
		}
		if resolvers != "" {
			cmds = append(cmds,
				spec("shuffledns", []string{"-d", target, "-list", perms, "-r", resolvers, "-o", filepath.Join(layout.DNS, "shuffledns.txt")}, logFile("shuffledns"), true, perms),
				spec("massdns", []string{"-r", resolvers, "-t", "A", "-o", "S", "-w", filepath.Join(layout.DNS, "massdns.txt"), perms}, logFile("massdns"), true, perms),
			)
		}
		return PhasePlan{
			Name:        name,
			RequiredAny: []string{"dnsx", "puredns", "shuffledns", "massdns"},
			Commands:    cmds,
			Post: func(l Layout) error {
				out := filepath.Join(l.DNS, "resolved.txt")
				return appendUnique(out, filepath.Join(l.DNS, "dnsx.txt"), filepath.Join(l.DNS, "puredns.txt"), filepath.Join(l.DNS, "shuffledns.txt"), filepath.Join(l.DNS, "massdns.txt"))
			},
		}, nil
	case "alive":
		return PhasePlan{
			Name:        name,
			RequiredAny: []string{"httpx"},
			Commands: []runner.CommandSpec{
				spec("httpx", []string{"-l", resolved, "-silent", "-json", "-tls-probe", "-tech-detect"}, filepath.Join(layout.Alive, "httpx.jsonl"), false, resolved),
			},
			Post: func(l Layout) error {
				return extractHTTPX(filepath.Join(l.Alive, "httpx.jsonl"), filepath.Join(l.Alive, "urls.txt"))
			},
		}, nil
	case "urls":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("waybackurls", []string{target}, filepath.Join(layout.URLs, "waybackurls.txt"), true, ""),
				spec("gau", []string{"--subs", target}, filepath.Join(layout.URLs, "gau.txt"), true, ""),
				spec("gauplus", []string{"-t", "5", target}, filepath.Join(layout.URLs, "gauplus.txt"), true, ""),
				spec("waymore", []string{"-i", target, "-mode", "U", "-oU", filepath.Join(layout.URLs, "waymore.txt")}, logFile("waymore"), true, ""),
			},
			Post: func(l Layout) error {
				return appendUnique(filepath.Join(l.URLs, "all.txt"), filepath.Join(l.URLs, "waybackurls.txt"), filepath.Join(l.URLs, "gau.txt"), filepath.Join(l.URLs, "gauplus.txt"), filepath.Join(l.URLs, "waymore.txt"))
			},
		}, nil
	case "crawl":
		hakrawler := spec("hakrawler", []string{"-plain"}, filepath.Join(layout.URLs, "hakrawler.txt"), true, aliveURLs)
		hakrawler.StdinFile = aliveURLs
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("katana", []string{"-list", aliveURLs, "-silent", "-jc"}, filepath.Join(layout.URLs, "katana.txt"), true, aliveURLs),
				hakrawler,
				spec("gospider", []string{"-S", aliveURLs, "-q"}, filepath.Join(layout.URLs, "gospider.txt"), true, aliveURLs),
			},
			Post: func(l Layout) error {
				return appendUnique(filepath.Join(l.URLs, "all.txt"), filepath.Join(l.URLs, "all.txt"), filepath.Join(l.URLs, "katana.txt"), filepath.Join(l.URLs, "hakrawler.txt"), filepath.Join(l.URLs, "gospider.txt"))
			},
		}, nil
	case "js":
		cmds := []runner.CommandSpec{
			spec("JSParser", []string{"-l", allURLs}, filepath.Join(layout.JS, "endpoints.txt"), true, allURLs),
		}
		lazyegg := spec("lazyegg", []string{}, filepath.Join(layout.JS, "lazyegg.txt"), true, allURLs)
		lazyegg.StdinFile = allURLs
		cmds = append(cmds, lazyegg)
		return PhasePlan{
			Name:     name,
			Commands: cmds,
			Post: func(l Layout) error {
				_ = extractParams(filepath.Join(l.JS, "endpoints.txt"), filepath.Join(l.JS, "params.txt"))
				_ = extractHosts(filepath.Join(l.JS, "endpoints.txt"), filepath.Join(l.JS, "subdomains.txt"))
				_ = filterByExt(filepath.Join(l.URLs, "all.txt"), filepath.Join(l.JS, "js-urls.txt"), ".js")
				return nil
			},
		}, nil
	case "secrets":
		mantra := spec("mantra", []string{}, filepath.Join(layout.Secrets, "mantra.txt"), true, jsURLs)
		mantra.StdinFile = jsURLs
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				mantra,
				spec("jssecrets", []string{"-l", jsURLs}, filepath.Join(layout.Secrets, "jssecrets.txt"), true, jsURLs),
				spec("trufflehog", []string{"filesystem", layout.JS, "--json"}, filepath.Join(layout.Secrets, "trufflehog.jsonl"), true, ""),
			},
		}, nil
	case "api":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("kiterunner", []string{"scan", aliveURLs, "-o", "text"}, filepath.Join(layout.API, "kiterunner.txt"), true, aliveURLs),
			},
		}, nil
	case "shortscan":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("shortscan", []string{"https://" + target}, filepath.Join(layout.Fuzz, "shortscan.txt"), true, ""),
			},
		}, nil
	case "takeover":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("nuclei", []string{"-l", subAll, "-tags", "takeover", "-jsonl", "-o", filepath.Join(layout.Takeover, "nuclei-takeover.jsonl")}, logFile("nuclei-takeover"), true, subAll),
			},
		}, nil
	case "intel":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("gitdorker", []string{"-q", target, "-o", filepath.Join(layout.Intel, "gitdorker.txt")}, logFile("gitdorker"), true, ""),
			},
		}, nil
	case "ports":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("naabu", []string{"-list", resolved, "-silent", "-o", filepath.Join(layout.Ports, "naabu.txt")}, logFile("naabu"), true, resolved),
			},
		}, nil
	case "nuclei":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("nuclei", []string{"-l", aliveURLs, "-jsonl", "-o", filepath.Join(layout.Nuclei, "nuclei.jsonl")}, logFile("nuclei"), true, aliveURLs),
			},
		}, nil
	case "fuzz":
		cmds := []runner.CommandSpec{}
		if webWordlist != "" {
			cmds = append(cmds,
				spec("ffuf", []string{"-w", webWordlist, "-u", "https://" + target + "/FUZZ", "-of", "json", "-o", filepath.Join(layout.Fuzz, "ffuf.json")}, logFile("ffuf"), true, webWordlist),
				spec("gobuster", []string{"dir", "-u", "https://" + target, "-w", webWordlist, "-o", filepath.Join(layout.Fuzz, "gobuster.txt")}, logFile("gobuster"), true, webWordlist),
				spec("dirsearch", []string{"-u", "https://" + target, "-w", webWordlist, "-o", filepath.Join(layout.Fuzz, "dirsearch.txt")}, logFile("dirsearch"), true, webWordlist),
			)
		}
		if paramWordlist != "" {
			cmds = append(cmds, spec("arjun", []string{"-i", aliveURLs, "-w", paramWordlist, "-oT", filepath.Join(layout.Fuzz, "arjun.txt")}, logFile("arjun"), true, aliveURLs))
		}
		cmds = append(cmds, spec("paramspider", []string{"-d", target, "-o", filepath.Join(layout.Fuzz, "paramspider.txt")}, logFile("paramspider"), true, ""))
		return PhasePlan{Name: name, Commands: cmds}, nil
	case "meg":
		paths := filepath.Join(layout.Meg, "paths.txt")
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("meg", []string{"-d", "1000", paths, aliveURLs, filepath.Join(layout.Meg, "out")}, logFile("meg"), true, aliveURLs),
			},
		}, nil
	case "lazyrecon":
		return PhasePlan{
			Name: name,
			Commands: []runner.CommandSpec{
				spec("lazyrecon", []string{target}, logFile("lazyrecon"), true, ""),
			},
		}, nil
	default:
		return PhasePlan{}, fmt.Errorf("unknown phase %q", name)
	}
}

func PrintDryRun(w io.Writer, meta *RunMetadata) {
	for _, cmd := range meta.DryRunPlan {
		fmt.Fprintf(w, "[%s:%s timeout=%s optional=%v] %s\n", cmd.Phase, cmd.Tool, cmd.Timeout, cmd.Optional, cmd.Command)
	}
}

func LoadMetadata(targetDir string) (*RunMetadata, error) {
	f, err := os.Open(filepath.Join(targetDir, "run.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var meta RunMetadata
	if err := json.NewDecoder(f).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func SaveMetadata(targetDir string, meta *RunMetadata) error {
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(targetDir, "run.json.tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(targetDir, "run.json"))
}

func Status(target, outputRoot string) (*RunMetadata, error) {
	target = scope.NormalizeTarget(target)
	if target == "" {
		return nil, errors.New("target is required")
	}
	layout := NewLayout(outputRoot, target)
	meta, err := LoadMetadata(layout.Root)
	if err != nil {
		return nil, err
	}
	meta.OutputCount = collectCounts(layout)
	return meta, nil
}

func PrintStatus(w io.Writer, meta *RunMetadata, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(meta)
	}
	elapsed := meta.UpdatedAt.Sub(meta.StartedAt).Round(time.Second)
	fmt.Fprintf(w, "target: %s\nprofile: %s\noutput: %s\nelapsed: %s\n", meta.Target, meta.Profile, meta.OutputDir, elapsed)
	if len(meta.Timeouts) > 0 {
		fmt.Fprintln(w, "killed-on-timeout:")
		for _, k := range sortedKeys(meta.Timeouts) {
			fmt.Fprintf(w, "  %s (%s)\n", k, meta.Timeouts[k])
		}
	}
	if len(meta.Missing) > 0 {
		fmt.Fprintln(w, "missing tools:")
		for _, k := range sortedKeys(meta.Missing) {
			fmt.Fprintf(w, "  %s (%s)\n", k, meta.Missing[k])
		}
	}
	if len(meta.Skipped) > 0 {
		fmt.Fprintln(w, "skipped tools:")
		for _, k := range sortedKeys(meta.Skipped) {
			fmt.Fprintf(w, "  %s: %s\n", k, meta.Skipped[k])
		}
	}
	fmt.Fprintln(w, "phases:")
	for _, p := range meta.Phases {
		reason := ""
		if p.Reason != "" {
			reason = " - " + p.Reason
		}
		fmt.Fprintf(w, "  %s: %s%s\n", p.Name, p.Status, reason)
	}
	fmt.Fprintln(w, "output counts:")
	for _, k := range sortedCountKeys(meta.OutputCount) {
		fmt.Fprintf(w, "  %s: %d\n", k, meta.OutputCount[k])
	}
	return nil
}

func NewLayout(outputRoot, target string) Layout {
	if outputRoot == "" {
		outputRoot = "/root/Targets"
	}
	root := filepath.Join(outputRoot, safeTargetDir(target))
	return Layout{
		Root:       root,
		Target:     target,
		Subdomains: filepath.Join(root, "subdomains"),
		DNS:        filepath.Join(root, "dns"),
		Alive:      filepath.Join(root, "alive"),
		URLs:       filepath.Join(root, "urls"),
		JS:         filepath.Join(root, "js"),
		Ports:      filepath.Join(root, "ports"),
		Nuclei:     filepath.Join(root, "nuclei"),
		Fuzz:       filepath.Join(root, "fuzz"),
		Meg:        filepath.Join(root, "meg"),
		Secrets:    filepath.Join(root, "secrets"),
		API:        filepath.Join(root, "api"),
		Takeover:   filepath.Join(root, "takeover"),
		Intel:      filepath.Join(root, "intel"),
		Errors:     filepath.Join(root, "errors"),
		Logs:       filepath.Join(root, "logs"),
	}
}

func PhaseOrder() []string {
	return []string{"subdomains", "ct", "dnsgen", "resolve", "alive", "urls", "crawl", "js", "secrets", "ports", "shortscan", "api", "nuclei", "takeover", "fuzz", "intel", "meg"}
}

func selectedPhases(phase string) ([]string, error) {
	if phase == "" {
		return PhaseOrder(), nil
	}
	valid := append(PhaseOrder(), "lazyrecon")
	for _, v := range valid {
		if phase == v {
			return []string{phase}, nil
		}
	}
	return nil, fmt.Errorf("unknown phase %q", phase)
}

func phaseStatus(plan PhasePlan, results []runner.Result, dryRun bool) (string, string) {
	if dryRun {
		return "planned", ""
	}
	if len(plan.Commands) == 0 {
		return "skipped", "no commands configured for phase"
	}
	if len(results) == 0 {
		return "skipped", "no commands executed"
	}
	requiredOK := len(plan.RequiredAny) == 0
	ran := false
	ranFailed := false
	ranSuccess := false
	for _, res := range results {
		if res.Skipped {
			continue
		}
		ran = true
		if res.ExitCode != 0 || res.TimedOut {
			ranFailed = true
		} else {
			ranSuccess = true
		}
		if contains(plan.RequiredAny, res.Tool) && res.ExitCode == 0 && !res.TimedOut {
			requiredOK = true
		}
	}
	if len(plan.RequiredAny) > 0 && !requiredOK {
		return "failed", "no required tool completed successfully"
	}
	if !ran {
		return "skipped", "all tools missing or skipped"
	}
	if ranSuccess && ranFailed {
		return "completed", "one or more optional tools failed"
	}
	if ranFailed {
		return "failed", "one or more tools failed"
	}
	return "completed", ""
}

func phaseComplete(meta *RunMetadata, phase string) bool {
	if meta == nil {
		return false
	}
	for _, p := range meta.Phases {
		if p.Name == phase && p.Status == "completed" {
			return true
		}
	}
	return false
}

func ensureLayout(l Layout) error {
	for _, dir := range []string{l.Root, l.Subdomains, l.DNS, l.Alive, l.URLs, l.JS, l.Ports, l.Nuclei, l.Fuzz, l.Meg, l.Secrets, l.API, l.Takeover, l.Intel, l.Errors, l.Logs} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	paths := filepath.Join(l.Meg, "paths.txt")
	if !fileExists(paths) {
		content := strings.Join([]string{
			"/.git/config",
			"/.env",
			"/.env.local",
			"/config.php",
			"/config.json",
			"/backup.zip",
			"/backup.tar.gz",
			"/database.sql",
			"/wp-config.php",
			"/.svn/entries",
			"",
		}, "\n")
		if err := os.WriteFile(paths, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func toolTimeout(profile profiles.Profile, tool string) time.Duration {
	if d, ok := profile.TimeoutFor(tool); ok {
		return d
	}
	return 5 * time.Minute
}

func appendUnique(out string, inputs ...string) error {
	seen := map[string]bool{}
	var lines []string
	for _, input := range inputs {
		f, err := os.Open(input)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := normalizeOutputLine(sc.Text())
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			lines = append(lines, line)
		}
		_ = f.Close()
	}
	sort.Strings(lines)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, []byte(strings.Join(lines, "\n")+newlineIfAny(lines)), 0o644)
}

func extractHTTPX(input, out string) error {
	f, err := os.Open(input)
	if err != nil {
		return appendUnique(out)
	}
	defer f.Close()
	var lines []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		value := line
		var obj map[string]any
		if json.Unmarshal([]byte(line), &obj) == nil {
			if u, ok := obj["url"].(string); ok {
				value = u
			} else if u, ok := obj["input"].(string); ok {
				value = u
			}
		}
		value = normalizeOutputLine(value)
		if value != "" && !seen[value] {
			seen[value] = true
			lines = append(lines, value)
		}
	}
	sort.Strings(lines)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, []byte(strings.Join(lines, "\n")+newlineIfAny(lines)), 0o644)
}

func extractParams(input, out string) error {
	f, err := os.Open(input)
	if err != nil {
		return appendUnique(out)
	}
	defer f.Close()
	seen := map[string]bool{}
	var params []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for key := range u.Query() {
			if key != "" && !seen[key] {
				seen[key] = true
				params = append(params, key)
			}
		}
	}
	sort.Strings(params)
	return os.WriteFile(out, []byte(strings.Join(params, "\n")+newlineIfAny(params)), 0o644)
}

func extractHosts(input, out string) error {
	f, err := os.Open(input)
	if err != nil {
		return appendUnique(out)
	}
	defer f.Close()
	seen := map[string]bool{}
	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return os.WriteFile(out, []byte(strings.Join(hosts, "\n")+newlineIfAny(hosts)), 0o644)
}

// extractShodanDomain parses `shodan domain <target>` output into FQDNs.
// Each data row looks like "<host>  <TYPE>  <value>"; the host column is empty
// for apex records. We join non-empty hosts to the apex (e.g. "api" -> the
// FQDN "api.<target>"), skip wildcards, and write a sorted, de-duplicated list.
func extractShodanDomain(input, out, target string) error {
	f, err := os.Open(input)
	if err != nil {
		return appendUnique(out)
	}
	defer f.Close()
	recordTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
		"SOA": true, "TXT": true, "CAA": true, "PTR": true, "SRV": true,
		"DNAME": true, "NAPTR": true, "DS": true, "HINFO": true,
	}
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	seen := map[string]bool{}
	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(fields[0], "."))
		// First column is a record type => apex record, no subdomain label.
		if recordTypes[strings.ToUpper(fields[0])] {
			continue
		}
		if host == "" || host == "*" || strings.HasPrefix(host, "*") {
			continue
		}
		fqdn := host
		if !strings.HasSuffix(host, "."+target) && host != target {
			fqdn = host + "." + target
		}
		if !seen[fqdn] {
			seen[fqdn] = true
			hosts = append(hosts, fqdn)
		}
	}
	sort.Strings(hosts)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, []byte(strings.Join(hosts, "\n")+newlineIfAny(hosts)), 0o644)
}

// filterByExt writes the subset of URLs from input whose path ends with ext
// (case-insensitive, ignoring any query string) to out, de-duplicated.
func filterByExt(input, out, ext string) error {
	f, err := os.Open(input)
	if err != nil {
		return appendUnique(out)
	}
	defer f.Close()
	ext = strings.ToLower(ext)
	seen := map[string]bool{}
	var matched []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		path := raw
		if u, err := url.Parse(raw); err == nil && u.Path != "" {
			path = u.Path
		}
		if strings.HasSuffix(strings.ToLower(path), ext) && !seen[raw] {
			seen[raw] = true
			matched = append(matched, raw)
		}
	}
	sort.Strings(matched)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, []byte(strings.Join(matched, "\n")+newlineIfAny(matched)), 0o644)
}

func collectCounts(l Layout) map[string]int {
	files := map[string]string{
		"subdomains":       filepath.Join(l.Subdomains, "all.txt"),
		"dns_permutations": filepath.Join(l.DNS, "permutations.txt"),
		"dns_resolved":     filepath.Join(l.DNS, "resolved.txt"),
		"alive_urls":       filepath.Join(l.Alive, "urls.txt"),
		"urls":             filepath.Join(l.URLs, "all.txt"),
		"js_endpoints":     filepath.Join(l.JS, "endpoints.txt"),
		"js_params":        filepath.Join(l.JS, "params.txt"),
		"js_subdomains":    filepath.Join(l.JS, "subdomains.txt"),
		"js_urls":          filepath.Join(l.JS, "js-urls.txt"),
		"ports":            filepath.Join(l.Ports, "naabu.txt"),
		"nuclei":           filepath.Join(l.Nuclei, "nuclei.jsonl"),
		"takeover":         filepath.Join(l.Takeover, "nuclei-takeover.jsonl"),
		"secrets_mantra":   filepath.Join(l.Secrets, "mantra.txt"),
		"api_kiterunner":   filepath.Join(l.API, "kiterunner.txt"),
		"intel_gitdorker":  filepath.Join(l.Intel, "gitdorker.txt"),
	}
	counts := map[string]int{}
	for name, path := range files {
		counts[name] = lineCount(path)
	}
	return counts
}

// lineSuffix renders " (N lines)" for a tool's output file, or "" when the
// file is absent/empty. Used for friendly per-tool progress messages.
func lineSuffix(path string) string {
	if path == "" {
		return ""
	}
	n := lineCount(path)
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" (%d lines)", n)
}

func lineCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	return count
}

func normalizeOutputLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, `"'`)
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		line = fields[0]
	}
	line = strings.TrimSuffix(line, ".")
	return line
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func safeTargetDir(target string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return replacer.Replace(target)
}

func newlineIfAny(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return "\n"
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedCountKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
