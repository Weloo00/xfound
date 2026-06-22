package pipeline

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"recon-runner/internal/scope"
)

// Report writes a human-readable summary of a target's recon output to w.
// It parses the JSONL files (httpx, nuclei) into plain lines and lists the
// plaintext result files, so the whole /root/Targets/<target>/ folder can be
// understood at a glance.
func Report(w io.Writer, target, outputRoot string) error {
	target = scope.NormalizeTarget(target)
	if target == "" {
		return errors.New("target is required")
	}
	layout := NewLayout(outputRoot, target)
	if _, err := os.Stat(layout.Root); err != nil {
		return fmt.Errorf("no output found for %s at %s", target, layout.Root)
	}

	fmt.Fprintf(w, "# Recon report — %s\n", target)
	if meta, err := LoadMetadata(layout.Root); err == nil {
		fmt.Fprintf(w, "profile: %s   elapsed: %s\n", meta.Profile, meta.UpdatedAt.Sub(meta.StartedAt).Round(time.Second))
		done, total := phaseProgress(meta)
		fmt.Fprintf(w, "phases:  %d/%d completed\n", done, total)
	}
	fmt.Fprintf(w, "output:  %s\n", layout.Root)

	reportList(w, "Subdomains", filepath.Join(layout.Subdomains, "all.txt"), 80)
	reportList(w, "Resolved (live DNS)", filepath.Join(layout.DNS, "resolved.txt"), 0)
	reportHTTPX(w, filepath.Join(layout.Alive, "httpx.jsonl"))
	reportCount(w, "URLs collected", filepath.Join(layout.URLs, "all.txt"))
	reportCount(w, "JS endpoints", filepath.Join(layout.JS, "endpoints.txt"))
	reportCount(w, "JS params", filepath.Join(layout.JS, "params.txt"))
	reportCount(w, "JS files", filepath.Join(layout.JS, "js-urls.txt"))
	reportSecrets(w, layout)
	reportList(w, "Open ports", filepath.Join(layout.Ports, "naabu.txt"), 0)
	reportNuclei(w, "Nuclei findings", filepath.Join(layout.Nuclei, "nuclei.jsonl"))
	reportNuclei(w, "Subdomain takeover", filepath.Join(layout.Takeover, "nuclei-takeover.jsonl"))
	reportCount(w, "GitHub dork hits", filepath.Join(layout.Intel, "gitdorker.txt"))
	return nil
}

func phaseProgress(meta *RunMetadata) (done, total int) {
	for _, p := range meta.Phases {
		total++
		if p.Status == "completed" {
			done++
		}
	}
	return done, total
}

func reportList(w io.Writer, title, path string, max int) {
	lines := readNonEmptyLines(path)
	fmt.Fprintf(w, "\n## %s (%d)\n", title, len(lines))
	if len(lines) == 0 {
		fmt.Fprintln(w, "  —")
		return
	}
	shown := lines
	if max > 0 && len(lines) > max {
		shown = lines[:max]
	}
	for _, l := range shown {
		fmt.Fprintf(w, "  %s\n", l)
	}
	if len(shown) < len(lines) {
		fmt.Fprintf(w, "  … +%d more (see %s)\n", len(lines)-len(shown), path)
	}
}

func reportCount(w io.Writer, title, path string) {
	n := len(readNonEmptyLines(path))
	fmt.Fprintf(w, "\n## %s: %d\n", title, n)
	if n > 0 {
		fmt.Fprintf(w, "  file: %s\n", path)
	}
}

type httpxLine struct {
	URL          string   `json:"url"`
	Input        string   `json:"input"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	Webserver    string   `json:"webserver"`
	Tech         []string `json:"tech"`
	Technologies []string `json:"technologies"`
}

func reportHTTPX(w io.Writer, path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(w, "\n## Live hosts (0)\n  —\n")
		return
	}
	defer f.Close()
	var rows []httpxLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h httpxLine
		if json.Unmarshal([]byte(line), &h) != nil {
			continue
		}
		rows = append(rows, h)
	}
	fmt.Fprintf(w, "\n## Live hosts (%d)\n", len(rows))
	if len(rows) == 0 {
		fmt.Fprintln(w, "  —")
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].StatusCode != rows[j].StatusCode {
			return rows[i].StatusCode < rows[j].StatusCode
		}
		return rows[i].url() < rows[j].url()
	})
	for _, h := range rows {
		extras := []string{}
		if h.Title != "" {
			extras = append(extras, "“"+h.Title+"”")
		}
		if tech := h.techList(); tech != "" {
			extras = append(extras, tech)
		}
		suffix := ""
		if len(extras) > 0 {
			suffix = "  " + strings.Join(extras, " ")
		}
		fmt.Fprintf(w, "  %-3d %s%s\n", h.StatusCode, h.url(), suffix)
	}
}

func (h httpxLine) url() string {
	if h.URL != "" {
		return h.URL
	}
	return h.Input
}

func (h httpxLine) techList() string {
	t := h.Tech
	if len(t) == 0 {
		t = h.Technologies
	}
	if len(t) == 0 && h.Webserver != "" {
		t = []string{h.Webserver}
	}
	if len(t) == 0 {
		return ""
	}
	return "[" + strings.Join(t, ", ") + "]"
}

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Host       string `json:"host"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func reportNuclei(w io.Writer, title, path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(w, "\n## %s (0)\n  —\n", title)
		return
	}
	defer f.Close()
	var rows []nucleiLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var n nucleiLine
		if json.Unmarshal([]byte(line), &n) != nil {
			continue
		}
		rows = append(rows, n)
	}
	fmt.Fprintf(w, "\n## %s (%d)\n", title, len(rows))
	if len(rows) == 0 {
		fmt.Fprintln(w, "  —")
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		return severityRank(rows[i].Info.Severity) < severityRank(rows[j].Info.Severity)
	})
	for _, n := range rows {
		where := n.MatchedAt
		if where == "" {
			where = n.Host
		}
		name := n.Info.Name
		if name == "" {
			name = n.TemplateID
		}
		fmt.Fprintf(w, "  [%-8s] %s → %s\n", strings.ToLower(n.Info.Severity), name, where)
	}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

func reportSecrets(w io.Writer, l Layout) {
	mantra := len(readNonEmptyLines(filepath.Join(l.Secrets, "mantra.txt")))
	jss := len(readNonEmptyLines(filepath.Join(l.Secrets, "jssecrets.txt")))
	th := len(readNonEmptyLines(filepath.Join(l.Secrets, "trufflehog.jsonl")))
	fmt.Fprintf(w, "\n## Secrets (mantra: %d, jssecrets: %d, trufflehog: %d)\n", mantra, jss, th)
	if mantra+jss+th == 0 {
		fmt.Fprintln(w, "  —")
		return
	}
	fmt.Fprintf(w, "  dir: %s\n", l.Secrets)
}

func readNonEmptyLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out
}
