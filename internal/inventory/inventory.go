package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"recon-runner/internal/profiles"
	"recon-runner/internal/wordlists"
)

type ToolDef struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Family   string `json:"family"`
}

type ToolStatus struct {
	ToolDef
	Path    string `json:"path,omitempty"`
	Present bool   `json:"present"`
}

type PathStatus struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Present bool   `json:"present"`
}

type Inventory struct {
	Tools       []ToolStatus        `json:"tools"`
	SourceTrees []PathStatus        `json:"source_trees"`
	Templates   PathStatus          `json:"templates"`
	Wordlists   wordlists.Inventory `json:"wordlists"`
}

type Options struct {
	ToolsRoot     string
	WordlistsRoot string
	TemplatesRoot string
}

func Detect(opts Options) Inventory {
	if opts.ToolsRoot == "" {
		opts.ToolsRoot = "/root/tools"
	}
	if opts.WordlistsRoot == "" {
		opts.WordlistsRoot = filepath.Join(opts.ToolsRoot, "wordlists")
	}
	if opts.TemplatesRoot == "" {
		opts.TemplatesRoot = "/root/nuclei-templates"
	}
	var tools []ToolStatus
	for _, def := range ToolDefs() {
		path, err := exec.LookPath(def.Name)
		tools = append(tools, ToolStatus{
			ToolDef: def,
			Path:    path,
			Present: err == nil,
		})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	sources := []PathStatus{
		pathStatus("SecLists", filepath.Join(opts.WordlistsRoot, "SecLists")),
		pathStatus("WordList", filepath.Join(opts.WordlistsRoot, "WordList")),
		pathStatus("lazyrecon", filepath.Join(opts.ToolsRoot, "lazyrecon")),
		pathStatus("bbht", filepath.Join(opts.ToolsRoot, "bbht")),
		pathStatus("JSParser", filepath.Join(opts.ToolsRoot, "JSParser")),
		pathStatus("crtndstry", filepath.Join(opts.ToolsRoot, "crtndstry")),
		pathStatus("ParamSpider", filepath.Join(opts.ToolsRoot, "ParamSpider")),
		pathStatus("GitDorker", filepath.Join(opts.ToolsRoot, "GitDorker")),
		pathStatus("altdns", filepath.Join(opts.ToolsRoot, "altdns")),
		pathStatus("dnscan", filepath.Join(opts.ToolsRoot, "dnscan")),
		pathStatus("kiterunner", filepath.Join(opts.ToolsRoot, "kiterunner")),
		pathStatus("mantra", filepath.Join(opts.ToolsRoot, "mantra")),
		pathStatus("jssecrets", filepath.Join(opts.ToolsRoot, "jssecrets")),
		pathStatus("waymore", filepath.Join(opts.ToolsRoot, "waymore")),
		pathStatus("lazyegg", filepath.Join(opts.ToolsRoot, "lazyegg")),
		pathStatus("shortscan", filepath.Join(opts.ToolsRoot, "shortscan")),
	}
	return Inventory{
		Tools:       tools,
		SourceTrees: sources,
		Templates:   pathStatus("nuclei-templates", opts.TemplatesRoot),
		Wordlists:   wordlists.Classify(opts.WordlistsRoot, 12),
	}
}

func ToolDefs() []ToolDef {
	required := map[string]bool{
		"httpx":     true,
		"subfinder": true,
	}
	family := map[string]string{
		"subfinder":   "subdomains",
		"amass":       "subdomains",
		"crtndstry":   "subdomains",
		"dnsgen":      "dns",
		"dnsx":        "dns",
		"puredns":     "dns",
		"shuffledns":  "dns",
		"massdns":     "dns",
		"httpx":       "alive",
		"waybackurls": "urls",
		"gau":         "urls",
		"gauplus":     "urls",
		"katana":      "crawl",
		"hakrawler":   "crawl",
		"gospider":    "crawl",
		"JSParser":    "js",
		"lazyegg":     "js",
		"naabu":       "ports",
		"nuclei":      "nuclei",
		"ffuf":        "fuzz",
		"gobuster":    "fuzz",
		"dirsearch":   "fuzz",
		"shortscan":   "fuzz",
		"arjun":       "params",
		"paramspider": "params",
		"kiterunner":  "api",
		"meg":         "meg",
		"trufflehog":  "secrets",
		"mantra":      "secrets",
		"jssecrets":   "secrets",
		"gitdorker":   "intel",
		"altdns":      "dns",
		"dnscan":      "dns",
		"shodan":      "subdomains",
		"waymore":     "urls",
		"lazyrecon":   "compat",
		"bbht":        "install",
	}
	var defs []ToolDef
	for _, name := range profiles.SupportedTools() {
		defs = append(defs, ToolDef{Name: name, Required: required[name], Family: family[name]})
	}
	return defs
}

func (i Inventory) Path(name string) (string, bool) {
	for _, t := range i.Tools {
		if t.Name == name && t.Present {
			return t.Path, true
		}
	}
	return "", false
}

func Print(w io.Writer, inv Inventory, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tSTATUS\tPATH\tFAMILY")
	for _, t := range inv.Tools {
		status := "missing"
		if t.Present {
			status = "present"
		}
		req := ""
		if t.Required {
			req = " required"
		}
		fmt.Fprintf(tw, "%s\t%s%s\t%s\t%s\n", t.Name, status, req, t.Path, t.Family)
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "RESOURCE\tSTATUS\tPATH")
	for _, s := range inv.SourceTrees {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, presentText(s.Present), s.Path)
	}
	fmt.Fprintf(tw, "%s\t%s\t%s\n", inv.Templates.Name, presentText(inv.Templates.Present), inv.Templates.Path)
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "WORDLIST CATEGORY\tCOUNT\tEXAMPLES")
	for _, c := range inv.Wordlists.Categories {
		example := ""
		if len(c.Files) > 0 {
			example = c.Files[0]
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\n", c.Name, len(c.Files), example)
	}
	return tw.Flush()
}

func pathStatus(name, path string) PathStatus {
	info, err := os.Stat(path)
	return PathStatus{Name: name, Path: path, Present: err == nil && info != nil}
}

func presentText(ok bool) string {
	if ok {
		return "present"
	}
	return "missing"
}
