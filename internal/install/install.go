package install

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"recon-runner/internal/runner"
)

type Step struct {
	Name     string   `json:"name"`
	Command  []string `json:"command,omitempty"`
	CheckBin string   `json:"check_bin,omitempty"`
	CheckDir string   `json:"check_dir,omitempty"`
	Optional bool     `json:"optional"`
}

func Plan(profile, toolsRoot string) ([]Step, error) {
	if profile == "" {
		profile = "bugbounty"
	}
	if profile != "bugbounty" {
		return nil, fmt.Errorf("unknown install profile %q (valid: bugbounty)", profile)
	}
	if toolsRoot == "" {
		toolsRoot = "/root/tools"
	}
	wordlists := filepath.Join(toolsRoot, "wordlists")
	return []Step{
		{Name: "go toolchain", CheckBin: "go"},
		{Name: "python3 toolchain", CheckBin: "python3"},
		{Name: "git", CheckBin: "git"},
		{Name: "create tools directory", Command: []string{"mkdir", "-p", toolsRoot}},
		{Name: "create wordlists directory", Command: []string{"mkdir", "-p", wordlists}},
		{Name: "SecLists", CheckDir: filepath.Join(wordlists, "SecLists"), Command: []string{"git", "clone", "https://github.com/danielmiessler/SecLists.git", filepath.Join(wordlists, "SecLists")}},
		{Name: "subfinder", CheckBin: "subfinder", Command: []string{"go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}},
		{Name: "httpx", CheckBin: "httpx", Command: []string{"go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"}},
		{Name: "dnsx", CheckBin: "dnsx", Command: []string{"go", "install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}},
		{Name: "naabu", CheckBin: "naabu", Command: []string{"go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}},
		{Name: "nuclei", CheckBin: "nuclei", Command: []string{"go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}},
		{Name: "katana", CheckBin: "katana", Command: []string{"go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"}},
		{Name: "waybackurls", CheckBin: "waybackurls", Command: []string{"go", "install", "github.com/tomnomnom/waybackurls@latest"}},
		{Name: "meg", CheckBin: "meg", Command: []string{"go", "install", "github.com/tomnomnom/meg@latest"}},
		{Name: "ffuf", CheckBin: "ffuf", Command: []string{"go", "install", "github.com/ffuf/ffuf/v2@latest"}},
		{Name: "gau", CheckBin: "gau", Command: []string{"go", "install", "github.com/lc/gau/v2/cmd/gau@latest"}},
		{Name: "gobuster", CheckBin: "gobuster", Command: []string{"go", "install", "github.com/OJ/gobuster/v3@latest"}},
		{Name: "lazyrecon source", Optional: true, CheckDir: filepath.Join(toolsRoot, "lazyrecon"), Command: []string{"git", "clone", "https://github.com/nahamsec/lazyrecon.git", filepath.Join(toolsRoot, "lazyrecon")}},
		{Name: "bbht source", Optional: true, CheckDir: filepath.Join(toolsRoot, "bbht"), Command: []string{"git", "clone", "https://github.com/nahamsec/bbht.git", filepath.Join(toolsRoot, "bbht")}},
		{Name: "JSParser source", Optional: true, CheckDir: filepath.Join(toolsRoot, "JSParser"), Command: []string{"git", "clone", "https://github.com/nahamsec/JSParser.git", filepath.Join(toolsRoot, "JSParser")}},
		{Name: "crtndstry source", Optional: true, CheckDir: filepath.Join(toolsRoot, "crtndstry"), Command: []string{"git", "clone", "https://github.com/nahamsec/crtndstry.git", filepath.Join(toolsRoot, "crtndstry")}},
	}, nil
}

func Run(ctx context.Context, w io.Writer, profile, toolsRoot string, dryRun bool) error {
	steps, err := Plan(profile, toolsRoot)
	if err != nil {
		return err
	}
	r := runner.Runner{}
	for _, step := range steps {
		if satisfied(step) {
			fmt.Fprintf(w, "ok      %s\n", step.Name)
			continue
		}
		if len(step.Command) == 0 {
			if step.Optional {
				fmt.Fprintf(w, "skip    %s (optional missing)\n", step.Name)
				continue
			}
			return fmt.Errorf("%s is missing and has no install command", step.Name)
		}
		fmt.Fprintf(w, "install %s: %s\n", step.Name, strings.Join(step.Command, " "))
		if dryRun {
			continue
		}
		spec := runner.CommandSpec{
			Phase:        "install",
			Tool:         step.Name,
			Path:         step.Command[0],
			Args:         step.Command[1:],
			Timeout:      30 * time.Minute,
			TimeoutLabel: (30 * time.Minute).String(),
			StdoutFile:   filepath.Join(os.TempDir(), "reconctl-install-"+sanitize(step.Name)+".out"),
			StderrFile:   filepath.Join(os.TempDir(), "reconctl-install-"+sanitize(step.Name)+".err"),
		}
		res := r.Run(ctx, spec)
		if res.TimedOut {
			return fmt.Errorf("%s timed out", step.Name)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("%s failed: %s", step.Name, res.Error)
		}
	}
	return nil
}

func satisfied(step Step) bool {
	if step.CheckBin != "" {
		_, err := exec.LookPath(step.CheckBin)
		return err == nil
	}
	if step.CheckDir != "" {
		info, err := os.Stat(step.CheckDir)
		return err == nil && info.IsDir()
	}
	return false
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	replacer := strings.NewReplacer("/", "-", " ", "-", ":", "-", "\\", "-")
	return replacer.Replace(s)
}
