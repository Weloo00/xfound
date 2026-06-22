package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"recon-runner/internal/install"
	"recon-runner/internal/inventory"
	"recon-runner/internal/pipeline"
	"recon-runner/internal/profiles"
)

const version = "0.2.0"

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xfound:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return flag.ErrHelp
	}
	switch args[0] {
	case "inventory":
		return runInventory(args[1:])
	case "install":
		return runInstall(ctx, args[1:])
	case "run":
		return runPipeline(ctx, args[1:])
	case "hunt":
		return runHunt(ctx, args[1:])
	case "status":
		return runStatus(args[1:])
	case "phases":
		return runPhases(args[1:])
	case "version":
		fmt.Println("xfound", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	toolsRoot := fs.String("tools-root", "/root/tools", "tools root")
	wordlistsRoot := fs.String("wordlists-root", "/root/tools/wordlists", "wordlists root")
	templatesRoot := fs.String("templates-root", "/root/nuclei-templates", "nuclei templates root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inv := inventory.Detect(inventory.Options{
		ToolsRoot:     *toolsRoot,
		WordlistsRoot: *wordlistsRoot,
		TemplatesRoot: *templatesRoot,
	})
	return inventory.Print(os.Stdout, inv, *asJSON)
}

func runInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	profile := fs.String("profile", "bugbounty", "install profile")
	toolsRoot := fs.String("tools-root", "/root/tools", "tools root")
	dryRun := fs.Bool("dry-run", false, "print steps without executing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return install.Run(ctx, os.Stdout, *profile, *toolsRoot, *dryRun)
}

func runPipeline(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	target := fs.String("target", "", "authorized target domain")
	scopeFile := fs.String("scope", "", "scope allowlist file")
	profileName := fs.String("profile", profiles.Normal, "scan profile: fast, normal, deep")
	phase := fs.String("phase", "", "single phase to run")
	dryRun := fs.Bool("dry-run", false, "render commands without executing")
	resume := fs.Bool("resume", true, "skip completed phases")
	outputRoot := fs.String("output-root", "/root/Targets", "target output root")
	wordlistsRoot := fs.String("wordlists-root", "/root/tools/wordlists", "wordlists root")
	toolsMap := fs.String("tools-map", "", "JSON file mapping tool names to executable paths/wrappers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	manager := pipeline.Manager{}
	if !*dryRun {
		manager.Progress = os.Stderr
	}
	meta, err := manager.Run(ctx, pipeline.Options{
		Target:        *target,
		ScopeFile:     *scopeFile,
		ProfileName:   *profileName,
		Phase:         *phase,
		DryRun:        *dryRun,
		Resume:        *resume,
		OutputRoot:    *outputRoot,
		WordlistsRoot: *wordlistsRoot,
		ToolsMapFile:  *toolsMap,
	})
	if err != nil {
		return err
	}
	if *dryRun {
		pipeline.PrintDryRun(os.Stdout, meta)
		return nil
	}
	return pipeline.PrintStatus(os.Stdout, meta, false)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	target := fs.String("target", "", "target domain")
	outputRoot := fs.String("output-root", "/root/Targets", "target output root")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	meta, err := pipeline.Status(*target, *outputRoot)
	if err != nil {
		return err
	}
	return pipeline.PrintStatus(os.Stdout, meta, *asJSON)
}

// runHunt is the easy one-command entrypoint:
//
//	xfound hunt spendesk.com
//
// It auto-scopes the apex + subdomains (no scope file needed), auto-loads a
// tools.json from the cwd or /root/.xfound/tools.json if present, and runs the
// full pipeline. Add --dry-run to preview, or --phase <name> for one phase.
func runHunt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("hunt", flag.ExitOnError)
	profileName := fs.String("profile", profiles.Normal, "scan profile: fast, normal, deep")
	phase := fs.String("phase", "", "single phase to run (default: all)")
	dryRun := fs.Bool("dry-run", false, "render commands without executing")
	resume := fs.Bool("resume", true, "skip completed phases")
	outputRoot := fs.String("output-root", "/root/Targets", "target output root")
	wordlistsRoot := fs.String("wordlists-root", "/root/tools/wordlists", "wordlists root")
	toolsMap := fs.String("tools-map", "", "JSON file mapping tool names to executable paths")
	// Accept the target in any position (e.g. `hunt example.com --dry-run` or
	// `hunt --dry-run example.com`). Go's flag package stops at the first
	// positional, so pull the bare domain out before parsing the flags.
	target, rest := splitTarget(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if target == "" {
		target = fs.Arg(0)
	}
	if target == "" {
		return fmt.Errorf("usage: xfound hunt <target> [--profile fast|normal|deep] [--dry-run]")
	}
	if *toolsMap == "" {
		*toolsMap = defaultToolsMap()
	}
	manager := pipeline.Manager{}
	if !*dryRun {
		manager.Progress = os.Stderr
	}
	meta, err := manager.Run(ctx, pipeline.Options{
		Target:        target,
		ProfileName:   *profileName,
		Phase:         *phase,
		DryRun:        *dryRun,
		Resume:        *resume,
		OutputRoot:    *outputRoot,
		WordlistsRoot: *wordlistsRoot,
		ToolsMapFile:  *toolsMap,
		AutoScope:     true,
	})
	if err != nil {
		return err
	}
	if *dryRun {
		pipeline.PrintDryRun(os.Stdout, meta)
		return nil
	}
	return pipeline.PrintStatus(os.Stdout, meta, false)
}

// splitTarget pulls the first bare (non-dash) argument out of args, returning
// it as the target plus the remaining args (flags) in original order. A token
// immediately following a known value-flag is treated as that flag's value, not
// the target.
func splitTarget(args []string) (string, []string) {
	valueFlags := map[string]bool{
		"--profile": true, "-profile": true,
		"--phase": true, "-phase": true,
		"--output-root": true, "-output-root": true,
		"--wordlists-root": true, "-wordlists-root": true,
		"--tools-map": true, "-tools-map": true,
	}
	target := ""
	var rest []string
	expectValue := false
	for _, a := range args {
		switch {
		case expectValue:
			rest = append(rest, a)
			expectValue = false
		case len(a) > 0 && a[0] == '-':
			rest = append(rest, a)
			if valueFlags[a] && !containsRune(a, '=') {
				expectValue = true
			}
		case target == "":
			target = a
		default:
			rest = append(rest, a)
		}
	}
	return target, rest
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

// defaultToolsMap returns the first existing default tools-map path, or "".
func defaultToolsMap() string {
	for _, p := range []string{"tools.json", "/root/.xfound/tools.json"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func runPhases(args []string) error {
	fs := flag.NewFlagSet("phases", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, name := range pipeline.PhaseOrder() {
		fmt.Println(name)
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  xfound hunt example.com                 # easy: auto-scope + run everything
  xfound hunt example.com --dry-run       # preview the commands first
  xfound hunt example.com --profile fast  # quicker, shorter timeouts
  xfound status --target example.com      # progress + output counts
  xfound inventory                        # what tools/wordlists are installed
  xfound install --profile bugbounty --dry-run
  xfound run --target example.com --scope scope.txt --phase secrets
  xfound phases
  xfound version

options:
  -h, --help    show help`)
}
