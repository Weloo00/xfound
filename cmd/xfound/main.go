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
	case "status":
		return runStatus(args[1:])
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	manager := pipeline.Manager{}
	meta, err := manager.Run(ctx, pipeline.Options{
		Target:        *target,
		ScopeFile:     *scopeFile,
		ProfileName:   *profileName,
		Phase:         *phase,
		DryRun:        *dryRun,
		Resume:        *resume,
		OutputRoot:    *outputRoot,
		WordlistsRoot: *wordlistsRoot,
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

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  xfound inventory
  xfound install --profile bugbounty --dry-run
  xfound run --target example.com --scope scope.txt --profile fast --dry-run
  xfound status --target example.com

options:
  -h, --help    show help`)
}
