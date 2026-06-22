package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"recon-runner/internal/profiles"
	"recon-runner/internal/runner"
)

type recordingRunner struct {
	results []runner.Result
}

func (r *recordingRunner) Run(_ context.Context, spec runner.CommandSpec) runner.Result {
	now := time.Now().UTC()
	r.results = append(r.results, runner.Result{
		Phase:      spec.Phase,
		Tool:       spec.Tool,
		Command:    append([]string{spec.Path}, spec.Args...),
		StartedAt:  now,
		FinishedAt: now,
		ExitCode:   0,
		Timeout:    spec.TimeoutLabel,
		StdoutFile: spec.StdoutFile,
		StderrFile: spec.StderrFile,
	})
	return r.results[len(r.results)-1]
}

func TestMissingToolBehaviorMarksRequiredPhaseFailedAndOptionalSkipped(t *testing.T) {
	dir := t.TempDir()
	scopeFile := writeFile(t, dir, "scope.txt", "example.com\n")
	profile, _ := profiles.Get(profiles.Fast)

	meta, err := (Manager{Locator: StaticLocator{}, Executor: &recordingRunner{}}).Run(context.Background(), Options{
		Target:        "example.com",
		ScopeFile:     scopeFile,
		Profile:       profile,
		Phase:         "alive",
		OutputRoot:    filepath.Join(dir, "Targets"),
		WordlistsRoot: filepath.Join(dir, "wordlists"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Phases[0].Status != "failed" {
		t.Fatalf("required missing phase status=%s want failed", meta.Phases[0].Status)
	}
	if meta.Missing["httpx"] != "alive" {
		t.Fatalf("missing httpx not recorded: %+v", meta.Missing)
	}

	meta, err = (Manager{Locator: StaticLocator{}, Executor: &recordingRunner{}}).Run(context.Background(), Options{
		Target:        "example.com",
		ScopeFile:     scopeFile,
		Profile:       profile,
		Phase:         "urls",
		OutputRoot:    filepath.Join(dir, "Targets2"),
		WordlistsRoot: filepath.Join(dir, "wordlists"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Phases[0].Status != "skipped" {
		t.Fatalf("optional missing phase status=%s want skipped", meta.Phases[0].Status)
	}
}

func TestDryRunRendersCommandsWithoutExecutingNetworkTools(t *testing.T) {
	dir := t.TempDir()
	scopeFile := writeFile(t, dir, "scope.txt", "spendesk.com\n")
	wordlists := filepath.Join(dir, "wordlists")
	writeFile(t, wordlists, "Discovery/Web-Content/raft-small.txt", "admin\n")
	writeFile(t, wordlists, "Discovery/DNS/subdomains.txt", "www\n")
	profile, _ := profiles.Get(profiles.Fast)
	rec := &recordingRunner{}

	meta, err := (Manager{Locator: StaticLocator{}, Executor: rec}).Run(context.Background(), Options{
		Target:        "spendesk.com",
		ScopeFile:     scopeFile,
		Profile:       profile,
		DryRun:        true,
		OutputRoot:    filepath.Join(dir, "Targets"),
		WordlistsRoot: wordlists,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.results) != 0 {
		t.Fatal("dry run executed commands")
	}
	if len(meta.DryRunPlan) == 0 {
		t.Fatal("expected dry-run commands")
	}
	var sawSubfinder bool
	for _, cmd := range meta.DryRunPlan {
		if cmd.Tool == "subfinder" && strings.Contains(cmd.Command, "spendesk.com") {
			sawSubfinder = true
		}
	}
	if !sawSubfinder {
		t.Fatalf("dry-run plan did not include subfinder target: %+v", meta.DryRunPlan)
	}
}

func TestResumeSkipsCompletedPhase(t *testing.T) {
	dir := t.TempDir()
	scopeFile := writeFile(t, dir, "scope.txt", "example.com\n")
	outRoot := filepath.Join(dir, "Targets")
	layout := NewLayout(outRoot, "example.com")
	if err := ensureLayout(layout); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := SaveMetadata(layout.Root, &RunMetadata{
		Target:    "example.com",
		Profile:   "fast",
		OutputDir: layout.Root,
		StartedAt: now,
		UpdatedAt: now,
		Phases: []PhaseRun{{
			Name:       "urls",
			Status:     "completed",
			StartedAt:  now,
			FinishedAt: now,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	rec := &recordingRunner{}
	profile, _ := profiles.Get(profiles.Fast)
	meta, err := (Manager{Locator: StaticLocator{"waybackurls": "/bin/echo"}, Executor: rec}).Run(context.Background(), Options{
		Target:     "example.com",
		ScopeFile:  scopeFile,
		Profile:    profile,
		Phase:      "urls",
		Resume:     true,
		OutputRoot: outRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.results) != 0 {
		t.Fatal("resume should not execute completed phase")
	}
	if meta.Phases[0].Status != "skipped" || !strings.Contains(meta.Phases[0].Reason, "resume") {
		t.Fatalf("unexpected resume phase: %+v", meta.Phases[0])
	}
}

func writeFile(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
