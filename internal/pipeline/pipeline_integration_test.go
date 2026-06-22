package pipeline

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"recon-runner/internal/profiles"
)

func TestIntegrationFakeCommandsTimeoutStderrResumeAndStatus(t *testing.T) {
	dir := t.TempDir()
	scopeFile := writeFile(t, dir, "scope.txt", "example.com\n")
	wordlists := filepath.Join(dir, "wordlists")
	writeFile(t, wordlists, "Discovery/DNS/subdomains.txt", "www\nmail\n")
	fakeDir := filepath.Join(dir, "bin")
	subfinder := writeExecutable(t, fakeDir, "subfinder", "#!/bin/sh\necho subfinder-stderr >&2\necho www.example.com\n")
	// dnscan is the slow optional tool that should be killed on timeout.
	dnscan := writeExecutable(t, fakeDir, "dnscan", "#!/bin/sh\necho dnscan-before-timeout >&2\nsleep 5\n")
	profile := profiles.Profile{
		Name: "test",
		ToolBudgets: map[string]time.Duration{
			"subfinder": time.Second,
			"dnscan":    100 * time.Millisecond,
		},
	}

	meta, err := (Manager{Locator: StaticLocator{
		"subfinder": subfinder,
		"dnscan":    dnscan,
	}}).Run(context.Background(), Options{
		Target:        "example.com",
		ScopeFile:     scopeFile,
		Profile:       profile,
		Phase:         "subdomains",
		OutputRoot:    filepath.Join(dir, "Targets"),
		WordlistsRoot: wordlists,
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Phases[0].Status != "completed" {
		t.Fatalf("phase status=%s reason=%s", meta.Phases[0].Status, meta.Phases[0].Reason)
	}
	if meta.Timeouts["dnscan"] != "subdomains" {
		t.Fatalf("dnscan timeout not recorded: %+v", meta.Timeouts)
	}
	errData, err := os.ReadFile(filepath.Join(dir, "Targets", "example.com", "errors", "subdomains-dnscan.stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(errData), "dnscan-before-timeout") {
		t.Fatalf("stderr not captured: %q", string(errData))
	}

	status, err := Status("example.com", filepath.Join(dir, "Targets"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := PrintStatus(&out, status, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "killed-on-timeout") || !strings.Contains(out.String(), "subdomains: 1") {
		t.Fatalf("status output missing timeout/counts:\n%s", out.String())
	}

	resumed, err := (Manager{Locator: StaticLocator{}}).Run(context.Background(), Options{
		Target:     "example.com",
		ScopeFile:  scopeFile,
		Profile:    profile,
		Phase:      "subdomains",
		Resume:     true,
		OutputRoot: filepath.Join(dir, "Targets"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Phases[0].Status != "skipped" || !strings.Contains(resumed.Phases[0].Reason, "resume") {
		t.Fatalf("resume did not skip completed phase: %+v", resumed.Phases[0])
	}
}

func writeExecutable(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
