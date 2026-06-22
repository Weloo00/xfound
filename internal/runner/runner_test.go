package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunCapturesStderrAndKillsOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process group kill is unix-specific")
	}
	dir := t.TempDir()
	res := Runner{}.Run(context.Background(), CommandSpec{
		Phase:      "test",
		Tool:       "slow",
		Path:       "/bin/sh",
		Args:       []string{"-c", "echo before >&2; sleep 5; echo after"},
		Timeout:    100 * time.Millisecond,
		StdoutFile: filepath.Join(dir, "out.txt"),
		StderrFile: filepath.Join(dir, "err.txt"),
	})
	if !res.TimedOut {
		t.Fatalf("expected timeout, got %+v", res)
	}
	if !strings.Contains(res.StderrSample, "before") {
		t.Fatalf("stderr sample missing output: %q", res.StderrSample)
	}
	data, err := os.ReadFile(filepath.Join(dir, "err.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "before") {
		t.Fatalf("stderr file missing output: %q", string(data))
	}
}

func TestRenderCommand(t *testing.T) {
	got := Render(CommandSpec{
		Path:       "ffuf",
		Args:       []string{"-u", "https://example.com/FUZZ", "-w", "/tmp/list with spaces.txt"},
		StdoutFile: "/tmp/out.txt",
	})
	if !strings.Contains(got, "ffuf -u https://example.com/FUZZ -w '/tmp/list with spaces.txt' > /tmp/out.txt") {
		t.Fatalf("unexpected render: %s", got)
	}
}
