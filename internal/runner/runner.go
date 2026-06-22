package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type CommandSpec struct {
	Phase        string        `json:"phase"`
	Tool         string        `json:"tool"`
	Path         string        `json:"path"`
	Args         []string      `json:"args"`
	Dir          string        `json:"dir,omitempty"`
	Env          []string      `json:"env,omitempty"`
	StdinFile    string        `json:"stdin_file,omitempty"`
	StdoutFile   string        `json:"stdout_file,omitempty"`
	StderrFile   string        `json:"stderr_file,omitempty"`
	Timeout      time.Duration `json:"-"`
	TimeoutLabel string        `json:"timeout"`
	Optional     bool          `json:"optional"`
	RequiresFile string        `json:"requires_file,omitempty"`
}

type Result struct {
	Phase        string    `json:"phase"`
	Tool         string    `json:"tool"`
	Command      []string  `json:"command"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	DurationMS   int64     `json:"duration_ms"`
	Timeout      string    `json:"timeout"`
	ExitCode     int       `json:"exit_code"`
	TimedOut     bool      `json:"timed_out"`
	Skipped      bool      `json:"skipped"`
	SkipReason   string    `json:"skip_reason,omitempty"`
	Error        string    `json:"error,omitempty"`
	StdoutFile   string    `json:"stdout_file,omitempty"`
	StderrFile   string    `json:"stderr_file,omitempty"`
	StdoutSample string    `json:"stdout_sample,omitempty"`
	StderrSample string    `json:"stderr_sample,omitempty"`
}

type Runner struct{}

func (Runner) Run(parent context.Context, spec CommandSpec) Result {
	if spec.TimeoutLabel == "" && spec.Timeout > 0 {
		spec.TimeoutLabel = spec.Timeout.String()
	}
	res := Result{
		Phase:      spec.Phase,
		Tool:       spec.Tool,
		Command:    append([]string{spec.Path}, spec.Args...),
		StartedAt:  time.Now().UTC(),
		Timeout:    spec.TimeoutLabel,
		ExitCode:   -1,
		StdoutFile: spec.StdoutFile,
		StderrFile: spec.StderrFile,
	}
	defer func() {
		res.FinishedAt = time.Now().UTC()
		res.DurationMS = res.FinishedAt.Sub(res.StartedAt).Milliseconds()
	}()

	if spec.Path == "" {
		res.Skipped = true
		res.SkipReason = "missing command path"
		return res
	}
	if spec.RequiresFile != "" && !fileExists(spec.RequiresFile) {
		res.Skipped = true
		res.SkipReason = "required input file is missing: " + spec.RequiresFile
		return res
	}

	ctx := parent
	cancel := func() {}
	if spec.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, spec.Timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if spec.Dir != "" {
		cmd.Dir = spec.Dir
	}
	if len(spec.Env) > 0 {
		cmd.Env = append(os.Environ(), spec.Env...)
	}

	var stdoutBuf, stderrBuf limitBuffer
	stdout, stdoutClose, err := outputWriter(spec.StdoutFile, &stdoutBuf)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer stdoutClose()
	stderr, stderrClose, err := outputWriter(spec.StderrFile, &stderrBuf)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer stderrClose()
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if spec.StdinFile != "" {
		f, err := os.Open(spec.StdinFile)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		defer f.Close()
		cmd.Stdin = f
	}

	if err := cmd.Start(); err != nil {
		res.Error = err.Error()
		res.StderrSample = stderrBuf.String()
		return res
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		res.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
	}

	if waitErr != nil {
		res.Error = waitErr.Error()
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		}
	} else {
		res.ExitCode = 0
	}
	res.StdoutSample = stdoutBuf.String()
	res.StderrSample = stderrBuf.String()
	return res
}

func Render(spec CommandSpec) string {
	parts := append([]string{spec.Path}, spec.Args...)
	for i, part := range parts {
		parts[i] = shellQuote(part)
	}
	if spec.StdinFile != "" {
		parts = append(parts, "<", shellQuote(spec.StdinFile))
	}
	if spec.StdoutFile != "" {
		parts = append(parts, ">", shellQuote(spec.StdoutFile))
	}
	return strings.Join(parts, " ")
}

func outputWriter(path string, sample *limitBuffer) (io.Writer, func(), error) {
	if path == "" {
		return sample, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return io.MultiWriter(f, sample), func() { _ = f.Close() }, nil
}

type limitBuffer struct {
	buf bytes.Buffer
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	const max = 4096
	n := len(p)
	if b.buf.Len() < max {
		remaining := max - b.buf.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return n, nil
}

func (b *limitBuffer) String() string {
	return b.buf.String()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || r == ':' || r == '=' || r == ',' || r == '@' || r == '+' || r == '%' || r == '*' || r == '~' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func SkipResult(spec CommandSpec, reason string) Result {
	now := time.Now().UTC()
	return Result{
		Phase:      spec.Phase,
		Tool:       spec.Tool,
		Command:    append([]string{spec.Path}, spec.Args...),
		StartedAt:  now,
		FinishedAt: now,
		Timeout:    spec.TimeoutLabel,
		ExitCode:   -1,
		Skipped:    true,
		SkipReason: reason,
		StdoutFile: spec.StdoutFile,
		StderrFile: spec.StderrFile,
	}
}

func ErrorResult(spec CommandSpec, err error) Result {
	now := time.Now().UTC()
	return Result{
		Phase:      spec.Phase,
		Tool:       spec.Tool,
		Command:    append([]string{spec.Path}, spec.Args...),
		StartedAt:  now,
		FinishedAt: now,
		Timeout:    spec.TimeoutLabel,
		ExitCode:   -1,
		Error:      fmt.Sprint(err),
		StdoutFile: spec.StdoutFile,
		StderrFile: spec.StderrFile,
	}
}
