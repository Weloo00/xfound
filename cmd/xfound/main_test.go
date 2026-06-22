package main

import (
	"strings"
	"testing"
)

func TestSplitTargetExtractsDomainInAnyPosition(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantTarget string
		wantRest   string
	}{
		{"target first", []string{"example.com", "--dry-run"}, "example.com", "--dry-run"},
		{"target last", []string{"--dry-run", "example.com"}, "example.com", "--dry-run"},
		{"flag with value before target", []string{"--profile", "fast", "example.com", "--dry-run"}, "example.com", "--profile fast --dry-run"},
		{"flag=value form", []string{"--profile=fast", "example.com"}, "example.com", "--profile=fast"},
		{"no target", []string{"--dry-run"}, "", "--dry-run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotTarget, gotRest := splitTarget(c.args)
			if gotTarget != c.wantTarget {
				t.Fatalf("target = %q, want %q", gotTarget, c.wantTarget)
			}
			if strings.Join(gotRest, " ") != c.wantRest {
				t.Fatalf("rest = %q, want %q", strings.Join(gotRest, " "), c.wantRest)
			}
		})
	}
}
