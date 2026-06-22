package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowlistBlocksOutOfScopeTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("example.com\n*.example.org\n10.0.0.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"https://example.com/login", true},
		{"api.example.org", true},
		{"example.org", false},
		{"10.0.0.5", true},
		{"spendesk.com", false},
	}
	for _, tt := range tests {
		if got := a.Allows(tt.target); got != tt.want {
			t.Fatalf("Allows(%q)=%v want %v", tt.target, got, tt.want)
		}
	}
}

func TestLoadRequiresEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("# comments only\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected empty scope to fail")
	}
}
