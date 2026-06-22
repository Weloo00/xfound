package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadToolsMapOverridesPath(t *testing.T) {
	dir := t.TempDir()
	mapFile := filepath.Join(dir, "tools.json")
	content := `{"paramspider":"/root/tools/ParamSpider/paramspider.py","empty":""}`
	if err := os.WriteFile(mapFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loc, err := LoadToolsMap(mapFile)
	if err != nil {
		t.Fatal(err)
	}
	if path, ok := loc.Path("paramspider"); !ok || path != "/root/tools/ParamSpider/paramspider.py" {
		t.Fatalf("paramspider not mapped: %q ok=%v", path, ok)
	}
	if _, ok := loc.Path("empty"); ok {
		t.Fatal("empty mapping should not resolve")
	}
}

func TestLoadToolsMapEmptyPathReturnsNil(t *testing.T) {
	loc, err := LoadToolsMap("")
	if err != nil {
		t.Fatal(err)
	}
	if loc != nil {
		t.Fatalf("expected nil locator, got %v", loc)
	}
}

func TestChainLocatorPrefersFirstMatch(t *testing.T) {
	chain := ChainLocator{
		StaticLocator{"httpx": "/override/httpx"},
		StaticLocator{"httpx": "/usr/bin/httpx", "gau": "/usr/bin/gau"},
	}
	if path, _ := chain.Path("httpx"); path != "/override/httpx" {
		t.Fatalf("chain did not prefer first match: %q", path)
	}
	if path, _ := chain.Path("gau"); path != "/usr/bin/gau" {
		t.Fatalf("chain did not fall through: %q", path)
	}
	if _, ok := chain.Path("missing"); ok {
		t.Fatal("missing tool should not resolve")
	}
}

func TestFilterByExtSelectsJSURLs(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "all.txt")
	out := filepath.Join(dir, "js-urls.txt")
	body := "https://x.com/app.js\nhttps://x.com/style.css\nhttps://x.com/a.js?v=1\nhttps://x.com/page\n"
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filterByExt(in, out, ".js"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"app.js", "a.js?v=1"} {
		if !contains(splitLines(got), "https://x.com/"+want) {
			t.Fatalf("expected %s in output, got:\n%s", want, got)
		}
	}
	if contains(splitLines(got), "https://x.com/style.css") {
		t.Fatalf("css should be filtered out:\n%s", got)
	}
}

func TestExtractShodanDomainJoinsHostsToApex(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "shodan-raw.txt")
	out := filepath.Join(dir, "shodan.txt")
	raw := "SPENDESK.COM\n\n" +
		"                         A      75.2.60.5\n" +
		"                         MX     aspmx.l.google.com\n" +
		"www                      A      1.2.3.4\n" +
		"api                      CNAME  x.cloudfront.net\n" +
		"*.dev                    A      9.9.9.9\n" +
		"app.spendesk.com         A      2.2.2.2\n"
	if err := os.WriteFile(in, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractShodanDomain(in, out, "spendesk.com"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	got := splitLines(string(data))
	want := []string{"api.spendesk.com", "app.spendesk.com", "www.spendesk.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAppendSubdomainsFiltersNoise(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "dnscan.txt")
	out := filepath.Join(dir, "all.txt")
	noisy := strings.Join([]string{
		"www.spendesk.com",
		"API.Spendesk.com", // case-insensitive dedupe to api?
		"api.spendesk.com",
		"75.2.60.5",      // IP — drop
		"10",             // number — drop
		"[*]",            // banner — drop
		"MS=ms77763507",  // TXT value — drop
		"evil.com",       // out of scope — drop
		"spendesk.com",   // apex — keep
		"a.b.spendesk.com",
	}, "\n") + "\n"
	if err := os.WriteFile(in, []byte(noisy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := appendSubdomains(out, "spendesk.com", in); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	got := splitLines(string(data))
	want := []string{"a.b.spendesk.com", "api.spendesk.com", "spendesk.com", "www.spendesk.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range filepathSplit(s) {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func filepathSplit(s string) []string {
	var lines []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
