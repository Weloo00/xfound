package wordlists

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

type Category struct {
	Name  string   `json:"name"`
	Files []string `json:"files"`
}

type Inventory struct {
	Root       string     `json:"root"`
	Categories []Category `json:"categories"`
}

func Classify(root string, maxPerCategory int) Inventory {
	cats := map[string][]string{
		"dns":         {},
		"web-content": {},
		"params":      {},
		"fuzzing":     {},
		"resolvers":   {},
		"usernames":   {},
		"passwords":   {},
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(filepath.Base(path), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !isLikelyWordlist(path) {
			return nil
		}
		name := strings.ToLower(filepath.Base(path))
		full := strings.ToLower(path)
		add := func(cat string) {
			cats[cat] = append(cats[cat], path)
		}
		switch {
		case strings.Contains(full, "resolver"):
			add("resolvers")
		case containsAny(full, "subdomain", "subdomains", "dns", "bitquark"):
			add("dns")
		case containsAny(full, "directory", "directories", "raft", "content", "dirbuster") || containsAny(name, "files", "small", "medium", "large"):
			add("web-content")
		case strings.Contains(full, "param"):
			add("params")
		case containsAny(full, "payload", "fuzz", "xss", "sqli", "lfi", "burp"):
			add("fuzzing")
		case strings.Contains(full, "user"):
			add("usernames")
		case containsAny(full, "password", "passw"):
			add("passwords")
		}
		return nil
	})

	var out []Category
	for _, name := range []string{"dns", "web-content", "params", "fuzzing", "resolvers", "usernames", "passwords"} {
		files := cats[name]
		sortWordlists(name, files)
		if maxPerCategory > 0 && len(files) > maxPerCategory {
			files = files[:maxPerCategory]
		}
		out = append(out, Category{Name: name, Files: files})
	}
	return Inventory{Root: root, Categories: out}
}

func isLikelyWordlist(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return true
	}
	switch ext {
	case ".txt", ".lst", ".dic", ".wordlist", ".words":
		return true
	default:
		return false
	}
}

func (i Inventory) First(category string) string {
	for _, c := range i.Categories {
		if c.Name == category && len(c.Files) > 0 {
			return c.Files[0]
		}
	}
	return ""
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func sortWordlists(category string, files []string) {
	sort.Slice(files, func(i, j int) bool {
		ri := rank(category, files[i])
		rj := rank(category, files[j])
		if ri != rj {
			return ri < rj
		}
		return files[i] < files[j]
	})
}

func rank(category, path string) int {
	p := strings.ToLower(path)
	switch category {
	case "web-content":
		switch {
		case strings.Contains(p, "raft-small-directories"):
			return 0
		case strings.Contains(p, "directory-list-2.3-small"):
			return 1
		case strings.Contains(p, "/common.txt"):
			return 2
		case strings.Contains(p, "quickhits"):
			return 3
		case strings.Contains(p, "activedirectory"):
			return 20
		}
	case "dns":
		switch {
		case strings.Contains(p, "subdomains-top1million-5000"):
			return 0
		case strings.Contains(p, "subdomains-top1million"):
			return 1
		case strings.Contains(p, "namelist"):
			return 2
		}
	case "passwords":
		switch {
		case strings.Contains(p, "default"):
			return 0
		case strings.Contains(p, "common"):
			return 1
		}
	}
	return 10
}
