package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
)

// ChainLocator resolves a tool name against an ordered list of locators,
// returning the first match. This lets an explicit override map take
// precedence over PATH lookups.
type ChainLocator []ToolLocator

func (c ChainLocator) Path(name string) (string, bool) {
	for _, l := range c {
		if l == nil {
			continue
		}
		if path, ok := l.Path(name); ok {
			return path, true
		}
	}
	return "", false
}

// LoadToolsMap reads a JSON object mapping tool names to absolute executable
// paths (or wrapper scripts) and returns a StaticLocator. Many bug-bounty
// tools (ParamSpider, GitDorker, mantra, kiterunner, ...) are Python projects
// or oddly-named binaries that are not on PATH under their xfound name; this
// map points the orchestrator at the real entrypoint.
//
// Example tools.json:
//
//	{
//	  "paramspider": "/root/tools/ParamSpider/paramspider.py",
//	  "gitdorker":   "/root/tools/GitDorker/GitDorker.py",
//	  "kiterunner":  "/root/go/bin/kr",
//	  "mantra":      "/root/tools/mantra/mantra"
//	}
func LoadToolsMap(path string) (StaticLocator, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tools-map: %w", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("tools-map %s: %w", path, err)
	}
	loc := StaticLocator{}
	for name, target := range raw {
		if target != "" {
			loc[name] = target
		}
	}
	return loc, nil
}
