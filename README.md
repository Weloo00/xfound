# xfound

`xfound` is a Go CLI for scoped, timed recon orchestration. It inventories local tooling, validates explicit target scope, runs profile-based recon phases with per-tool timeouts, and writes organized output under `/root/Targets/<target>/`.

## Build

```sh
go test ./...
go build -o bin/xfound ./cmd/xfound
```

## Quick start (one command)

```sh
xfound hunt spendesk.com              # auto-scope (apex + subs) + run everything
xfound hunt spendesk.com --dry-run    # preview commands first (recommended)
xfound hunt spendesk.com --profile fast
xfound status --target spendesk.com   # progress + output counts
```

`hunt` needs no scope file — it authorizes the target apex and its subdomains
automatically, and auto-loads `tools.json` (cwd) or `/root/.xfound/tools.json`
if present.

## All commands

```sh
xfound inventory                 # detect installed tools, wordlists, templates
xfound install --profile bugbounty --dry-run
xfound hunt example.com --profile fast --dry-run
xfound run --target example.com --scope scope.txt --phase secrets
xfound status --target example.com
xfound phases                    # list the ordered phase pipeline
xfound version
```

`run` requires an explicit `--scope` file. Use `--dry-run` first to inspect the
commands before running tools against an authorized target.

## Phases

The default pipeline runs in this order:

| Phase        | Tools                                              | Output dir   |
|--------------|----------------------------------------------------|--------------|
| `subdomains` | subfinder, amass, dnscan                           | `subdomains` |
| `ct`         | crtndstry                                          | `subdomains` |
| `dnsgen`     | dnsgen, altdns                                     | `dns`        |
| `resolve`    | dnsx, puredns, shuffledns, massdns                 | `dns`        |
| `alive`      | httpx                                              | `alive`      |
| `urls`       | waybackurls, gau, gauplus, waymore                 | `urls`       |
| `crawl`      | katana, hakrawler, gospider                        | `urls`       |
| `js`         | JSParser, lazyegg (+ js-urls.txt extraction)       | `js`         |
| `secrets`    | mantra, jssecrets, trufflehog                      | `secrets`    |
| `ports`      | naabu                                              | `ports`      |
| `shortscan`  | shortscan (IIS short-name)                         | `fuzz`       |
| `api`        | kiterunner                                         | `api`        |
| `nuclei`     | nuclei                                             | `nuclei`     |
| `takeover`   | nuclei (`-tags takeover`)                          | `takeover`   |
| `fuzz`       | ffuf, gobuster, dirsearch, arjun, paramspider      | `fuzz`       |
| `intel`      | gitdorker (GitHub dorking)                         | `intel`      |
| `meg`        | meg                                                | `meg`        |

Run a single phase with `--phase <name>`.

## Tool mapping (`--tools-map`)

Many bug-bounty tools are Python projects or oddly-named binaries that are not
on `PATH` under their xfound name (ParamSpider, GitDorker, mantra, kiterunner,
dnscan, …). Point xfound at the real entrypoints with a JSON map:

```json
{
  "paramspider": "/root/tools/ParamSpider/paramspider.py",
  "gitdorker":   "/root/tools/GitDorker/GitDorker.py",
  "kiterunner":  "/root/go/bin/kr",
  "mantra":      "/root/tools/mantra/mantra",
  "jssecrets":   "/root/tools/jssecrets/jssecrets",
  "dnscan":      "/root/tools/dnscan/dnscan.py",
  "altdns":      "/root/tools/altdns/altdns.py",
  "waymore":     "/root/tools/waymore/waymore.py"
}
```

```sh
xfound run --target example.com --scope scope.txt --tools-map tools.json --dry-run
```

The map takes precedence over `PATH`; anything unmapped still resolves via
`PATH`. For tools that need an interpreter, point the entry at a small wrapper
script, e.g. `/usr/local/bin/paramspider`:

```sh
#!/bin/sh
exec python3 /root/tools/ParamSpider/paramspider.py "$@"
```

> Flags for the directory-based tools are best-effort defaults. Always
> `--dry-run` first and adjust the wrapper/args to match your tool versions.

## Safety

Only run active phases against assets where you have explicit authorization. If
a program policy forbids automated scanners or high-volume traffic, keep runs to
dry-run/passive planning or tune execution accordingly.
