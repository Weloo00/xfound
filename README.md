# xfound

`xfound` is a Go CLI for scoped, timed recon orchestration. It inventories local tooling, validates explicit target scope, runs profile-based recon phases with per-tool timeouts, and writes organized output under `/root/Targets/<target>/`.

## Build

```sh
go test ./...
go build -o bin/xfound ./cmd/xfound
```

## Usage

```sh
xfound inventory
xfound install --profile bugbounty --dry-run
xfound run --target example.com --scope scope.txt --profile fast --dry-run
xfound status --target example.com
```

All target runs require a scope file. Use `--dry-run` first to inspect the commands before running tools against an authorized target.

## Phases

Supported phases include:

- `subdomains`
- `ct`
- `dnsgen`
- `resolve`
- `alive`
- `urls`
- `crawl`
- `js`
- `ports`
- `nuclei`
- `fuzz`
- `meg`

## Safety

Only run active phases against assets where you have explicit authorization. If a program policy forbids automated scanners or high-volume traffic, keep runs to dry-run/passive planning or tune execution accordingly.
