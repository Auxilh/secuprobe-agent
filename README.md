# SecuProbe Internal Network Agent

A small, dependency-free Go binary that scans an **internal** network surface from
inside your infrastructure and reports findings to SecuProbe. It lets you assess
hosts that are not exposed to the public internet, without opening them up.

Internal Network Agents are an **Enterprise** feature.

## Install

From the SecuProbe dashboard (**Advanced tools → Agents**), generate an install
token, then run on the host that should do the scanning:

```bash
curl -fsSL https://secuprobe.io/install-agent.sh | sh -s -- --token <AGENT_TOKEN>
```

On Linux the installer registers a `systemd` service (`secuprobe-agent`) that scans
on a schedule. On macOS/Windows it installs the binary and prints how to run it.

### Install options

| Flag | Meaning |
|------|---------|
| `--token <t>` | Install token (required). |
| `--targets "<list>"` | Hosts to scan: comma-separated IPs, IPv4 CIDR ranges (≤ /22) or hostnames. Empty = scan this host as seen from the network. |
| `--version <tag>` | Pin a release (default: `latest`). |
| `--install-dir <dir>` | Binary location (default: `/usr/local/bin`). |

## Configuration (environment)

The binary is configured entirely through the environment (the installer writes
`/etc/secuprobe-agent/config.env`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENT_TOKEN` | — | Install token (`spagent_…`), required. |
| `REPORT_URL` | `https://secuprobe.io/api/agent/report` | Where reports are posted. |
| `SCAN_TARGETS` | local host | Hosts/ranges to scan (see `--targets`). |
| `SCAN_INTERVAL_SECONDS` | `3600` | Delay between scan cycles. `0` = run once and exit. |
| `SCAN_TIMEOUT_MS` | `2000` | Per-port TCP connect timeout. |
| `SCAN_CONCURRENCY` | `100` | Concurrent port probes. |

## What it does

1. TCP-connect scan of ~1000 common ports on each target, with banner grab.
2. Best-effort service identification (product + version) from banners.
3. Posts `{ hostname, openPorts, services }` to `REPORT_URL`.

CVE correlation is done **server-side** from the reported services, so the agent
needs no outbound internet beyond `REPORT_URL` and ships no vulnerability database.

## Build

```bash
go test ./...
go build -o secuprobe-agent ./cmd/agent
```

Releases (five OS/arch binaries) are cross-compiled and published to GitHub
Releases by `.github/workflows/build.yml` on every `v*` tag.
