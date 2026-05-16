# Network Scanning Tool

A Python-based network reconnaissance utility for host discovery and service exposure checks.

This project implements packet-level network scanning using Scapy and supports:

- ICMP host liveness checks
- TCP SYN port scanning
- UDP probing with configurable ambiguity handling
- ARP-based LAN host discovery
- Optional curses-based interactive TUI
- File output with scan metadata headers

## Table of Contents

1. [Project Summary](#project-summary)
2. [Who This Tool Is For](#who-this-tool-is-for)
3. [What The Tool Does](#what-the-tool-does)
4. [What The Tool Does Not Do](#what-the-tool-does-not-do)
5. [Feature Matrix](#feature-matrix)
6. [Architecture](#architecture)
7. [Execution Flow](#execution-flow)
8. [Repository Layout](#repository-layout)
9. [Installation](#installation)
10. [Quick Start](#quick-start)
11. [CLI Reference](#cli-reference)
12. [Input Rules and Validation](#input-rules-and-validation)
13. [Scan Engine Details](#scan-engine-details)
14. [Service Detection Option](#service-detection-option)
15. [TUI Mode](#tui-mode)
16. [Output Format](#output-format)
17. [Logging](#logging)
18. [Performance Tuning](#performance-tuning)
19. [Security, Legal, and Ethics](#security-legal-and-ethics)
20. [Testing](#testing)
21. [Known Issues and Caveats](#known-issues-and-caveats)
22. [Use Cases](#use-cases)
23. [Troubleshooting](#troubleshooting)
24. [Extending the Project](#extending-the-project)
25. [Roadmap Suggestions](#roadmap-suggestions)
26. [FAQ](#faq)

## Project Summary

The Network Scanning Tool is a command-line and terminal-UI scanner that sends low-level network probes and classifies responses into practical states.

At a high level:

- You provide a target (single IP or CIDR subnet).
- You choose one scan mode or run all supported modes.
- You optionally provide TCP/UDP ports.
- The scanner sends packets and interprets replies.
- Results are printed and can also be written to text files.

Primary implementation path:

- Main CLI: `src/main.py`
- Core scanner engine: `src/scanner.py`
- Optional TUI: `src/tui.py`

Run the tool using `src/main.py`.

## Who This Tool Is For

- Network administrators doing inventory and reachability checks
- Security teams validating exposed services
- Students learning basic scanning mechanics
- Developers building custom scan workflows on top of Scapy

## What The Tool Does

1. Validates target input as either an IP address or an IP network.
2. Parses and validates port lists/ranges for TCP/UDP scanning.
3. Runs one or more scan methods:
	 - ICMP echo scan
	 - TCP SYN scan
	 - UDP scan
	 - ARP discovery scan
4. Aggregates results in a common dictionary model.
5. Formats and prints results consistently.
6. Optionally writes run metadata + results to an output file.

## What The Tool Does Not Do

- It is not a full Nmap replacement.
- It does not include OS fingerprinting.
- It does not include version/service fingerprinting in a reliable production-ready form.
- It does not persist scan data in a database.
- It does not include built-in distributed/parallel scan orchestration.

## Feature Matrix

| Capability | Status | Notes |
| --- | --- | --- |
| ICMP host check | Implemented | Uses Scapy `IP/ICMP` + `sr1` |
| TCP SYN scan | Implemented | Classifies `open`, `closed`, `filtered`, `error` |
| UDP scan | Implemented | Classifies `open`/`closed`/`error` with configurable ambiguity fallback |
| ARP LAN discovery | Implemented | Broadcast ARP request and collect IP/MAC pairs |
| Port parsing (`80,443,1-100`) | Implemented | Deduplicates and sorts final list |
| Delay/rate limiting | Implemented | Delay between probes and retries |
| Output file writing | Implemented | Header metadata + result text |
| Output append mode | Implemented | `--append` |
| Safe overwrite guard | Implemented | `--force` can override |
| TUI (curses) | Implemented | Basic interactive mode |
| Service detection flag | Partially wired | CLI exposes flag, backend methods missing |

## Architecture

### Logical Components

1. CLI layer (`src/main.py`)
	 - Parses arguments
	 - Validates target/ports/timeout
	 - Initializes scanner config
	 - Handles output writing and formatting

2. Scan engine (`src/scanner.py`)
	 - Implements ICMP/TCP/UDP/ARP probe logic
	 - Encapsulates packet crafting and response classification
	 - Returns normalized dictionaries/lists

3. TUI layer (`src/tui.py`)
	 - Provides terminal prompts and scan spinner
	 - Dispatches scan in worker thread
	 - Renders formatted results in curses view

4. Documentation and project guidance (`docs/`)
	 - User/developer/protocol/security guides
	 - API, usage, and troubleshooting references

### Data Flow Diagram

```text
User Input (CLI args or TUI prompts)
					|
					v
		Argument Parsing + Validation
					|
					v
			NetworkScanner Initialization
					|
					v
		scan_network(target, type, ports)
					|
		 +------+------+------+------+
		 |             |             |
		 v             v             v
	icmp_scan     tcp_scan      udp_scan       arp_scan
		 \             |             |             /
			\            |             |            /
			 +-----------+------+------+-----------+
									|
									v
					 Aggregated Result Dictionary
									|
									v
			format_results() -> terminal / file output
```

## Execution Flow

### CLI Path

1. User runs command against `src/main.py`.
2. Argument parser loads options and validates target/timeout.
3. Scanner object is created with:
	 - timeout
	 - delay
	 - max ports
	 - UDP ambiguity policy
4. Optional root privilege check is performed for ARP/all modes.
5. Ports are parsed if provided.
6. `scan_network()` dispatches selected scan type(s).
7. Results are formatted.
8. Results are printed.
9. Optional output file write happens.

### TUI Path

1. User runs with `--tui`.
2. Curses UI collects fields (target, ports, timeout, delay).
3. A worker thread executes scanner call.
4. Main thread renders spinner until completion.
5. Results are displayed in terminal UI.

## Repository Layout

```text
Network-Scanning-Tool/
├── src/
│   ├── main.py          # Primary CLI entry point
│   ├── scanner.py       # Core scanning engine
│   ├── tui.py           # Curses-based interactive UI
│   └── __init__.py      # Package marker
├── tests/
│   ├── test_scanner.py      # Unit-style tests (currently network-dependent)
│   └── test_integration.py  # Integration-style tests
├── docs/
│   ├── Documentation_Overview.md
│   ├── UDP_FEATURE_GUIDE.md
│   ├── api/README.md
│   ├── development/README.md
│   ├── guides/README.md
│   ├── guides/troubleshooting.md
│   ├── protocols/README.md
│   └── security/README.md
├── scripts/
│   ├── bootstrap.ps1
│   └── bootstrap.sh
├── setup.py             # Packaging metadata
├── requirements.txt     # Runtime dependencies
└── requirements-dev.txt # Development/test tooling
```

## Installation

### Prerequisites

- Python 3.10+ recommended
- Packet/raw socket permission (admin/root level often required)
- Network access to target

### Create Environment

Recommended bootstrap scripts:

Windows (PowerShell):

```powershell
./scripts/bootstrap.ps1 -InstallDev
```

Linux/macOS:

```bash
bash scripts/bootstrap.sh --dev
```

Manual setup:

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Install developer tooling:

```bash
pip install -r requirements-dev.txt
```

## Quick Start

Basic host check:

```bash
python src/main.py 192.168.1.1 -t icmp
```

TCP scan with explicit ports:

```bash
python src/main.py 192.168.1.1 -t tcp -p 22,80,443
```

UDP scan with controlled delay:

```bash
python src/main.py 192.168.1.1 -t udp -p 53,123,161 --delay 0.3
```

ARP discovery on local subnet:

```bash
python src/main.py 192.168.1.0/24 -t arp
```

Run all scans and save output:

```bash
python src/main.py 192.168.1.1 -t all -p 1-200 -o full_scan.txt --force
```

## CLI Reference

```text
usage: python src/main.py TARGET [options]
```

### Positional

- `target`
	- IP address (example: `192.168.1.1`)
	- or network (example: `192.168.1.0/24`)

### Options

- `-t, --type {all,icmp,tcp,udp,arp}`
	- Scan mode
	- Default: `all`

- `-p, --ports PORTS`
	- Comma-separated list and/or ranges
	- Examples: `80,443`, `1-1024`, `22,80,443,8000-8100`

- `-T, --timeout SECONDS`
	- Timeout per probe
	- Default: `2`

- `-o, --output FILE`
	- Write output to file

- `--append`
	- Append to output file instead of overwriting

- `--force`
	- Force operation where applicable
	- Used by overwrite safety check
	- Also bypasses privilege warning abort path

- `--delay FLOAT`
	- Delay between probes/retries
	- Default: `0.0`

- `--udp-ambiguity {open,closed}`
	- How to classify UDP no-response cases
	- Default: `open`

- `--max-ports INT`
	- Max number of ports allowed for TCP/UDP scan in one run
	- Default: `1024`

- `--tui`
	- Launch curses interactive mode

- `-s, --service-detect`
	- Intended to enable banner/service detection on open ports
	- Caveat: currently not fully implemented in scanner backend

## Input Rules and Validation

### Target Validation

`validate_target()` accepts:

- Valid IP address via `ipaddress.ip_address(...)`
- Valid network via `ipaddress.ip_network(..., strict=False)`

Invalid values fail early with user-facing error.

### Port Parsing Rules

`parse_ports()` behavior:

- Splits on commas
- For ranges (`A-B`), expands inclusive sequence
- Validates each port is in `[0, 65535]`
- Validates `A <= B` for ranges
- De-duplicates and sorts final list

Examples:

- Input: `80,443,80,1000-1002`
- Parsed: `[80, 443, 1000, 1001, 1002]`

### Timeout Validation

- Timeout must be positive
- Values `<= 0` are rejected

## Scan Engine Details

All scan logic lives in `NetworkScanner` inside `src/scanner.py`.

### 1) ICMP Scan

Method: `icmp_scan(target)`

Packet:

- `IP(dst=target)/ICMP()`

Interpretation:

- Any response: host is considered up (`True`)
- No response/exception: considered down (`False`)

### 2) TCP SYN Scan

Method: `tcp_scan(target, ports)`

Per-port packet:

- `IP(dst=target)/TCP(dport=port, flags="S")`

Interpretation:

- No response: `filtered`
- TCP SYN-ACK (`0x12`): `open`, followed by RST send to close half-open state
- TCP RST-ACK (`0x14`): `closed`
- Other/unexpected exceptions: `error`

Rate limiting:

- Optional sleep between ports using `delay`

### 3) UDP Scan

Method: `udp_scan(target, ports)`

Per-port packet:

- `IP(dst=target)/UDP(dport=port)`

Algorithm:

- Retries each port probe (`udp_retries`, default `2`)
- Tracks two booleans:
	- `is_closed`
	- `got_udp_response`

Interpretation logic:

- ICMP type 3 code 3 (Port Unreachable): `closed`
- Other ICMP unreachable cases: `closed`
- UDP response received: `open`
- No definitive response after retries:
	- `open` if `udp_ambiguity=open`
	- `closed` if `udp_ambiguity=closed`

Important note:

- Current implementation intentionally collapses ambiguity to `open` or `closed` based on policy, rather than returning `open|filtered`.

### 4) ARP Scan

Method: `arp_scan(network)`

If target has no CIDR suffix:

- It auto-appends `/24`.

Packet:

- `Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)`

Interpretation:

- Collects responses into list of dictionaries:
	- `{"ip": ..., "mac": ...}`

### 5) Orchestration: `scan_network(...)`

Result model:

```python
{
		"icmp": bool | None,
		"tcp": dict[int, str] | None,
		"udp": dict[int, str] | None,
		"arp": list[dict[str, str]] | None,
}
```

Dispatch behavior:

- `all` runs ICMP, TCP (if ports), UDP (if ports), ARP
- `tcp` and `udp` warn when ports are omitted
- Invalid target yields unmodified default structure with `None` fields

## Service Detection Option

CLI supports `-s/--service-detect` and expects scanner methods:

- `tcp_service_detect(target, open_ports)`
- `udp_service_detect(target, udp_ports)`

Current state:

- These methods are referenced in `src/main.py` but not implemented in `src/scanner.py`.
- If `--service-detect` is used and open ports exist, runtime will raise an attribute error.

Recommendation:

- Keep `--service-detect` disabled until those methods are added.

## TUI Mode

Launch:

```bash
python src/main.py 127.0.0.1 --tui
```

Capabilities:

- Edit target, ports, timeout, delay interactively
- Toggle scan type between TCP/UDP
- Toggle service-detect flag in UI state
- Run scan in background thread with spinner
- Render results in simple curses screen

Limitations:

- TUI currently toggles only between TCP and UDP scan types.
- It does not expose full CLI option space.

## Output Format

Terminal output is generated by `format_results()`.

When writing to file (`-o`), the tool prepends metadata header:

```text
Scan run: <UTC ISO timestamp>
Target: <target>
Scan type: <scan type>
Ports: <port expression or None>
Timeout: <seconds>s
Delay between probes: <seconds>s
---
```

Then writes the formatted scan results body.

### Example Result

```text
Scan Results:
=============

ICMP Scan: Host 192.168.1.1 is UP

TCP Port Scan Results:
Port 22: open
Port 80: open
Port 443: filtered

UDP Port Scan Results:
Port 53: open
Port 161: closed

ARP Scan Results:
IP Address               MAC Address
----------------------------------------
192.168.1.10             aa:bb:cc:dd:ee:ff
```

## Logging

The CLI creates `logs/scanner.log` and logs at INFO level to:

- File handler (UTF-8)
- Stdout stream handler

Scanner exceptions in TCP/UDP methods are logged with stack traces via module logger.

## Performance Tuning

Main knobs:

- `-T/--timeout`: increase for slow networks, decrease for faster scans
- `--delay`: add inter-probe delay to reduce burst load
- `--max-ports`: safety cap for request size
- `--udp-ambiguity`: control conservative vs optimistic UDP classification

Practical guidance:

1. For unstable networks, increase timeout and add delay.
2. For LAN testing, lower timeout and keep delay near zero.
3. For broad UDP scans, prefer moderate delay to avoid ICMP rate-limit effects.

## Security, Legal, and Ethics

Always scan only with explicit authorization.

Guidelines:

- Obtain written permission before scanning non-owned assets.
- Define and document scan scope.
- Coordinate with network owners to avoid alert fatigue and service disruption.
- Store output logs securely (may contain sensitive host/service metadata).
- Respect local law and corporate policy.

## Testing

Run tests with Pytest:

```bash
pytest -q
```

Or:

```bash
python -m pytest tests/
```

Current test landscape:

- `tests/test_scanner.py`: basic checks for scanner methods
- `tests/test_integration.py`: larger scenario tests

Important testing caveat:

- Many tests call real network methods directly (instead of mocking Scapy), so pass/fail can depend on host/network/environment and privileges.

## Known Issues and Caveats

This section is intentionally explicit so users know the current state.

1. Service detection flag is not fully implemented
	 - `--service-detect` references scanner methods that do not currently exist.

2. Windows compatibility problem in privilege check
	 - CLI uses `os.geteuid()` directly.
	 - On Windows, this attribute is not available and can cause immediate runtime failure in non-TUI path.

3. Package/module import style is script-oriented
	 - `src/main.py` imports `from scanner import ...`.
	 - This works when launching as script (`python src/main.py`), but not necessarily with module-style execution (`python -m src.main`).

4. ARP behavior on single IP target
	 - ARP scan helper auto-converts single IP input into `/24` network scan.
	 - This may scan a wider segment than expected.

5. Tests are network-environment dependent
	 - Several tests expect specific network conditions and may be flaky in CI or isolated environments.

## Use Cases

### 1) Quick Reachability Check

Use ICMP to validate whether a host responds:

```bash
python src/main.py 10.0.0.20 -t icmp
```

### 2) Service Exposure Spot Check

Validate a known service set:

```bash
python src/main.py 10.0.0.20 -t tcp -p 22,80,443,3389
```

### 3) UDP Infrastructure Validation

Check common infra ports (DNS/NTP/SNMP):

```bash
python src/main.py 10.0.0.20 -t udp -p 53,123,161 --udp-ambiguity open
```

### 4) LAN Asset Discovery

Discover active hosts and MACs in subnet:

```bash
python src/main.py 192.168.1.0/24 -t arp
```

### 5) Audit Trail Output

Persist run with metadata:

```bash
python src/main.py 192.168.1.1 -t all -p 1-200 -o audit_scan.txt --force
```

## Troubleshooting

### Permission Denied / Raw Socket Errors

- Linux/macOS: run with elevated privileges where policy allows.
- Ensure local endpoint security tools are not blocking packet operations.

### All Ports Show Filtered or Closed

- Increase timeout (`-T 3` or `-T 5`).
- Add delay (`--delay 0.2`).
- Confirm target firewall and ACL behavior.

### UDP Results Seem Uncertain

- UDP is inherently ambiguous in many environments.
- Tune `--udp-ambiguity` based on your risk preference.

### Output File Write Fails

- If file exists and you are not appending, either:
	- use `--append`, or
	- use `--force` to overwrite.

### Windows Crash Around `geteuid`

- Current CLI path has a Unix-centric privilege check.
- Use TUI path or patch privilege detection for Windows compatibility.

## Extending the Project

### High-Value Extension Points

1. Implement service detection methods in `NetworkScanner`.
2. Add JSON/CSV output writers.
3. Add structured logging (JSON logs).
4. Add scan profiles (quick, balanced, deep).
5. Add async/paralleled probe dispatch with rate controls.
6. Add platform-aware privilege checks.
7. Add mock-based tests for deterministic CI.

### Suggested Internal Refactors

- Normalize imports for package + script compatibility.
- Split scanner protocol methods into separate modules.
- Add central constants for statuses and defaults.
- Add strict typed result models using dataclasses or TypedDict.

## Roadmap Suggestions

Short-term:

- Fix `--service-detect` runtime gap.
- Fix Windows privilege check behavior.
- Align docs with actual UDP semantics.

Mid-term:

- Add banner-grab modules with safe timeout handling.
- Add JSON output and report templates.
- Add deterministic unit tests with Scapy mocks.

Long-term:

- Plugin architecture for new scan types.
- Historical result storage and diffing.
- Multi-target batch mode with concurrency controls.

## FAQ

### Which file should I run?

Run `src/main.py`.

### Do I need admin/root privileges?

Often yes for raw socket operations (especially ARP and low-level probes), depending on OS and environment.

### Why does UDP look less certain than TCP?

UDP has no handshake, and many services/firewalls do not respond clearly. This is normal in network scanning.

### Can I run this on Windows?

Partially, but current non-TUI CLI path has a Unix-specific privilege check caveat described above.

### Are tests fully deterministic?

Not currently. Many tests depend on real network behavior and host environment.

---

If you are maintaining this repository, treat this README as the practical source-of-truth for current behavior in `src/` and as a migration guide for stabilizing legacy and platform-specific gaps.
