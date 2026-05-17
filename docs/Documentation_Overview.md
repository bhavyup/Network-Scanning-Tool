# Network Scanning Project - Documentation Overview

## Project Purpose

This project is a Python network scanner for host discovery and basic service exposure checks. It supports ICMP, TCP, UDP, and ARP scanning workflows and can write formatted output to terminal and files.

## Main Features

- ICMP host liveness checks
- TCP SYN port scanning
- UDP scanning with ambiguity policy
- ARP host discovery on local segments
- Flexible target input (`IP` or `CIDR`)
- Configurable timeout, delay, and max ports
- Output file support with run metadata
- Optional curses-based TUI mode
- Unprivileged fallback mode (ICMP via ping, TCP connect scan, best-effort UDP)
- Basic TCP/UDP service detection (banner/protocol hints)

## Project Structure

```text
Network-Scanning-Tool/
├── src/
│   ├── main.py
│   ├── scanner.py
│   ├── tui.py
│   └── __init__.py
├── tests/
│   ├── test_integration.py
│   ├── test_main.py
│   ├── test_scanner.py
│   └── test_tui.py
├── docs/
│   ├── Documentation_Overview.md
│   ├── UDP_FEATURE_GUIDE.md
│   ├── api/README.md
│   ├── development/README.md
│   ├── guides/README.md
│   ├── guides/troubleshooting.md
│   ├── protocols/README.md
│   └── security/README.md
├── requirements.txt
├── requirements-dev.txt
├── setup.py
└── README.md
```

## How It Works

1. `src/main.py` parses CLI arguments.
2. Inputs are validated (target, timeout, ports).
3. `NetworkScanner` runs selected protocols.
4. Results are formatted into a unified report.
5. Output is printed and optionally written to file.

## Example Usage

```bash
python src/main.py 192.168.1.1 -t icmp
python src/main.py 192.168.1.1 -t tcp -p 22,80,443
python src/main.py 192.168.1.1 -t udp -p 53,123,161 --udp-ambiguity open
python src/main.py 192.168.1.0/24 -t arp -o arp_results.txt --force
python src/main.py 192.168.1.1 -t tcp -p 80,443 --service-detect
python src/main.py 192.168.1.1 -t tcp -p 80,443 --unprivileged
```

## Dependencies

- Python 3.10+
- scapy
- ipaddress
- typing-extensions

## Testing

Run tests with:

```bash
python -m pytest tests/
```

For coverage reporting:

```bash
python -m pytest -q --cov=src --cov-report=term-missing --cov-fail-under=90
```

Type checking:

```bash
python -m mypy src
```

Note: tests are deterministic and avoid live network calls. Live scans still
require admin/root privileges when run manually.

## Security Reminder

Scan only systems and networks you own or are explicitly authorized to test.
