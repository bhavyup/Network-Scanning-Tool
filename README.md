<div align="center">

```
+-------------------------------------------------------------------+
|                       NETWORK SCANNING TOOL                       |
|       Fast, pragmatic recon for hosts, ports, and services.       |
+-------------------------------------------------------------------+
```

</div>

<!-- readme-gen:start:badges -->
<div align="center">

![Python](https://img.shields.io/badge/python-3.10%2B-0d1117?style=for-the-badge&labelColor=161b22&logo=python&logoColor=white)
![License](https://img.shields.io/github/license/bhavyup/Network-Scanning-Tool?style=for-the-badge&labelColor=161b22&color=0d1117)
![CI](https://img.shields.io/github/actions/workflow/status/bhavyup/Network-Scanning-Tool/ci.yml?style=for-the-badge&labelColor=161b22&logo=githubactions&logoColor=white&color=0d1117)

![Stars](https://img.shields.io/github/stars/bhavyup/Network-Scanning-Tool?style=for-the-badge&labelColor=161b22&color=0d1117)
![Forks](https://img.shields.io/github/forks/bhavyup/Network-Scanning-Tool?style=for-the-badge&labelColor=161b22&color=0d1117)
![Issues](https://img.shields.io/github/issues/bhavyup/Network-Scanning-Tool?style=for-the-badge&labelColor=161b22&color=0d1117)
![Last Commit](https://img.shields.io/github/last-commit/bhavyup/Network-Scanning-Tool?style=for-the-badge&labelColor=161b22&color=0d1117)

</div>
<!-- readme-gen:end:badges -->

> Network reconnaissance should be fast, readable, and safe by default. This tool gives you a single CLI and TUI surface to check host liveness, probe ports, and collect basic service hints without drowning you in noise.

---

## Highlights

- ICMP, TCP SYN, UDP, and ARP scanning with a single command surface
- Unprivileged fallback path (ICMP via ping, TCP connect, UDP best effort)
- Basic service detection for TCP banners and UDP response hints
- Curses-based TUI for interactive runs
- Output files with run metadata headers and safe overwrite controls
- Tunable timeout, delay, and UDP ambiguity policy

## Quick Start

### Requirements

- Python 3.10+
- Admin/root permissions for raw packet scans (ARP and full "all" mode)
- Network authorization to scan your targets

### Install

```
git clone https://github.com/bhavyup/Network-Scanning-Tool.git
cd Network-Scanning-Tool
python -m venv .venv
```

Windows:

```
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS:

```
source .venv/bin/activate
pip install -r requirements.txt
```

### Run

```
python src/main.py 192.168.1.1 -t icmp
python src/main.py 192.168.1.1 -t tcp -p 22,80,443
python src/main.py 192.168.1.1 -t udp -p 53,123,161 --udp-ambiguity open
python src/main.py 192.168.1.0/24 -t arp
```

### TUI Mode

```
python src/main.py --tui
```

### Unprivileged Mode

```
python src/main.py 192.168.1.1 -t tcp -p 80,443 --unprivileged
```

When run without admin/root privileges, the tool automatically falls back to unprivileged mode and warns about ARP limitations.

## Output

- Terminal output is printed via a consistent summary format.
- Use `-o <file>` to write to a text file with metadata headers.
- `--append` adds to existing files, and `--force` overwrites safely.

## Documentation

- [docs/Documentation_Overview.md](docs/Documentation_Overview.md)
- [docs/UDP_FEATURE_GUIDE.md](docs/UDP_FEATURE_GUIDE.md)
- [docs/guides/troubleshooting.md](docs/guides/troubleshooting.md)
- [docs/api/README.md](docs/api/README.md)

---

## Architecture

<!-- readme-gen:start:architecture -->
```mermaid
graph LR
    CLI[src/main.py] --> Scanner[src/scanner.py]
    TUI[src/tui.py] --> Scanner
    Scanner --> Network[Target hosts]
    Scanner --> Output[Terminal or file output]
```
<!-- readme-gen:end:architecture -->

## Project Structure

<!-- readme-gen:start:tree -->
```
Network-Scanning-Tool/
├── src/
│   ├── main.py
│   ├── scanner.py
│   └── tui.py
├── tests/
│   ├── test_scanner.py
│   └── test_integration.py
├── docs/
│   ├── Documentation_Overview.md
│   ├── UDP_FEATURE_GUIDE.md
│   └── guides/
├── scripts/
│   ├── bootstrap.ps1
│   └── bootstrap.sh
├── requirements.txt
├── requirements-dev.txt
└── setup.py
```
<!-- readme-gen:end:tree -->

## Project Health

<!-- readme-gen:start:health -->
| Category | Status | Score |
|:---------|:------:|------:|
| Tests | ########............ | 40% |
| CI/CD | ########............ | 40% |
| Type Safety | ########............ | 40% |
| Documentation | ################.... | 80% |
| Coverage | .................... | 0% |

> Overall: 40% - Needs attention
<!-- readme-gen:end:health -->

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for setup, test guidance, and PR expectations.

## License

MIT. See [LICENSE](LICENSE).

<!-- readme-gen:start:footer -->
<div align="center">
Built with care by [Contributors](https://github.com/bhavyup/Network-Scanning-Tool/graphs/contributors)
</div>
<!-- readme-gen:end:footer -->
