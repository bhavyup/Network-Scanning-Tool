# UDP Port Scanning Feature Guide

## Overview

UDP scanning is implemented in `src/scanner.py` and exposed through `src/main.py` with `-t udp`.

## Current Behavior

For each UDP target port:

1. Probe packet is sent with Scapy.
2. Scanner retries according to internal retry count.
3. Responses are classified as:
   - `open`: UDP response received
   - `closed`: ICMP unreachable or policy-driven no-response classification
   - `error`: exception occurred

### Ambiguous No-Response Handling

Use `--udp-ambiguity` to decide how no-response ports are classified after retries:

- `--udp-ambiguity open`
- `--udp-ambiguity closed`

## Usage Examples

### Single UDP port

```bash
python src/main.py 192.168.1.100 -t udp -p 53
```

### Multiple UDP ports

```bash
python src/main.py 192.168.1.100 -t udp -p 53,123,161,389
```

### UDP range with delay and timeout

```bash
python src/main.py 192.168.1.100 -t udp -p 1-500 -T 3 --delay 0.2
```

### UDP with explicit ambiguity policy

```bash
python src/main.py 192.168.1.100 -t udp -p 53,123,161 --udp-ambiguity closed
```

### Save UDP results

```bash
python src/main.py 192.168.1.100 -t udp -p 53,123,161 -o udp_scan.txt --force
```

## CLI Options Relevant to UDP

- `-t, --type udp`
- `-p, --ports`
- `-T, --timeout`
- `--delay`
- `--udp-ambiguity {open,closed}`
- `--max-ports`
- `-o, --output`
- `--append`
- `--force`

## Sample Output

```text
Scan Results:
=============

UDP Port Scan Results:
Port 53: open
Port 123: closed
Port 161: open
```

## Notes and Caveats

- UDP is connectionless and can still be difficult to interpret in strict firewall environments.
- Use moderate delay and timeout values in production networks.
- `--service-detect` performs best-effort UDP probes and may not identify every service.

## Troubleshooting

### All UDP ports show closed

- Increase timeout (`-T 3` or higher)
- Reduce scan rate with `--delay`
- Try `--udp-ambiguity open` for conservative false-negative avoidance

### Scan is too slow

- Reduce port range
- Lower timeout where appropriate
- Use target-specific service ports first

### Max ports error

- Increase cap with `--max-ports`
- Or split scan into smaller batches
