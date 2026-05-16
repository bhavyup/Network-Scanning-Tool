# Network Protocol Documentation

This document explains the protocol logic currently implemented by the scanner in `src/scanner.py`.

## ICMP Scanning

### Overview

ICMP scanning checks host liveness by sending an echo request and waiting for a reply.

### Implementation

1. Build packet: `IP(dst=target) / ICMP()`
2. Send with timeout using Scapy `sr1`
3. Classify:
   - response present: host is up
   - response missing or error: host is down

### Result Values

- `True`: host appears reachable
- `False`: no reply received in timeout window

## TCP SYN Scanning

### Overview

TCP scan uses SYN probes to estimate port state.

### Implementation

1. Build packet: `IP(dst=target) / TCP(dport=port, flags="S")`
2. Wait for response with `sr1`
3. Classify:
   - SYN-ACK (`0x12`): `open`
   - RST-ACK (`0x14`): `closed`
   - no response: `filtered`
   - exception: `error`
4. Send RST when SYN-ACK is received to close the half-open state.

### Result Values

- `open`
- `closed`
- `filtered`
- `error`

## UDP Scanning

### Overview

UDP scan behavior is inherently less deterministic than TCP, so this implementation uses retries plus a configurable ambiguity policy.

### Implementation

1. Build packet: `IP(dst=target) / UDP(dport=port)`
2. Probe each port across retry attempts (`udp_retries`)
3. Classify by response:
   - UDP response: `open`
   - ICMP type 3 code 3: `closed`
   - other ICMP unreachable: `closed`
   - no response after retries:
     - `open` if `udp_ambiguity=open`
     - `closed` if `udp_ambiguity=closed`
   - exception: `error`

### Result Values

- `open`
- `closed`
- `error`

Note: current implementation does not emit `open|filtered` or `filtered` for UDP.

## ARP Scanning

### Overview

ARP scanning discovers active hosts in a local segment by broadcasting ARP requests.

### Implementation

1. If target has no CIDR, scanner auto-appends `/24`
2. Build packet: `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)`
3. Send with Scapy `srp`
4. Collect responders into list entries:
   - `{"ip": received.psrc, "mac": received.hwsrc}`

### Result Values

List of host dictionaries or empty list when none respond.

## Comparison Summary

| Protocol | Scope | Typical Output |
| --- | --- | --- |
| ICMP | Host-level | up/down |
| TCP | Port-level | open/closed/filtered/error |
| UDP | Port-level | open/closed/error |
| ARP | LAN segment | discovered IP/MAC pairs |

## Practical Notes

- ARP is local-network oriented and usually needs elevated privileges.
- TCP and UDP probe rates should be tuned with timeout and delay options.
- Always scan only with explicit authorization.
