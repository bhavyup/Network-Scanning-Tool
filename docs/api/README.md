# NetworkScanner API Documentation

## Overview

The `NetworkScanner` class in `src/scanner.py` provides protocol-level scan helpers and one orchestration method for mixed scans.

## Class Constructor

```python
NetworkScanner(
    timeout: int = 2,
    delay: float = 0.0,
    max_ports: int = 1024,
    udp_ambiguity: str = "open",
)
```

### Parameters

- `timeout`: probe timeout in seconds.
- `delay`: delay between probes/retries.
- `max_ports`: hard cap for TCP/UDP ports in one call.
- `udp_ambiguity`: how to classify UDP no-response after retries.
  - allowed values: `open` or `closed`.

## Methods

### icmp_scan

```python
icmp_scan(target: str) -> bool
```

Sends an ICMP echo request and returns:

- `True` if any response is received
- `False` on timeout/error

### tcp_scan

```python
tcp_scan(target: str, ports: List[int]) -> Dict[int, str]
```

Per-port status values:

- `open`
- `closed`
- `filtered`
- `error`

### udp_scan

```python
udp_scan(target: str, ports: List[int]) -> Dict[int, str]
```

Per-port status values:

- `open`
- `closed`
- `error`

For no-response cases, output is controlled by `udp_ambiguity`.

### arp_scan

```python
arp_scan(network: str) -> List[Dict[str, str]]
```

Returns host records as:

```python
{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff"}
```

If the target has no CIDR suffix, `/24` is applied automatically.

### validate_ip

```python
validate_ip(ip: str) -> bool
```

### validate_network

```python
validate_network(network: str) -> bool
```

### scan_network

```python
scan_network(
    target: str,
    scan_type: str = "all",
    ports: Optional[List[int]] = None,
) -> Dict
```

Supported scan types:

- `all`
- `icmp`
- `tcp`
- `udp`
- `arp`

Result model:

```python
{
    "icmp": bool | None,
    "tcp": dict[int, str] | None,
    "udp": dict[int, str] | None,
    "arp": list[dict[str, str]] | None,
}
```

## Usage Examples

### Basic ICMP scan

```python
scanner = NetworkScanner(timeout=2)
is_up = scanner.icmp_scan("192.168.1.1")
print("UP" if is_up else "DOWN")
```

### TCP scan

```python
scanner = NetworkScanner(timeout=2, delay=0.05)
results = scanner.tcp_scan("192.168.1.10", [22, 80, 443])
print(results)
```

### UDP scan with explicit ambiguity policy

```python
scanner = NetworkScanner(timeout=2, udp_ambiguity="closed")
results = scanner.udp_scan("192.168.1.10", [53, 123, 161])
print(results)
```

### Combined scan

```python
scanner = NetworkScanner(timeout=2, max_ports=512)
results = scanner.scan_network(
    target="192.168.1.10",
    scan_type="all",
    ports=[22, 53, 80, 443],
)
print(results)
```

## Notes

- Raw socket operations can require elevated privileges.
- ARP behavior depends on local network context.
- Service-detection helper methods are referenced by CLI logic but are not currently implemented in `NetworkScanner`.

