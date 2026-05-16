# Troubleshooting Guide

This guide covers common problems and practical fixes for the current scanner implementation.

## 1) Permission Errors

### Symptoms

- `Permission denied`
- `Operation not permitted`
- ARP scans fail immediately

### Fixes

1. Run with elevated privileges where your policy allows.
2. On Windows, launch your terminal as Administrator.
3. Use safer settings (`--delay`, smaller port ranges) on production networks.

## 2) Windows Error Around `os.geteuid`

### Symptoms

- CLI exits with an attribute error on Windows before scanning starts.

### Cause

`src/main.py` currently uses a Unix-only privilege check path (`os.geteuid`).

### Workarounds

1. Use `--tui` mode for interactive runs.
2. Patch privilege detection to be platform-aware before regular CLI use.

## 3) Invalid Target or Port Input

### Symptoms

- `Error: Invalid target format`
- `Invalid port format`

### Fixes

1. Use valid targets:
   - `192.168.1.10`
   - `192.168.1.0/24`
2. Use valid ports/ranges:
   - `80,443`
   - `1-1000`

## 4) TCP Shows Mostly `filtered`

### Symptoms

- Most or all scanned TCP ports show `filtered`.

### Fixes

1. Increase timeout: `-T 3` or `-T 5`.
2. Add delay: `--delay 0.2`.
3. Confirm firewall/ACL behavior on the target network.

## 5) UDP Results Look Uncertain

### Symptoms

- Many UDP ports appear open or closed unexpectedly.

### Cause

UDP has ambiguous no-response behavior by design.

### Fixes

1. Set explicit policy:
   - `--udp-ambiguity open`
   - `--udp-ambiguity closed`
2. Increase timeout and add delay to reduce false assumptions.

## 6) Service Detection Fails

### Symptoms

- Error like missing `tcp_service_detect` or `udp_service_detect`.

### Cause

`--service-detect` is exposed by CLI but backend methods are not implemented yet.

### Workaround

Run scans without `--service-detect` until backend methods are added.

## 7) Output File Write Fails

### Symptoms

- Existing output file blocks write.

### Fixes

1. Use append mode: `--append`
2. Or overwrite explicitly: `--force`

## 8) Debugging and Logs

### Log Location

- `logs/scanner.log`

### Tips

1. Re-run with small, known-good targets.
2. Test one protocol at a time (`icmp`, `tcp`, `udp`, `arp`).
3. Confirm network reachability with system tools (`ping`) before deep scans.

## 9) Test Suite Is Flaky

### Symptoms

- Tests pass/fail inconsistently across machines.

### Cause

Current tests depend on live network state.

### Fixes

1. Run tests in a stable network.
2. Prefer mocked protocol tests for CI hardening.
