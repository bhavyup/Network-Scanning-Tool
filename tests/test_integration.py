import pytest

from src.scanner import NetworkScanner


@pytest.fixture()
def scanner() -> NetworkScanner:
    return NetworkScanner(timeout=1)


def test_scan_network_all_success(monkeypatch, scanner: NetworkScanner) -> None:
    monkeypatch.setattr(scanner, "icmp_scan", lambda target: True)
    monkeypatch.setattr(scanner, "tcp_scan", lambda target, ports: {80: "open"})
    monkeypatch.setattr(scanner, "udp_scan", lambda target, ports: {53: "closed"})
    monkeypatch.setattr(scanner, "arp_scan", lambda target: [{"ip": "1.1.1.2", "mac": "aa"}])

    results = scanner.scan_network(target="192.168.1.1", scan_type="all", ports=[80, 53])
    assert results["icmp"] is True
    assert results["tcp"][80] == "open"
    assert results["udp"][53] == "closed"
    assert results["arp"]


def test_scan_network_invalid_target(scanner: NetworkScanner) -> None:
    results = scanner.scan_network(target="invalid", scan_type="all", ports=[80])
    assert results["icmp"] is None
    assert results["tcp"] is None
    assert results["arp"] is None
    assert results["_errors"]


def test_scan_network_collects_port_errors(monkeypatch, scanner: NetworkScanner) -> None:
    monkeypatch.setattr(scanner, "icmp_scan", lambda target: True)
    monkeypatch.setattr(scanner, "tcp_scan", lambda target, ports: {80: "error", 81: "open"})
    monkeypatch.setattr(scanner, "udp_scan", lambda target, ports: {53: "error"})
    monkeypatch.setattr(scanner, "arp_scan", lambda target: [])

    results = scanner.scan_network(target="192.168.1.1", scan_type="all", ports=[80, 53])
    errors = " ".join(results["_errors"])
    assert "TCP scan had" in errors
    assert "UDP scan had" in errors


def test_scan_network_no_ports_warning(capsys, scanner: NetworkScanner) -> None:
    results = scanner.scan_network(target="192.168.1.1", scan_type="tcp", ports=None)
    output = capsys.readouterr().out
    assert "Warning: No ports specified" in output
    assert results["tcp"] is None


def test_scan_network_udp_no_ports_warning(capsys, scanner: NetworkScanner) -> None:
    results = scanner.scan_network(target="192.168.1.1", scan_type="udp", ports=None)
    output = capsys.readouterr().out
    assert "Warning: No ports specified for UDP scan" in output
    assert results["udp"] is None


def test_scan_network_arp_error(monkeypatch, scanner: NetworkScanner) -> None:
    def boom(_target):
        raise RuntimeError("arp failed")

    monkeypatch.setattr(scanner, "arp_scan", boom)
    results = scanner.scan_network(target="192.168.1.1", scan_type="arp", ports=None)
    assert results["arp"] is None
    assert "arp failed" in " ".join(results["_errors"])


def test_scan_network_icmp_error(monkeypatch, scanner: NetworkScanner) -> None:
    def boom(_target):
        raise RuntimeError("icmp failed")

    monkeypatch.setattr(scanner, "icmp_scan", boom)
    results = scanner.scan_network(target="192.168.1.1", scan_type="icmp", ports=None)
    assert results["icmp"] is None
    assert "icmp failed" in " ".join(results["_errors"])


def test_scan_network_generic_exception(monkeypatch, scanner: NetworkScanner) -> None:
    def boom(_target):
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner, "validate_ip", boom)
    results = scanner.scan_network(target="192.168.1.1", scan_type="icmp", ports=None)
    assert "Error during network scan" in " ".join(results["_errors"])