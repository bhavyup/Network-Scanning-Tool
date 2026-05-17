import errno
import socket
from types import SimpleNamespace

import pytest

import src.scanner as scanner_mod
from src.scanner import NetworkScanner


class DummyResponse:
    def __init__(
        self,
        layer=None,
        tcp_flags=None,
        icmp_type=None,
        icmp_code=None,
    ) -> None:
        self._layer = layer
        self._tcp_flags = tcp_flags
        self._icmp_type = icmp_type
        self._icmp_code = icmp_code

    def haslayer(self, layer) -> bool:
        return layer == self._layer

    def getlayer(self, layer):
        if layer == scanner_mod.TCP:
            return SimpleNamespace(flags=self._tcp_flags)
        if layer == scanner_mod.ICMP:
            return SimpleNamespace(type=self._icmp_type, code=self._icmp_code)
        if layer == scanner_mod.UDP:
            return SimpleNamespace()
        return SimpleNamespace()


class DummyTCPSocket:
    def __init__(self, status_by_port) -> None:
        self.status_by_port = status_by_port
        self.timeout = None

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def connect_ex(self, addr) -> int:
        return int(self.status_by_port.get(addr[1], 0))

    def close(self) -> None:
        return None


class DummyUDPSocket:
    def __init__(self, behavior_by_port) -> None:
        self.behavior_by_port = behavior_by_port
        self.port = None
        self.timeout = None

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def connect(self, addr) -> None:
        self.port = addr[1]

    def send(self, data) -> None:
        return None

    def recv(self, _size: int):
        action = self.behavior_by_port.get(self.port, "timeout")
        if action == "data":
            return b"ok"
        if action == "empty":
            return b""
        if action == "timeout":
            raise socket.timeout()
        if action == "reset":
            raise ConnectionResetError()
        if action == "oserror":
            err = OSError("udp")
            setattr(err, "winerror", 10061)
            raise err
        if action == "oserror-other":
            err = OSError("udp")
            setattr(err, "winerror", 999)
            raise err
        raise RuntimeError("unexpected")

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class DummyConn:
    def __init__(self, recv_data=b"", raise_timeout=False) -> None:
        self.recv_data = recv_data
        self.raise_timeout = raise_timeout
        self.timeout = None

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def sendall(self, _data) -> None:
        return None

    def recv(self, _size: int):
        if self.raise_timeout:
            raise socket.timeout()
        return self.recv_data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class DummyTLSSocket:
    def __init__(self, has_cert: bool) -> None:
        self.has_cert = has_cert

    def getpeercert(self):
        return {"subject": "x"} if self.has_cert else None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class DummySSLContext:
    def __init__(self, has_cert: bool) -> None:
        self.has_cert = has_cert
        self.check_hostname = False
        self.verify_mode = None

    def wrap_socket(self, _sock, server_hostname=None):
        return DummyTLSSocket(self.has_cert)


@pytest.fixture()
def scanner() -> NetworkScanner:
    return NetworkScanner(timeout=1, delay=0.0, max_ports=10)


def test_validate_ip_and_network(scanner: NetworkScanner) -> None:
    assert scanner.validate_ip("192.168.1.1") is True
    assert scanner.validate_ip("256.256.256.256") is False
    assert scanner.validate_network("192.168.1.0/24") is True
    assert scanner.validate_network("256.256.256.0/24") is False


def test_invalid_udp_ambiguity() -> None:
    with pytest.raises(ValueError):
        NetworkScanner(timeout=1, udp_ambiguity="maybe")


def test_icmp_scan_unprivileged(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True)

    class DummyProc:
        returncode = 0

    monkeypatch.setattr(scanner_mod.subprocess, "run", lambda *args, **kwargs: DummyProc())
    assert scan.icmp_scan("1.1.1.1") is True

    class DummyProcFail:
        returncode = 1

    monkeypatch.setattr(scanner_mod.subprocess, "run", lambda *args, **kwargs: DummyProcFail())
    assert scan.icmp_scan("1.1.1.1") is False


def test_icmp_scan_unprivileged_posix(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True)
    seen = {}

    class DummyProc:
        returncode = 0

    def fake_run(cmd, stdout=None, stderr=None):
        seen["cmd"] = cmd
        return DummyProc()

    monkeypatch.setattr(scanner_mod, "_os_name", lambda: "posix")
    monkeypatch.setattr(scanner_mod.subprocess, "run", fake_run)
    assert scan.icmp_scan("1.1.1.1") is True
    assert "-c" in seen["cmd"]


def test_icmp_scan_privileged_paths(monkeypatch, scanner: NetworkScanner) -> None:
    monkeypatch.setattr(scanner_mod, "sr1", lambda *args, **kwargs: object())
    assert scanner.icmp_scan("1.1.1.1") is True

    monkeypatch.setattr(scanner_mod, "sr1", lambda *args, **kwargs: None)
    assert scanner.icmp_scan("1.1.1.1") is False

    def boom(*args, **kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(scanner_mod, "sr1", boom)
    with pytest.raises(RuntimeError):
        scanner.icmp_scan("1.1.1.1")


def test_tcp_scan_privileged(monkeypatch, scanner: NetworkScanner) -> None:
    responses = [
        DummyResponse(layer=scanner_mod.TCP, tcp_flags=0x12),
        DummyResponse(layer=scanner_mod.TCP, tcp_flags=0x14),
        None,
    ]
    monkeypatch.setattr(scanner_mod, "sr1", lambda *args, **kwargs: responses.pop(0))
    sent = []
    monkeypatch.setattr(scanner_mod, "send", lambda *args, **kwargs: sent.append(args[0]))

    results = scanner.tcp_scan("1.1.1.1", [80, 81, 82])
    assert results[80] == "open"
    assert results[81] == "closed"
    assert results[82] == "filtered"
    assert sent


def test_tcp_scan_unexpected_flags(monkeypatch, scanner: NetworkScanner) -> None:
    monkeypatch.setattr(
        scanner_mod,
        "sr1",
        lambda *args, **kwargs: DummyResponse(layer=scanner_mod.TCP, tcp_flags=0x10),
    )
    monkeypatch.setattr(scanner_mod, "send", lambda *args, **kwargs: None)

    results = scanner.tcp_scan("1.1.1.1", [80])
    assert results[80] == "filtered"


def test_tcp_scan_unprivileged(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True)
    status_by_port = {
        80: 0,
        81: errno.ECONNREFUSED,
        82: errno.ETIMEDOUT,
    }

    def socket_factory(*args, **kwargs):
        return DummyTCPSocket(status_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    results = scan.tcp_scan("1.1.1.1", [80, 81, 82])
    assert results[80] == "open"
    assert results[81] == "closed"
    assert results[82] == "filtered"


def test_tcp_scan_unprivileged_timeout(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True)

    class TimeoutSocket(DummyTCPSocket):
        def connect_ex(self, addr) -> int:
            raise socket.timeout()

    monkeypatch.setattr(scanner_mod.socket, "socket", lambda *args, **kwargs: TimeoutSocket({}))
    results = scan.tcp_scan("1.1.1.1", [80])
    assert results[80] == "filtered"


def test_tcp_scan_unprivileged_error(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True)

    class ErrorSocket(DummyTCPSocket):
        def connect_ex(self, addr) -> int:
            raise RuntimeError("boom")

    monkeypatch.setattr(scanner_mod.socket, "socket", lambda *args, **kwargs: ErrorSocket({}))
    results = scan.tcp_scan("1.1.1.1", [80])
    assert results[80] == "error"


def test_tcp_scan_error(monkeypatch, scanner: NetworkScanner) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(scanner_mod, "sr1", boom)
    results = scanner.tcp_scan("1.1.1.1", [80])
    assert results[80] == "error"


def test_tcp_scan_max_ports(scanner: NetworkScanner) -> None:
    with pytest.raises(ValueError):
        scanner.tcp_scan("1.1.1.1", list(range(scanner.max_ports + 1)))


def test_udp_scan_privileged(monkeypatch, scanner: NetworkScanner) -> None:
    scanner.udp_retries = 1
    responses = [
        DummyResponse(layer=scanner_mod.ICMP, icmp_type=3, icmp_code=3),
        DummyResponse(layer=scanner_mod.UDP),
        None,
    ]
    monkeypatch.setattr(scanner_mod, "sr1", lambda *args, **kwargs: responses.pop(0))

    results = scanner.udp_scan("1.1.1.1", [53, 123, 161])
    assert results[53] == "closed"
    assert results[123] == "open"
    assert results[161] == "open"


def test_udp_scan_icmp_other_code(monkeypatch, scanner: NetworkScanner) -> None:
    scanner.udp_retries = 1
    monkeypatch.setattr(
        scanner_mod,
        "sr1",
        lambda *args, **kwargs: DummyResponse(layer=scanner_mod.ICMP, icmp_type=3, icmp_code=1),
    )
    results = scanner.udp_scan("1.1.1.1", [53])
    assert results[53] == "closed"


def test_udp_scan_unknown_response(monkeypatch, scanner: NetworkScanner) -> None:
    scanner.udp_retries = 1

    class UnknownResponse:
        def haslayer(self, _layer):
            return False

    monkeypatch.setattr(scanner_mod, "sr1", lambda *args, **kwargs: UnknownResponse())
    results = scanner.udp_scan("1.1.1.1", [53])
    assert results[53] == "open"


def test_udp_scan_ambiguity_closed(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, udp_ambiguity="closed")
    scan.udp_retries = 1
    monkeypatch.setattr(scanner_mod, "sr1", lambda *args, **kwargs: None)

    results = scan.udp_scan("1.1.1.1", [999])
    assert results[999] == "closed"


def test_udp_scan_error(monkeypatch, scanner: NetworkScanner) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(scanner_mod, "sr1", boom)
    results = scanner.udp_scan("1.1.1.1", [53])
    assert results[53] == "error"


def test_udp_scan_unprivileged(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True, udp_ambiguity="open")
    behavior_by_port = {
        53: "data",
        123: "timeout",
        161: "reset",
    }

    def socket_factory(*args, **kwargs):
        return DummyUDPSocket(behavior_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    results = scan.udp_scan("1.1.1.1", [53, 123, 161])
    assert results[53] == "open"
    assert results[123] == "open"
    assert results[161] == "closed"


def test_udp_scan_unprivileged_oserror(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True, udp_ambiguity="open")
    behavior_by_port = {53: "oserror"}

    def socket_factory(*args, **kwargs):
        return DummyUDPSocket(behavior_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    results = scan.udp_scan("1.1.1.1", [53])
    assert results[53] == "closed"


def test_udp_scan_unprivileged_socket_error(monkeypatch) -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True, udp_ambiguity="open")

    def socket_factory(*args, **kwargs):
        raise RuntimeError("socket failed")

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    results = scan.udp_scan("1.1.1.1", [53])
    assert results[53] == "error"


def test_tcp_service_detect(monkeypatch, scanner: NetworkScanner) -> None:
    def create_connection(addr, timeout=None):
        port = addr[1]
        if port == 80:
            return DummyConn(recv_data=b"HTTP/1.1 200 OK\r\n")
        return DummyConn(recv_data=b"")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", create_connection)
    monkeypatch.setattr(scanner_mod.ssl, "create_default_context", lambda: DummySSLContext(True))

    services = scanner.tcp_service_detect("1.1.1.1", [80, 443])
    assert "HTTP" in services[80]
    assert "TLS service" in services[443]


def test_tcp_service_detect_timeout(monkeypatch, scanner: NetworkScanner) -> None:
    def create_connection(addr, timeout=None):
        return DummyConn(recv_data=b"", raise_timeout=True)

    monkeypatch.setattr(scanner_mod.socket, "create_connection", create_connection)
    services = scanner.tcp_service_detect("1.1.1.1", [21])
    assert services[21] == "open (no banner)"


def test_tcp_service_detect_tls_failure(monkeypatch, scanner: NetworkScanner) -> None:
    def create_connection(addr, timeout=None):
        return DummyConn(recv_data=b"")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", create_connection)
    monkeypatch.setattr(scanner_mod.ssl, "create_default_context", lambda: (_ for _ in ()).throw(RuntimeError("tls")))

    services = scanner.tcp_service_detect("1.1.1.1", [443])
    assert "TLS/HTTPS likely" in services[443]


def test_tcp_service_detect_tls_no_cert(monkeypatch, scanner: NetworkScanner) -> None:
    def create_connection(addr, timeout=None):
        return DummyConn(recv_data=b"")

    monkeypatch.setattr(scanner_mod.socket, "create_connection", create_connection)
    monkeypatch.setattr(scanner_mod.ssl, "create_default_context", lambda: DummySSLContext(False))
    services = scanner.tcp_service_detect("1.1.1.1", [443])
    assert services[443] == "TLS service"


def test_udp_service_detect(monkeypatch, scanner: NetworkScanner) -> None:
    behavior_by_port = {
        53: "data",
        123: "timeout",
    }

    def socket_factory(*args, **kwargs):
        return DummyUDPSocket(behavior_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    services = scanner.udp_service_detect("1.1.1.1", [53, 123])
    assert services[53].startswith("udp-response")
    assert services[123] == "open|unknown"


def test_udp_service_detect_empty_response(monkeypatch, scanner: NetworkScanner) -> None:
    behavior_by_port = {53: "empty"}

    def socket_factory(*args, **kwargs):
        return DummyUDPSocket(behavior_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    services = scanner.udp_service_detect("1.1.1.1", [53])
    assert services[53] == "open|unknown"


def test_udp_service_detect_closed(monkeypatch, scanner: NetworkScanner) -> None:
    behavior_by_port = {53: "reset"}

    def socket_factory(*args, **kwargs):
        return DummyUDPSocket(behavior_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    services = scanner.udp_service_detect("1.1.1.1", [53])
    assert services[53] == "closed/unreachable"


def test_udp_service_detect_probe_error(monkeypatch, scanner: NetworkScanner) -> None:
    behavior_by_port = {53: "oserror-other"}

    def socket_factory(*args, **kwargs):
        return DummyUDPSocket(behavior_by_port)

    monkeypatch.setattr(scanner_mod.socket, "socket", socket_factory)
    services = scanner.udp_service_detect("1.1.1.1", [53])
    assert services[53].startswith("probe-error")


def test_arp_scan(monkeypatch, scanner: NetworkScanner) -> None:
    class DummyRecv:
        psrc = "192.168.1.10"
        hwsrc = "aa:bb:cc:dd:ee:ff"

    monkeypatch.setattr(scanner_mod, "srp", lambda *args, **kwargs: ([(None, DummyRecv())], []))
    results = scanner.arp_scan("192.168.1.0/24")
    assert results == [{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff"}]


def test_arp_scan_default_subnet(monkeypatch, scanner: NetworkScanner) -> None:
    class DummyRecv:
        psrc = "192.168.1.10"
        hwsrc = "aa:bb:cc:dd:ee:ff"

    monkeypatch.setattr(scanner_mod, "srp", lambda *args, **kwargs: ([(None, DummyRecv())], []))
    results = scanner.arp_scan("192.168.1.10")
    assert results


def test_arp_scan_error(monkeypatch, scanner: NetworkScanner) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("arp failed")

    monkeypatch.setattr(scanner_mod, "srp", boom)
    with pytest.raises(RuntimeError):
        scanner.arp_scan("192.168.1.0/24")


def test_arp_scan_unprivileged() -> None:
    scan = NetworkScanner(timeout=1, unprivileged=True)
    with pytest.raises(RuntimeError):
        scan.arp_scan("192.168.1.0/24")