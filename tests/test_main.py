import sys
import builtins

import pytest

import src.main as main_mod
from src.main import parse_ports, validate_target, format_results, print_startup_precheck


def test_parse_ports_valid() -> None:
    assert parse_ports("80,443,1-3") == [1, 2, 3, 80, 443]
    assert parse_ports("22,22,80") == [22, 80]


def test_parse_ports_invalid() -> None:
    with pytest.raises(ValueError):
        parse_ports("10-1")

    with pytest.raises(ValueError):
        parse_ports("70000")

    with pytest.raises(ValueError):
        parse_ports("1-70000")


def test_validate_target() -> None:
    assert validate_target("192.168.1.1") is True
    assert validate_target("10.0.0.0/24") is True
    assert validate_target("invalid") is False


def test_format_results_basic() -> None:
    results = {
        "icmp": True,
        "tcp": {80: "open"},
        "udp": {53: "closed"},
        "arp": [{"ip": "1.1.1.2", "mac": "aa:bb"}],
        "_tcp_services": {80: "HTTP/1.1 200 OK"},
        "_udp_services": {53: "udp-response (10 bytes)"},
        "_errors": [],
    }
    output = format_results(results, target="1.1.1.1")
    assert "ICMP Scan: Host 1.1.1.1 is UP" in output
    assert "TCP Port Scan Results" in output
    assert "UDP Port Scan Results" in output
    assert "TCP Service Detection" in output
    assert "UDP Service Detection" in output
    assert "ARP Scan Results" in output


def test_print_startup_precheck(capsys) -> None:
    precheck = {
        "is_privileged": True,
        "scapy_version": "2.5.0",
        "scapy_use_pcap": False,
    }
    print_startup_precheck(precheck, use_unprivileged=False)
    output = capsys.readouterr().out
    assert "mode=RAW" in output
    assert "scapy=2.5.0" in output


def test_print_startup_precheck_no_pcap(capsys) -> None:
    precheck = {
        "is_privileged": False,
        "scapy_version": "2.5.0",
        "scapy_use_pcap": None,
    }
    print_startup_precheck(precheck, use_unprivileged=True)
    output = capsys.readouterr().out
    assert "use_pcap" not in output
    assert "fallback enabled" in output


def test_has_root_privileges_posix(monkeypatch) -> None:
    monkeypatch.setattr(main_mod, "_os_name", lambda: "posix")
    monkeypatch.setattr(main_mod.os, "geteuid", lambda: 0, raising=False)
    assert main_mod.has_root_privileges() is True


def test_has_root_privileges_windows(monkeypatch) -> None:
    import types

    dummy_ctypes = types.SimpleNamespace(
        windll=types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=lambda: 1))
    )
    monkeypatch.setitem(sys.modules, "ctypes", dummy_ctypes)
    monkeypatch.setattr(main_mod, "_os_name", lambda: "nt")
    assert main_mod.has_root_privileges() is True


def test_collect_startup_precheck_with_scapy(monkeypatch) -> None:
    import types

    dummy_conf = types.SimpleNamespace(use_pcap=True)
    dummy_scapy = types.SimpleNamespace(__version__="2.6.0")
    dummy_config = types.SimpleNamespace(conf=dummy_conf)
    monkeypatch.setitem(sys.modules, "scapy", dummy_scapy)
    monkeypatch.setitem(sys.modules, "scapy.config", dummy_config)
    data = main_mod.collect_startup_precheck()
    assert data["scapy_version"] == "2.6.0"
    assert data["scapy_use_pcap"] is True


class DummyScanner:
    def __init__(self, **kwargs) -> None:
        self.timeout = kwargs.get("timeout", 1)
        self.delay = kwargs.get("delay", 0.0)
        self.unprivileged = kwargs.get("unprivileged", False)
        self.calls = {"tcp": 0, "udp": 0}

    def scan_network(self, target, scan_type, ports=None):
        return {
            "icmp": True,
            "tcp": {80: "open"} if scan_type in ("all", "tcp") and ports else None,
            "udp": {53: "open"} if scan_type in ("all", "udp") and ports else None,
            "arp": [],
            "_errors": [],
        }

    def tcp_service_detect(self, _target, _ports):
        self.calls["tcp"] += 1
        return {80: "HTTP/1.1 200 OK"}

    def udp_service_detect(self, _target, _ports):
        self.calls["udp"] += 1
        return {53: "udp-response"}


def run_main_with_args(monkeypatch, args):
    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(
        main_mod,
        "collect_startup_precheck",
        lambda: {"is_privileged": True, "scapy_version": "2.5.0", "scapy_use_pcap": False},
    )
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", args)
    main_mod.main()


def test_main_requires_target(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    assert "target is required" in capsys.readouterr().out


def test_main_invalid_timeout(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "--timeout", "0"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    assert "Timeout must be a positive" in capsys.readouterr().out


def test_main_invalid_target(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", "invalid"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    assert "Invalid target format" in capsys.readouterr().out


def test_main_invalid_ports(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "tcp", "-p", "3-1"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    assert "Invalid port format" in capsys.readouterr().out


def test_main_tui_mode(monkeypatch) -> None:
    import types

    called = {"tui": False}
    dummy_tui = types.SimpleNamespace(run_tui=lambda *_args, **_kwargs: called.update({"tui": True}))

    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": True})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setitem(sys.modules, "tui", dummy_tui)
    monkeypatch.setattr(sys, "argv", ["main.py", "--tui"])

    main_mod.main()
    assert called["tui"] is True


def test_main_success_output_file(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "scan.txt"
    args = ["main.py", "1.1.1.1", "-t", "tcp", "-p", "80", "-o", str(output_path), "--force"]
    run_main_with_args(monkeypatch, args)
    data = output_path.read_text(encoding="utf-8")
    assert "Scan Results" in data


def test_main_append_output_file(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "scan.txt"
    output_path.write_text("existing\n", encoding="utf-8")
    args = [
        "main.py",
        "1.1.1.1",
        "-t",
        "tcp",
        "-p",
        "80",
        "-o",
        str(output_path),
        "--append",
    ]
    run_main_with_args(monkeypatch, args)
    data = output_path.read_text(encoding="utf-8")
    assert "existing" in data
    assert "Scan Results" in data


def test_main_output_file_guard(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "scan.txt"
    output_path.write_text("existing", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "tcp", "-p", "80", "-o", str(output_path)])
    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": True})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    assert "exists" in capsys.readouterr().out


def test_main_output_write_error(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "scan.txt"
    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": True})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(main_mod.logging, "FileHandler", lambda *_args, **_kwargs: main_mod.logging.NullHandler())
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "tcp", "-p", "80", "-o", str(output_path), "--force"])

    def bad_open(*_args, **_kwargs):
        raise OSError("write failed")

    monkeypatch.setattr(builtins, "open", bad_open)
    main_mod.main()
    assert "Failed to write" in capsys.readouterr().out


def test_main_unprivileged_notices(monkeypatch, capsys) -> None:
    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": False})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "arp"])

    main_mod.main()
    output = capsys.readouterr().out
    assert "Using unprivileged scan mode automatically" in output
    assert "ARP scan requires admin/root" in output


def test_main_user_requested_unprivileged(monkeypatch, capsys) -> None:
    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": True})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "icmp", "--unprivileged"])

    main_mod.main()
    output = capsys.readouterr().out
    assert "user-requested unprivileged" in output


def test_main_service_detection(monkeypatch) -> None:
    scanner = DummyScanner(timeout=1)
    monkeypatch.setattr(main_mod, "NetworkScanner", lambda **_kwargs: scanner)
    monkeypatch.setattr(
        main_mod,
        "collect_startup_precheck",
        lambda: {"is_privileged": True, "scapy_version": "2.5.0", "scapy_use_pcap": False},
    )
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "all", "-p", "80,53", "--service-detect"])
    main_mod.main()
    assert scanner.calls["tcp"] == 1
    assert scanner.calls["udp"] == 1


def test_main_scan_errors_exit(monkeypatch) -> None:
    class ErrorScanner(DummyScanner):
        def scan_network(self, target, scan_type, ports=None):
            return {"icmp": True, "tcp": None, "udp": None, "arp": None, "_errors": ["boom"]}

    monkeypatch.setattr(main_mod, "NetworkScanner", ErrorScanner)
    monkeypatch.setattr(
        main_mod,
        "collect_startup_precheck",
        lambda: {"is_privileged": True, "scapy_version": "2.5.0", "scapy_use_pcap": False},
    )
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "icmp"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 2


def test_main_keyboard_interrupt(monkeypatch) -> None:
    class InterruptScanner(DummyScanner):
        def scan_network(self, target, scan_type, ports=None):
            raise KeyboardInterrupt()

    monkeypatch.setattr(main_mod, "NetworkScanner", InterruptScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": True})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "icmp"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 0


def test_main_unhandled_exception(monkeypatch, capsys) -> None:
    monkeypatch.setattr(main_mod, "NetworkScanner", DummyScanner)
    monkeypatch.setattr(main_mod, "collect_startup_precheck", lambda: {"is_privileged": True})
    monkeypatch.setattr(main_mod, "print_startup_precheck", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(main_mod, "format_results", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(sys, "argv", ["main.py", "1.1.1.1", "-t", "icmp"])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 1
    assert "Error: boom" in capsys.readouterr().out
