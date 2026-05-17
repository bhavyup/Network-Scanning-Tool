import threading
import time
import types
import sys

import pytest

pytest.importorskip("curses")

import src.tui as tui


class FakeScreen:
    def __init__(self, max_y=30, max_x=120, inputs=None) -> None:
        self._max_y = max_y
        self._max_x = max_x
        self.inputs = list(inputs) if inputs else []
        self.calls = []
        self._delay = 120

    def getmaxyx(self):
        return self._max_y, self._max_x

    def addstr(self, y, x, text, attr=0) -> None:
        self.calls.append(("addstr", y, x, text, attr))

    def erase(self) -> None:
        self.calls.append(("erase",))

    def refresh(self) -> None:
        self.calls.append(("refresh",))

    def timeout(self, value) -> None:
        self._delay = value

    def getdelay(self):
        return self._delay

    def getch(self):
        if self.inputs:
            return self.inputs.pop(0)
        return -1

    def move(self, y, x) -> None:
        self.calls.append(("move", y, x))

    def get_wch(self):
        if self.inputs:
            return self.inputs.pop(0)
        return "\n"


def patch_curses(monkeypatch) -> None:
    monkeypatch.setattr(tui.curses, "curs_set", lambda *_: None)
    monkeypatch.setattr(tui.curses, "has_colors", lambda: False)
    monkeypatch.setattr(tui.curses, "start_color", lambda: None)
    monkeypatch.setattr(tui.curses, "use_default_colors", lambda: None)
    monkeypatch.setattr(tui.curses, "init_pair", lambda *_: None)
    monkeypatch.setattr(tui.curses, "color_pair", lambda *_: 0)


def test_truncate_and_parse_ports() -> None:
    assert tui._truncate("hello", 2) == "he"
    assert tui._truncate("hello", 4) == "h..."
    assert tui._truncate("hello", 10) == "hello"
    assert tui._truncate("hello", 0) == ""

    assert tui._parse_ports("") is None
    assert tui._parse_ports("80,443,1-3") == [1, 2, 3, 80, 443]
    assert tui._parse_ports("80,,443") == [80, 443]
    with pytest.raises(ValueError):
        tui._parse_ports("3-1")


def test_format_results_lines() -> None:
    results = {
        "icmp": True,
        "tcp": {80: "open"},
        "udp": {53: "closed"},
        "arp": [{"ip": "1.1.1.2", "mac": "aa"}],
        "_tcp_services": {80: "banner"},
        "_udp_services": {53: "udp"},
        "_errors": [],
    }
    lines = tui._format_results_lines(results, "1.1.1.1")
    joined = "\n".join(lines)
    assert "ICMP: host 1.1.1.1 is UP" in joined
    assert "TCP Services" in joined
    assert "UDP Services" in joined
    assert "ARP Hosts" in joined


def test_format_results_lines_with_errors() -> None:
    results = {"icmp": None, "tcp": None, "udp": None, "arp": None, "_errors": ["fail"]}
    lines = tui._format_results_lines(results, "1.1.1.1")
    joined = "\n".join(lines)
    assert "Scan Errors" in joined


def test_push_activity() -> None:
    activity = []
    tui._push_activity(activity, "first")
    tui._push_activity(activity, "second")
    assert len(activity) == 2
    assert activity[-1].endswith("second")


def test_collect_tui_precheck() -> None:
    scanner = tui.NetworkScanner(timeout=1, unprivileged=True)
    data = tui._collect_tui_precheck(scanner, precheck={"is_privileged": False})
    assert data["use_unprivileged"] is True


def test_collect_tui_precheck_with_scapy(monkeypatch) -> None:
    scanner = tui.NetworkScanner(timeout=1, unprivileged=False)
    dummy_conf = types.SimpleNamespace(use_pcap=True)
    dummy_scapy = types.SimpleNamespace(__version__="2.6.0")
    dummy_config = types.SimpleNamespace(conf=dummy_conf)
    monkeypatch.setitem(sys.modules, "scapy", dummy_scapy)
    monkeypatch.setitem(sys.modules, "scapy.config", dummy_config)
    data = tui._collect_tui_precheck(scanner, precheck=None)
    assert data["scapy_version"] == "2.6.0"
    assert data["scapy_use_pcap"] is True


def test_collect_tui_precheck_scapy_failure(monkeypatch) -> None:
    scanner = tui.NetworkScanner(timeout=1, unprivileged=False)
    monkeypatch.setitem(sys.modules, "scapy", None)
    monkeypatch.setitem(sys.modules, "scapy.config", None)
    data = tui._collect_tui_precheck(scanner, precheck=None)
    assert data["scapy_version"] == "unknown"


def test_draw_and_safe_addstr(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    tui._safe_addstr(screen, 0, 0, "hello")
    tui._safe_addstr(screen, 0, -2, "hello")
    tui._safe_addstr(screen, 100, 0, "skip")
    tui._draw_box(screen, 1, 1, 2, 2, title="Tiny")
    tui._draw_box(screen, 1, 1, 4, 10, title="Box")
    assert screen.calls


def test_render_ui(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    state = tui.TUIState()
    precheck = {"is_privileged": False, "scapy_version": "2.5", "scapy_use_pcap": False}
    tui._render_ui(screen, state, precheck)
    assert screen.calls


def test_render_left_panel_unprivileged_warning(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    state = tui.TUIState(scan_type_index=tui.SCAN_TYPES.index("arp"))
    precheck = {"use_unprivileged": True}
    tui._render_left_panel(screen, state, precheck, y=0, x=0, h=20, w=60)
    assert screen.calls


def test_render_right_panel_scanning(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    state = tui.TUIState(scanning=True, started_at=time.time(), spinner_index=1)
    tui._render_right_panel(screen, state, y=0, x=0, h=30, w=100)
    assert screen.calls


def test_render_right_panel_error_lines(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    state = tui.TUIState(result_lines=["Scan Errors", "  - issue"])
    tui._render_right_panel(screen, state, y=0, x=0, h=20, w=80)
    assert screen.calls


def test_render_right_panel_small(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    state = tui.TUIState()
    tui._render_right_panel(screen, state, y=0, x=0, h=5, w=10)
    assert screen.calls == []


def test_render_help_overlay(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen()
    tui._render_help_overlay(screen)
    assert screen.calls


def test_prompt_input(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen(inputs=["n", "e", "w", "\n"])
    value = tui._prompt_input(screen, "Target", "")
    assert value == "new"


def test_prompt_input_escape(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen(inputs=["\x1b"])
    value = tui._prompt_input(screen, "Target", "keep")
    assert value == "keep"


def test_prompt_input_backspace(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen(inputs=["a", "b", "\b", "\n"])
    value = tui._prompt_input(screen, "Target", "")
    assert value == "a"


def test_prompt_input_key_codes(monkeypatch) -> None:
    patch_curses(monkeypatch)

    class KeyScreen(FakeScreen):
        def get_wch(self):
            if self.inputs:
                return self.inputs.pop(0)
            return tui.curses.KEY_ENTER

    screen = KeyScreen(inputs=["a", tui.curses.KEY_BACKSPACE, tui.curses.KEY_ENTER])
    value = tui._prompt_input(screen, "Target", "")
    assert value == ""


def test_run_scan_thread_service_detect() -> None:
    class FakeScanner:
        def scan_network(self, target, scan_type, ports):
            return {"icmp": True, "tcp": {80: "open"}, "udp": {}, "arp": [], "_errors": []}

        def tcp_service_detect(self, _target, _ports):
            return {80: "banner"}

        def udp_service_detect(self, _target, _ports):
            return {}

    results = {}
    lock = threading.Lock()
    tui.run_scan_thread(
        FakeScanner(),
        target="1.1.1.1",
        scan_type="tcp",
        ports=[80],
        service_detect=True,
        results_container=results,
        lock=lock,
    )
    assert results.get("_tcp_services") == {80: "banner"}


def test_tui_main_exit(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen(inputs=[ord("q")])
    scanner = tui.NetworkScanner(timeout=1, unprivileged=True)
    tui._tui_main(screen, scanner, precheck={"is_privileged": False})


def test_tui_main_small_terminal(monkeypatch) -> None:
    patch_curses(monkeypatch)
    screen = FakeScreen(max_y=10, max_x=40, inputs=[ord("q")])
    scanner = tui.NetworkScanner(timeout=1, unprivileged=True)
    tui._tui_main(screen, scanner, precheck={"is_privileged": False})


def test_tui_main_keypaths(monkeypatch) -> None:
    patch_curses(monkeypatch)

    class FakeScanner:
        def __init__(self) -> None:
            self.timeout = 1
            self.delay = 0.0

        def scan_network(self, target, scan_type, ports):
            return {"icmp": True, "tcp": {80: "open"}, "udp": {}, "arp": [], "_errors": []}

        def tcp_service_detect(self, _target, _ports):
            return {80: "banner"}

        def udp_service_detect(self, _target, _ports):
            return {}

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None) -> None:
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self) -> None:
            if self._target:
                self._target(*self._args, **self._kwargs)

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(tui.threading, "Thread", FakeThread)
    monkeypatch.setattr(tui, "_prompt_input", lambda *_args, **_kwargs: "10.0.0.1")

    screen = FakeScreen(
        inputs=[
            tui.curses.KEY_DOWN,
            tui.curses.KEY_DOWN,
            tui.curses.KEY_RIGHT,
            tui.curses.KEY_LEFT,
            tui.curses.KEY_UP,
            ord("?"),
            ord("q"),
            ord("m"),
            ord("d"),
            ord("c"),
            ord("e"),
            ord("s"),
            ord("q"),
        ]
    )
    tui._tui_main(screen, FakeScanner(), precheck={"is_privileged": False, "use_unprivileged": True})


def test_tui_main_edit_fields(monkeypatch) -> None:
    patch_curses(monkeypatch)

    class FakeScanner:
        def __init__(self) -> None:
            self.timeout = 1
            self.delay = 0.0

        def scan_network(self, target, scan_type, ports):
            return {"icmp": True, "tcp": {}, "udp": {}, "arp": [], "_errors": []}

        def tcp_service_detect(self, _target, _ports):
            return {}

        def udp_service_detect(self, _target, _ports):
            return {}

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None) -> None:
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self) -> None:
            if self._target:
                self._target(*self._args, **self._kwargs)

        def is_alive(self) -> bool:
            return False

    values = iter(["5", "0.2"])
    monkeypatch.setattr(tui, "_prompt_input", lambda *_args, **_kwargs: next(values))
    monkeypatch.setattr(tui.threading, "Thread", FakeThread)

    screen = FakeScreen(
        inputs=[
            tui.curses.KEY_DOWN,
            tui.curses.KEY_DOWN,
            ord("e"),
            tui.curses.KEY_DOWN,
            ord("e"),
            tui.curses.KEY_DOWN,
            ord("e"),
            tui.curses.KEY_DOWN,
            ord("e"),
            ord("q"),
        ]
    )
    tui._tui_main(screen, FakeScanner(), precheck={"is_privileged": False, "use_unprivileged": True})


def test_tui_main_ports_unused_branch(monkeypatch) -> None:
    patch_curses(monkeypatch)

    class FakeScanner:
        def __init__(self) -> None:
            self.timeout = 1
            self.delay = 0.0

        def scan_network(self, target, scan_type, ports):
            return {"icmp": True, "tcp": {}, "udp": {}, "arp": [], "_errors": []}

        def tcp_service_detect(self, _target, _ports):
            return {}

        def udp_service_detect(self, _target, _ports):
            return {}

    screen = FakeScreen(inputs=[ord("m"), tui.curses.KEY_DOWN, ord("e"), ord("q")])
    tui._tui_main(screen, FakeScanner(), precheck={"is_privileged": False, "use_unprivileged": True})


def test_tui_main_scanning_key_block(monkeypatch) -> None:
    patch_curses(monkeypatch)

    class FakeScanner:
        def __init__(self) -> None:
            self.timeout = 1
            self.delay = 0.0

        def scan_network(self, target, scan_type, ports):
            return {"icmp": True, "tcp": {}, "udp": {}, "arp": [], "_errors": []}

        def tcp_service_detect(self, _target, _ports):
            return {}

        def udp_service_detect(self, _target, _ports):
            return {}

    class AliveThread:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None) -> None:
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self) -> None:
            if self._target:
                self._target(*self._args, **self._kwargs)

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(tui.threading, "Thread", AliveThread)
    screen = FakeScreen(inputs=[ord("s"), ord("x"), ord("q")])
    tui._tui_main(screen, FakeScanner(), precheck={"is_privileged": False, "use_unprivileged": True})


def test_has_root_privileges_posix(monkeypatch) -> None:
    monkeypatch.setattr(tui, "_os_name", lambda: "posix")
    monkeypatch.setattr(tui.os, "geteuid", lambda: 0, raising=False)
    assert tui._has_root_privileges() is True


def test_has_root_privileges_posix_error(monkeypatch) -> None:
    monkeypatch.setattr(tui, "_os_name", lambda: "posix")
    monkeypatch.setattr(tui.os, "geteuid", lambda: (_ for _ in ()).throw(RuntimeError("x")), raising=False)
    assert tui._has_root_privileges() is False


def test_has_root_privileges_windows(monkeypatch) -> None:
    dummy_ctypes = types.SimpleNamespace(
        windll=types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=lambda: 1))
    )
    monkeypatch.setitem(sys.modules, "ctypes", dummy_ctypes)
    monkeypatch.setattr(tui, "_os_name", lambda: "nt")
    assert tui._has_root_privileges() is True


def test_has_root_privileges_fallback(monkeypatch) -> None:
    monkeypatch.setattr(tui, "_os_name", lambda: "other")
    if hasattr(tui.os, "geteuid"):
        monkeypatch.delattr(tui.os, "geteuid", raising=False)
    assert tui._has_root_privileges() is False
