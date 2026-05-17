import curses
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, cast

try:
    from scanner import NetworkScanner
except Exception:  # pragma: no cover - fallback for package-style imports
    from src.scanner import NetworkScanner

SCAN_TYPES: List[str] = ["icmp", "tcp", "udp", "arp", "all"]
FIELD_ORDER: List[str] = ["target", "ports", "scan_type", "timeout", "delay", "service_detect"]


def _os_name() -> str:
    return os.name


def _has_root_privileges() -> bool:
    if _os_name() == "nt":
        try:
            import ctypes

            windll = getattr(ctypes, "windll", None)
            if windll is None:
                return False
            shell32 = getattr(windll, "shell32", None)
            if shell32 is None:
                return False
            is_admin = getattr(shell32, "IsUserAnAdmin", None)
            if is_admin is None:
                return False
            return bool(is_admin())
        except Exception:
            return False

    if hasattr(os, "geteuid"):
        try:
            geteuid = cast(Callable[[], int], os.geteuid)
            return geteuid() == 0
        except Exception:
            return False

    return False


def _collect_tui_precheck(
    scanner: NetworkScanner, precheck: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    data: Dict[str, Any]
    if precheck is not None:
        data = dict(precheck)
    else:
        data = {
            "is_privileged": _has_root_privileges(),
            "scapy_version": "unknown",
            "scapy_use_pcap": None,
        }
        try:
            import scapy
            from scapy.config import conf

            data["scapy_version"] = scapy.__version__
            data["scapy_use_pcap"] = bool(getattr(conf, "use_pcap", False))
        except Exception:
            pass

    if "use_unprivileged" not in data:
        data["use_unprivileged"] = bool(getattr(scanner, "unprivileged", False))

    return data


def _safe_addstr(stdscr: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    max_y, max_x = stdscr.getmaxyx()
    if y < 0 or y >= max_y or x >= max_x:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    width = max_x - x
    if width <= 0:
        return
    stdscr.addstr(y, x, text[:width], attr)


def _truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _draw_box(
    stdscr: Any,
    y: int,
    x: int,
    h: int,
    w: int,
    title: Optional[str] = None,
    attr: int = 0,
) -> None:
    if h < 3 or w < 3:
        return

    _safe_addstr(stdscr, y, x, "+" + "-" * (w - 2) + "+", attr)
    for row in range(y + 1, y + h - 1):
        _safe_addstr(stdscr, row, x, "|", attr)
        _safe_addstr(stdscr, row, x + w - 1, "|", attr)
    _safe_addstr(stdscr, y + h - 1, x, "+" + "-" * (w - 2) + "+", attr)

    if title:
        label = f" {title} "
        _safe_addstr(stdscr, y, x + 2, _truncate(label, max(0, w - 4)), attr)


def _parse_ports(ports_text: str) -> Optional[List[int]]:
    if not ports_text.strip():
        return None

    ports: List[int] = []
    for part in ports_text.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            start_s, end_s = p.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                raise ValueError("start port must be <= end port")
            if start < 0 or end > 65535:
                raise ValueError("ports must be in range 0..65535")
            ports.extend(range(start, end + 1))
        else:
            single = int(p)
            if single < 0 or single > 65535:
                raise ValueError("ports must be in range 0..65535")
            ports.append(single)

    return sorted(list(set(ports)))


def _format_results_lines(results: Dict[str, Any], target: str) -> List[str]:
    lines: List[str] = []
    lines.append("Scan Results")
    lines.append("============")
    lines.append("")

    if results.get("icmp") is not None:
        status = "UP" if results["icmp"] else "DOWN"
        lines.append(f"ICMP: host {target} is {status}")
        lines.append("")

    if results.get("tcp") is not None:
        lines.append("TCP Ports")
        for port, status in sorted(results["tcp"].items()):
            lines.append(f"  {port}: {status}")
        lines.append("")

    if results.get("udp") is not None:
        lines.append("UDP Ports")
        for port, status in sorted(results["udp"].items()):
            lines.append(f"  {port}: {status}")
        lines.append("")

    if results.get("_tcp_services"):
        lines.append("TCP Services")
        for port, info in sorted(results["_tcp_services"].items()):
            lines.append(f"  {port}: {info}")
        lines.append("")

    if results.get("_udp_services"):
        lines.append("UDP Services")
        for port, info in sorted(results["_udp_services"].items()):
            lines.append(f"  {port}: {info}")
        lines.append("")

    if results.get("arp") is not None:
        lines.append("ARP Hosts")
        if results["arp"]:
            for item in results["arp"]:
                lines.append(f"  {item.get('ip', '')}  {item.get('mac', '')}")
        else:
            lines.append("  No hosts found")
        lines.append("")

    errors = results.get("_errors") or []
    if errors:
        lines.append("Scan Errors")
        for err in errors:
            lines.append(f"  - {err}")
        lines.append("")

    if not lines:
        lines = ["No results yet."]

    return lines


def _push_activity(activity: List[str], message: str) -> None:
    stamp = time.strftime("%H:%M:%S")
    activity.append(f"[{stamp}] {message}")
    if len(activity) > 200:
        del activity[: len(activity) - 200]


def _prompt_input(stdscr: Any, label: str, current: str) -> str:
    max_y, max_x = stdscr.getmaxyx()
    prompt = f"{label} [{current}]: "
    available = max(1, max_x - len(prompt) - 2)
    buffer = list(current)

    old_delay = 120
    if hasattr(stdscr, "getdelay"):
        try:
            old_delay = stdscr.getdelay()
        except Exception:
            old_delay = 120

    stdscr.timeout(-1)
    try:
        curses.curs_set(1)
    except Exception:
        pass

    try:
        while True:
            _safe_addstr(stdscr, max_y - 1, 0, " " * max(1, max_x - 1))
            visible = "".join(buffer)
            _safe_addstr(stdscr, max_y - 1, 0, _truncate(prompt + visible, max_x - 1))
            cursor_x = min(max_x - 2, len(prompt) + len(buffer))
            try:
                stdscr.move(max_y - 1, max(0, cursor_x))
            except Exception:
                pass
            stdscr.refresh()

            key = stdscr.get_wch()

            if isinstance(key, str):
                if key in ("\n", "\r"):
                    break
                if key == "\x1b":
                    return current
                if key in ("\b", "\x7f", "\x08"):
                    if buffer:
                        buffer.pop()
                    continue
                if key.isprintable() and len(buffer) < available:
                    buffer.append(key)
                continue

            if key in (curses.KEY_ENTER, 10, 13):
                break
            if key in (curses.KEY_BACKSPACE, curses.KEY_DC, 127):
                if buffer:
                    buffer.pop()
                continue
    finally:
        _safe_addstr(stdscr, max_y - 1, 0, " " * max(1, max_x - 1))
        try:
            curses.curs_set(0)
        except Exception:
            pass
        stdscr.timeout(old_delay if isinstance(old_delay, int) else 120)

    value = "".join(buffer).strip()
    return value if value else current


@dataclass
class TUIState:
    target: str = "127.0.0.1"
    ports: str = "22,80,443"
    scan_type_index: int = 2  # udp
    timeout: str = "2"
    delay: str = "0.0"
    service_detect: bool = False
    selected_field: int = 0
    status_line: str = "Ready. Press 's' to start a scan."
    result_lines: List[str] = field(default_factory=lambda: ["No scan yet. Press 's' to start."])
    activity_lines: List[str] = field(default_factory=list)
    scanning: bool = False
    started_at: float = 0.0
    spinner_index: int = 0
    show_help: bool = False

    @property
    def scan_type(self) -> str:
        return SCAN_TYPES[self.scan_type_index]

    def cycle_scan_type(self, step: int = 1) -> None:
        self.scan_type_index = (self.scan_type_index + step) % len(SCAN_TYPES)



def run_scan_thread(
    scanner: NetworkScanner,
    target: str,
    scan_type: str,
    ports: Optional[List[int]],
    service_detect: bool,
    results_container: Dict[str, Any],
    lock: threading.Lock,
) -> None:
    try:
        res = scanner.scan_network(target=target, scan_type=scan_type, ports=ports)

        if service_detect:
            # TCP service detection for open ports
            if res.get("tcp"):
                open_tcp = [p for p, s in res["tcp"].items() if s == "open"]
                if open_tcp:
                    try:
                        res["_tcp_services"] = scanner.tcp_service_detect(target, open_tcp)
                    except Exception as exc:
                        errs = res.setdefault("_errors", [])
                        errs.append(f"TCP service detection failed: {exc}")

            # UDP service detection for open/ambiguous ports
            if res.get("udp"):
                udp_ports = [p for p, s in res["udp"].items() if s in ("open", "open|filtered")]
                if udp_ports:
                    try:
                        res["_udp_services"] = scanner.udp_service_detect(target, udp_ports)
                    except Exception as exc:
                        errs = res.setdefault("_errors", [])
                        errs.append(f"UDP service detection failed: {exc}")

        with lock:
            results_container.clear()
            results_container.update(res)
    except Exception as exc:
        with lock:
            results_container.clear()
            results_container["__error__"] = str(exc)


def run_tui(scanner: NetworkScanner, precheck: Optional[Dict[str, Any]] = None) -> None:
    curses.wrapper(_tui_main, scanner, precheck)


def _tui_main(stdscr: Any, scanner: NetworkScanner, precheck: Optional[Dict[str, Any]] = None) -> None:
    curses.curs_set(0)
    stdscr.timeout(120)

    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)   # accent
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # warning
        curses.init_pair(3, curses.COLOR_RED, -1)     # error
        curses.init_pair(4, curses.COLOR_CYAN, -1)    # muted/meta

    precheck_data = _collect_tui_precheck(scanner, precheck)
    state = TUIState()
    _push_activity(state.activity_lines, "Command deck initialized")

    scan_thread: Optional[threading.Thread] = None
    results_container: Dict[str, Any] = {}
    results_lock = threading.Lock()

    while True:
        max_y, max_x = stdscr.getmaxyx()
        stdscr.erase()

        if max_y < 24 or max_x < 92:
            _safe_addstr(stdscr, 0, 0, "Terminal too small. Resize to at least 92x24.", curses.color_pair(3))
            _safe_addstr(stdscr, 2, 0, "Press 'q' to quit.")
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                return
            continue

        _render_ui(stdscr, state, precheck_data)
        if state.show_help:
            _render_help_overlay(stdscr)
        stdscr.refresh()

        if state.scanning and scan_thread is not None:
            state.spinner_index = (state.spinner_index + 1) % 4
            if not scan_thread.is_alive():
                state.scanning = False
                elapsed = time.time() - state.started_at
                with results_lock:
                    if "__error__" in results_container:
                        msg = results_container["__error__"]
                        state.result_lines = ["Scan failed", "", msg]
                        state.status_line = f"Scan failed: {msg}"
                        _push_activity(state.activity_lines, f"Scan failed: {msg}")
                    else:
                        results = dict(results_container)
                        state.result_lines = _format_results_lines(results, state.target)
                        errs = results.get("_errors") or []
                        if errs:
                            state.status_line = (
                                f"Scan completed with {len(errs)} error(s) in {elapsed:.1f}s"
                            )
                            _push_activity(
                                state.activity_lines,
                                f"Scan completed with {len(errs)} error(s) in {elapsed:.1f}s",
                            )
                        else:
                            state.status_line = f"Scan completed in {elapsed:.1f}s"
                            _push_activity(state.activity_lines, f"Scan completed in {elapsed:.1f}s")

        key = stdscr.getch()
        if key == -1:
            continue

        if key in (ord("q"), ord("Q")):
            if state.show_help:
                state.show_help = False
                state.status_line = "Help closed"
                continue
            return

        if key in (ord("?"), ord("h"), ord("H")):
            state.show_help = not state.show_help
            state.status_line = "Help opened" if state.show_help else "Help closed"
            continue

        if state.show_help:
            state.show_help = False
            state.status_line = "Help closed"
            continue

        if state.scanning:
            state.status_line = "Scan is running. Wait for completion before editing."
            continue

        if key == curses.KEY_UP:
            state.selected_field = (state.selected_field - 1) % len(FIELD_ORDER)
            continue
        if key == curses.KEY_DOWN:
            state.selected_field = (state.selected_field + 1) % len(FIELD_ORDER)
            continue

        if key == curses.KEY_LEFT:
            if FIELD_ORDER[state.selected_field] == "scan_type":
                state.cycle_scan_type(-1)
            continue

        if key == curses.KEY_RIGHT:
            if FIELD_ORDER[state.selected_field] == "scan_type":
                state.cycle_scan_type(1)
            continue

        if key in (ord("m"), ord("M")):
            state.cycle_scan_type(1)
            state.status_line = f"Scan mode switched to {state.scan_type}"
            continue

        if key in (ord("d"), ord("D")):
            state.service_detect = not state.service_detect
            state.status_line = (
                "Service detection enabled" if state.service_detect else "Service detection disabled"
            )
            continue

        if key in (ord("c"), ord("C")):
            state.result_lines = ["Output cleared."]
            state.activity_lines = []
            _push_activity(state.activity_lines, "Output and activity cleared")
            state.status_line = "Cleared"
            continue

        if key in (ord("e"), ord("E"), 10, 13):
            field = FIELD_ORDER[state.selected_field]
            if field == "target":
                state.target = _prompt_input(stdscr, "Target", state.target)
                state.status_line = "Target updated"
            elif field == "ports":
                if state.scan_type in ("icmp", "arp"):
                    state.status_line = "Ports are unused for current mode. Switch to tcp/udp/all to edit."
                else:
                    state.ports = _prompt_input(stdscr, "Ports", state.ports)
                    state.status_line = "Ports updated"
            elif field == "scan_type":
                state.cycle_scan_type(1)
                state.status_line = f"Scan mode switched to {state.scan_type}"
            elif field == "timeout":
                state.timeout = _prompt_input(stdscr, "Timeout (seconds)", state.timeout)
                state.status_line = "Timeout updated"
            elif field == "delay":
                state.delay = _prompt_input(stdscr, "Delay (seconds)", state.delay)
                state.status_line = "Delay updated"
            elif field == "service_detect":
                state.service_detect = not state.service_detect
                state.status_line = (
                    "Service detection enabled" if state.service_detect else "Service detection disabled"
                )
            continue

        if key in (ord("s"), ord("S")):
            try:
                timeout_val = float(state.timeout)
                delay_val = float(state.delay)
                if timeout_val <= 0:
                    raise ValueError("timeout must be positive")
                if delay_val < 0:
                    raise ValueError("delay must be >= 0")

                scanner.timeout = timeout_val
                scanner.delay = delay_val

                ports_list: Optional[List[int]] = None
                if state.scan_type in ("tcp", "udp", "all"):
                    ports_list = _parse_ports(state.ports)

                _push_activity(
                    state.activity_lines,
                    (
                        f"Starting scan: type={state.scan_type} target={state.target} "
                        f"ports={ports_list or 'none'} service_detect={'on' if state.service_detect else 'off'}"
                    ),
                )
                state.status_line = "Scan running..."
                state.started_at = time.time()
                state.scanning = True
                results_container = {}
                scan_thread = threading.Thread(
                    target=run_scan_thread,
                    args=(
                        scanner,
                        state.target,
                        state.scan_type,
                        ports_list,
                        state.service_detect,
                        results_container,
                        results_lock,
                    ),
                    daemon=True,
                )
                scan_thread.start()
            except Exception as exc:
                state.status_line = f"Cannot start scan: {exc}"
                _push_activity(state.activity_lines, f"Validation failed: {exc}")


def _render_ui(stdscr: Any, state: TUIState, precheck_data: Dict[str, Any]) -> None:
    max_y, max_x = stdscr.getmaxyx()

    accent = curses.color_pair(1)
    warning = curses.color_pair(2)
    error = curses.color_pair(3)
    muted = curses.color_pair(4)

    header_h = 6
    footer_h = 2
    content_h = max_y - header_h - footer_h

    left_w = max(40, min(52, max_x // 3))
    right_w = max_x - left_w - 1

    _safe_addstr(stdscr, 0, 0, "NETSCAN // OPERATIONS CONSOLE", accent | curses.A_BOLD)
    _safe_addstr(stdscr, 1, 0, "Claude-like command workflow for network reconnaissance", muted)

    mode_label = "UNPRIVILEGED" if precheck_data.get("use_unprivileged") else "RAW"
    admin_label = "yes" if precheck_data.get("is_privileged") else "no"
    scapy_version = precheck_data.get("scapy_version", "unknown")
    pcap = precheck_data.get("scapy_use_pcap")
    if pcap is None:
        pcap_text = "n/a"
    else:
        pcap_text = str(pcap)

    chips = [
        f"runtime={mode_label}",
        f"admin={admin_label}",
        f"scapy={scapy_version}",
        f"pcap={pcap_text}",
        f"mode={state.scan_type}",
        f"service={'on' if state.service_detect else 'off'}",
    ]
    chip_text = "  ".join(f"[{c}]" for c in chips)
    _safe_addstr(stdscr, 2, 0, _truncate(chip_text, max_x - 1), muted)

    scanner_state = "SCANNING" if state.scanning else "READY"
    scanner_attr = warning | curses.A_BOLD if state.scanning else accent | curses.A_BOLD
    _safe_addstr(stdscr, 3, 0, _truncate(f"Session State: {scanner_state}", max_x - 1), scanner_attr)
    _safe_addstr(stdscr, 4, 0, "Tip: ? opens the command legend and workflow map", muted)

    _draw_box(stdscr, header_h, 0, content_h, left_w, "Command Panel")
    _draw_box(stdscr, header_h, left_w + 1, content_h, right_w, "Live Workspace")

    _render_left_panel(stdscr, state, precheck_data, header_h + 1, 1, content_h - 2, left_w - 2)
    _render_right_panel(stdscr, state, header_h + 1, left_w + 2, content_h - 2, right_w - 2)

    status_attr = accent if not state.scanning else warning
    if state.status_line.lower().startswith("scan failed"):
        status_attr = error
    _safe_addstr(stdscr, max_y - 2, 0, _truncate("Status: " + state.status_line, max_x - 1), status_attr)
    _safe_addstr(
        stdscr,
        max_y - 1,
        0,
        _truncate("Keys: Up/Down select  Enter/e edit  m mode  d service  s scan  c clear  ? help  q quit", max_x - 1),
        muted,
    )



def _render_left_panel(
    stdscr: Any,
    state: TUIState,
    precheck_data: Dict[str, Any],
    y: int,
    x: int,
    h: int,
    w: int,
) -> None:
    warning = curses.color_pair(2)
    error = curses.color_pair(3)
    accent = curses.color_pair(1)
    muted = curses.color_pair(4)

    rows: List[str] = []
    rows.append("MISSION PROFILE")
    rows.append("----------------")
    rows.append(f"Target endpoint    : {state.target}")

    ports_display = state.ports
    if state.scan_type in ("icmp", "arp"):
        ports_display = "(unused for this mode)"
    rows.append(f"Ports profile      : {ports_display}")
    rows.append(f"Scan mode          : {state.scan_type}")
    rows.append(f"Timeout sec        : {state.timeout}")
    rows.append(f"Delay sec          : {state.delay}")
    rows.append(f"Service detect     : {'ON' if state.service_detect else 'OFF'}")
    rows.append("")

    rows.append("EXECUTION LANE")
    rows.append("--------------")
    if precheck_data.get("use_unprivileged"):
        rows.append("Transport path     : fallback sockets")
        rows.append("ARP availability   : unavailable")
    else:
        rows.append("Transport path     : raw packet path")
        rows.append("ARP availability   : enabled")

    rows.append("")
    rows.append("SERVICE STRATEGY")
    rows.append("----------------")
    if state.service_detect:
        rows.append("Status             : enabled")
        rows.append("Behavior           : banner/protocol probing")
    else:
        rows.append("Status             : disabled")
        rows.append("Behavior           : port-state only")

    if state.scan_type in ("arp", "all") and precheck_data.get("use_unprivileged"):
        rows.append("")
        rows.append("WARNING: ARP in non-admin mode")
        rows.append("- ARP requires elevated privileges")
        rows.append("- Run as admin or avoid arp/all")

    usable_h = max(1, h)
    for i in range(min(len(rows), usable_h)):
        attr = 0
        line = rows[i]

        if i == 2 and FIELD_ORDER[state.selected_field] == "target":
            attr = curses.A_REVERSE | accent
        elif i == 3 and FIELD_ORDER[state.selected_field] == "ports":
            attr = curses.A_REVERSE | accent
        elif i == 4 and FIELD_ORDER[state.selected_field] == "scan_type":
            attr = curses.A_REVERSE | accent
        elif i == 5 and FIELD_ORDER[state.selected_field] == "timeout":
            attr = curses.A_REVERSE | accent
        elif i == 6 and FIELD_ORDER[state.selected_field] == "delay":
            attr = curses.A_REVERSE | accent
        elif i == 7 and FIELD_ORDER[state.selected_field] == "service_detect":
            attr = curses.A_REVERSE | accent

        if i in (0, 9, 14):
            attr |= curses.A_BOLD | muted

        if "WARNING:" in line:
            attr |= warning | curses.A_BOLD
        elif line.startswith("- ") and state.scan_type in ("arp", "all") and precheck_data.get("use_unprivileged"):
            attr |= error

        _safe_addstr(stdscr, y + i, x, _truncate(line, w), attr)



def _render_right_panel(stdscr: Any, state: TUIState, y: int, x: int, h: int, w: int) -> None:
    if h < 8 or w < 20:
        return

    activity_h = max(8, h // 3)
    telemetry_h = max(5, h // 8)
    results_h = h - activity_h - telemetry_h - 1

    _draw_box(stdscr, y, x, activity_h, w, "Operator Timeline")
    _draw_box(stdscr, y + activity_h, x, telemetry_h, w, "Session Telemetry")
    _draw_box(stdscr, y + activity_h + telemetry_h, x, results_h, w, "Findings")

    spinner_frames = ["|", "/", "-", "\\"]
    if state.scanning:
        elapsed = time.time() - state.started_at
        spin = spinner_frames[state.spinner_index % len(spinner_frames)]
        _safe_addstr(
            stdscr,
            y + 1,
            x + 2,
            _truncate(f"Live stream: running {state.scan_type} {spin}  elapsed={elapsed:.1f}s", max(0, w - 4)),
            curses.color_pair(2),
        )
    else:
        _safe_addstr(stdscr, y + 1, x + 2, _truncate("Live stream: idle", max(0, w - 4)), curses.color_pair(4))

    activity_body_h = max(1, activity_h - 3)
    visible_activity = state.activity_lines[-activity_body_h:]
    start_row = y + 2
    for i, line in enumerate(visible_activity):
        _safe_addstr(stdscr, start_row + i, x + 2, _truncate(line, max(0, w - 4)))

    # Telemetry strip
    elapsed = (time.time() - state.started_at) if state.scanning else 0.0
    selected = FIELD_ORDER[state.selected_field]
    telemetry = [
        f"focus={selected}",
        f"mode={state.scan_type}",
        f"service={'on' if state.service_detect else 'off'}",
        f"runtime={elapsed:.1f}s" if state.scanning else "runtime=idle",
    ]
    tele_line = "  |  ".join(telemetry)
    _safe_addstr(
        stdscr,
        y + activity_h + 1,
        x + 2,
        _truncate(tele_line, max(0, w - 4)),
        curses.color_pair(4),
    )

    result_body_h = max(1, results_h - 2)
    visible_results = state.result_lines[-result_body_h:]
    start_result_row = y + activity_h + telemetry_h + 1
    for i, line in enumerate(visible_results):
        attr = 0
        if line.startswith("Scan Errors") or line.startswith("  -"):
            attr = curses.color_pair(3)
        _safe_addstr(stdscr, start_result_row + i, x + 2, _truncate(line, max(0, w - 4)), attr)


def _render_help_overlay(stdscr: Any) -> None:
    max_y, max_x = stdscr.getmaxyx()
    width = min(96, max_x - 6)
    height = min(22, max_y - 6)
    y = (max_y - height) // 2
    x = (max_x - width) // 2

    _draw_box(stdscr, y, x, height, width, "Command Deck // Help")

    lines = [
        "Navigation",
        "  Up/Down            move active focus across command fields",
        "  Left/Right         rotate scan mode when Scan mode is selected",
        "",
        "Actions",
        "  e or Enter         edit focused field",
        "  m                  quick rotate scan mode",
        "  d                  toggle service detection",
        "  s                  launch scan job",
        "  c                  clear timeline and findings",
        "",
        "Scan Logic Notes",
        "  - Ports are used only by tcp, udp, or all.",
        "  - Service detection probes banners/protocol hints after base scan.",
        "  - In non-admin mode, arp (and all with arp) will report warnings.",
        "",
        "Workflow",
        "  1. Set target + mode",
        "  2. Tune timeout/delay",
        "  3. Start scan and inspect findings",
        "",
        "Press any key (or ?) to close help.",
    ]

    for i, line in enumerate(lines[: max(0, height - 2)]):
        _safe_addstr(stdscr, y + 1 + i, x + 2, _truncate(line, max(0, width - 4)))
