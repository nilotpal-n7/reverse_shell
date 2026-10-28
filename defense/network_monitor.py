"""
Network Connection Monitor & Forensics
======================================
Defensive tool that observes active network sockets, listening services,
and connection endpoints, mapping network traffic back to responsible processes.

Educational Objectives:
    - Understand socket states: LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT
    - Map socket inodes and ports to local process identifiers (PID)
    - Detect unexpected outbound connections and beaconing patterns
    - Observe differences between loopback (127.0.0.1) and interface (0.0.0.0) bindings

Dependencies: Python stdlib (subprocess, socket, re, platform, json, time)
Optional: psutil (if installed, provides enriched process details)

Usage:
    # Print snapshot of active connections
    python -m defense.network_monitor

    # Filter for connections on specific port (e.g., our lab port 4444)
    python -m defense.network_monitor --port 4444

    # Output as structured JSON
    python -m defense.network_monitor --json

    # Continuous monitoring mode (alerts on new/closed sockets)
    python -m defense.network_monitor --watch --interval 2
"""

import argparse
import json
import os
import platform
import re
import subprocess
import time
from typing import Any

# Common lab / suspicious ports for defensive alerting
FLAGGED_PORTS: set[int] = {4444, 1337, 31337, 6667, 8888, 9999, 1234, 5555, 4443}


class SocketConnection:
    """Represents a single network connection or listening socket."""

    def __init__(
        self,
        proto: str,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        state: str,
        pid: int | None = None,
        process_name: str | None = None,
    ):
        self.proto = proto.upper()
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.state = state.upper()
        self.pid = pid
        self.process_name = process_name or "Unknown"

    @property
    def key(self) -> str:
        """Unique signature of the connection."""
        return f"{self.proto}_{self.local_ip}:{self.local_port}->{self.remote_ip}:{self.remote_port}_{self.state}"

    def is_suspicious(self) -> tuple[bool, list[str]]:
        """Evaluate connection against defensive anomaly rules."""
        reasons = []
        # Rule 1: Connected to or listening on common lab/test ports
        if self.local_port in FLAGGED_PORTS or self.remote_port in FLAGGED_PORTS:
            reasons.append(
                f"Port match in lab/uncommon registry ({self.local_port or self.remote_port})"
            )

        # Rule 2: Listening bound to all interfaces (0.0.0.0)
        if self.state == "LISTEN" and self.local_ip in ("0.0.0.0", "::"):
            reasons.append("Listening publicly on all interfaces (0.0.0.0)")

        # Rule 3: Outbound ESTABLISHED connection without associated PID
        if self.state == "ESTABLISHED" and (self.pid is None or self.pid <= 0):
            reasons.append("Established connection with unresolved PID")

        return (len(reasons) > 0, reasons)

    def to_dict(self) -> dict[str, Any]:
        suspicious, reasons = self.is_suspicious()
        return {
            "proto": self.proto,
            "local_address": f"{self.local_ip}:{self.local_port}",
            "remote_address": f"{self.remote_ip}:{self.remote_port}",
            "state": self.state,
            "pid": self.pid,
            "process_name": self.process_name,
            "suspicious": suspicious,
            "reasons": reasons,
        }


def _get_process_name_by_pid(pid: int) -> str:
    """Cross-platform helper to obtain process name from PID."""
    if pid <= 0:
        return "System"

    # On Linux/Android procfs
    comm_path = f"/proc/{pid}/comm"
    if os.path.exists(comm_path):
        try:
            with open(comm_path) as f:
                return f.read().strip()
        except OSError:
            pass

    # Try psutil if available
    try:
        import psutil  # type: ignore

        p = psutil.Process(pid)
        return p.name()
    except Exception:
        pass

    return "Unknown"


# ─── Platform-Specific Parsers ───────────────────────────────────


def _parse_linux_ss() -> list[SocketConnection]:
    """Parse connections on Linux using 'ss -tunap'."""
    connections = []
    try:
        res = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=5)
        lines = res.stdout.strip().splitlines()
        if len(lines) <= 1:
            return []

        # Example line:
        # tcp  LISTEN  0  128  127.0.0.1:4444  0.0.0.0:*  users:(("python",pid=1234,fd=4))
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0]
            state = parts[1] if proto.startswith("tcp") else "UNCONN"
            local_idx = 4 if proto.startswith("tcp") else 3
            remote_idx = 5 if proto.startswith("tcp") else 4

            if len(parts) <= remote_idx:
                continue

            local_addr = parts[local_idx]
            remote_addr = parts[remote_idx]

            # Parse IP and Port
            def split_addr(s: str) -> tuple[str, int]:
                s = s.replace("[", "").replace("]", "")
                if ":" in s:
                    host, port_str = s.rsplit(":", 1)
                    port = int(port_str) if port_str.isdigit() else 0
                    return host, port
                return s, 0

            l_ip, l_port = split_addr(local_addr)
            r_ip, r_port = split_addr(remote_addr)

            # Parse PID and process name from users:(("python",pid=1234,...))
            pid = None
            pname = None
            rest = " ".join(parts[remote_idx + 1 :])
            pid_match = re.search(r"pid=(\d+)", rest)
            if pid_match:
                pid = int(pid_match.group(1))

            pname_match = re.search(r'"([^"]+)"', rest)
            if pname_match:
                pname = pname_match.group(1)

            if pid and not pname:
                pname = _get_process_name_by_pid(pid)

            connections.append(
                SocketConnection(
                    proto=proto,
                    local_ip=l_ip,
                    local_port=l_port,
                    remote_ip=r_ip,
                    remote_port=r_port,
                    state=state,
                    pid=pid,
                    process_name=pname,
                )
            )
    except Exception:
        pass
    return connections


def _parse_windows_netstat() -> list[SocketConnection]:
    """Parse connections on Windows using 'netstat -ano -p tcp'."""
    connections = []
    try:
        res = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=5
        )
        # Output format:
        # Proto  Local Address          Foreign Address        State           PID
        # TCP    127.0.0.1:4444         0.0.0.0:0              LISTENING       1234
        for line in res.stdout.strip().splitlines():
            line = line.strip()
            if not line.startswith("TCP"):
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0]
            local_addr = parts[1]
            foreign_addr = parts[2]
            state = parts[3]
            pid_str = parts[4]

            def split_addr(s: str) -> tuple[str, int]:
                if ":" in s:
                    h, p = s.rsplit(":", 1)
                    return h, int(p) if p.isdigit() else 0
                return s, 0

            l_ip, l_port = split_addr(local_addr)
            r_ip, r_port = split_addr(foreign_addr)
            pid = int(pid_str) if pid_str.isdigit() else None
            pname = _get_process_name_by_pid(pid) if pid else None

            # Standardize state name
            std_state = "LISTEN" if state == "LISTENING" else state

            connections.append(
                SocketConnection(
                    proto=proto,
                    local_ip=l_ip,
                    local_port=l_port,
                    remote_ip=r_ip,
                    remote_port=r_port,
                    state=std_state,
                    pid=pid,
                    process_name=pname,
                )
            )
    except Exception:
        pass
    return connections


def inspect_active_connections(filter_port: int | None = None) -> list[SocketConnection]:
    """
    Retrieve active connections across Linux/WSL2, Windows, or Android.
    Optionally filter by port number.
    """
    current_os = platform.system().lower()
    conns: list[SocketConnection] = []

    if current_os == "windows":
        conns = _parse_windows_netstat()
    else:
        # Linux, WSL2, macOS, Android
        conns = _parse_linux_ss()
        if not conns:
            # Fallback to netstat on Linux if ss is unavailable
            conns = _parse_windows_netstat()

    if filter_port is not None:
        conns = [c for c in conns if c.local_port == filter_port or c.remote_port == filter_port]

    return conns


# ─── Interactive Continuous Monitor ──────────────────────────────


class NetworkMonitor:
    """Continuous monitor tracking connection lifecycle (opened / closed)."""

    def __init__(self, filter_port: int | None = None, interval: float = 2.0):
        self.filter_port = filter_port
        self.interval = interval
        self.known_sockets: dict[str, SocketConnection] = {}

    def run(self) -> None:
        """Run the monitoring loop."""
        print("=" * 70)
        print(" Network Connection Security Observer ")
        print("=" * 70)
        print(f"Monitoring interval: {self.interval}s")
        if self.filter_port:
            print(f"Filtering for port:  {self.filter_port}")
        print("Press Ctrl+C to terminate observation.\n")

        # Initial baseline
        initial = inspect_active_connections(self.filter_port)
        for c in initial:
            self.known_sockets[c.key] = c

        print(f"Baseline established: {len(self.known_sockets)} active socket(s) tracked.\n")

        try:
            while True:
                time.sleep(self.interval)
                current = inspect_active_connections(self.filter_port)
                current_map = {c.key: c for c in current}

                # Detect newly opened sockets
                for key, conn in current_map.items():
                    if key not in self.known_sockets:
                        t = time.strftime("%X")
                        suspicious, reasons = conn.is_suspicious()
                        badge = "[ALERT]" if suspicious else "[NEW]"
                        print(
                            f"{badge} {t} | {conn.proto:<4} {conn.local_ip}:{conn.local_port} -> "
                            f"{conn.remote_ip}:{conn.remote_port} | State: {conn.state} | "
                            f"PID: {conn.pid} ({conn.process_name})"
                        )
                        if reasons:
                            for r in reasons:
                                print(f"        └── Note: {r}")

                # Detect closed sockets
                for key, old_conn in self.known_sockets.items():
                    if key not in current_map:
                        t = time.strftime("%X")
                        print(
                            f"[CLOSED] {t} | {old_conn.proto:<4} {old_conn.local_ip}:{old_conn.local_port} -> "
                            f"{old_conn.remote_ip}:{old_conn.remote_port} (PID {old_conn.pid})"
                        )

                self.known_sockets = current_map
        except KeyboardInterrupt:
            print("\nObservation stopped by user.")


# ─── CLI Entrypoint ──────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Connection Monitor & Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=None, help="Filter connections by port")
    parser.add_argument(
        "--watch", action="store_true", help="Continuously monitor and alert on socket changes"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0, help="Poll interval in seconds (default: 2.0)"
    )
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if args.watch:
        monitor = NetworkMonitor(filter_port=args.port, interval=args.interval)
        monitor.run()
        return

    # Snapshot mode
    connections = inspect_active_connections(filter_port=args.port)

    if args.json:
        data = [c.to_dict() for c in connections]
        print(json.dumps(data, indent=2))
        return

    print("=" * 80)
    print(f" Active Network Connections Snapshot ({len(connections)} found) ")
    print("=" * 80)
    print(
        f"{'PROTO':<6} {'LOCAL ADDRESS':<22} {'REMOTE ADDRESS':<22} {'STATE':<12} {'PID':<8} {'PROCESS'}"
    )
    print("-" * 80)

    for c in connections:
        pid_str = str(c.pid) if c.pid is not None else "-"
        pname = c.process_name[:18]
        suspicious, _ = c.is_suspicious()
        flag = " [!]" if suspicious else ""
        print(
            f"{c.proto:<6} {c.local_ip + ':' + str(c.local_port):<22} "
            f"{c.remote_ip + ':' + str(c.remote_port):<22} {c.state:<12} {pid_str:<8} {pname}{flag}"
        )

    print("-" * 80)
    flagged = [c for c in connections if c.is_suspicious()[0]]
    if flagged:
        print(f"\n[!] Flagged {len(flagged)} connection(s) requiring attention:")
        for fc in flagged:
            _, reasons = fc.is_suspicious()
            print(
                f"  - {fc.proto} {fc.local_ip}:{fc.local_port} -> {fc.remote_ip}:{fc.remote_port} (PID {fc.pid})"
            )
            for r in reasons:
                print(f"      • {r}")
    else:
        print("\nAll observed connections match standard baseline profiles.")


if __name__ == "__main__":
    main()
