"""
Process Hierarchy & Anomaly Inspector
=====================================
Defensive tool that inspects the system process table, reconstructs
parent-child relationships, and flags structural anomalies and suspicious patterns.

Educational Objectives:
    - Trace process ancestry: init/systemd -> daemon -> worker or shell -> child
    - Detect abnormal parent-child execution lineages (e.g., web servers spawning shells)
    - Identify processes running from ephemeral or world-writable paths (/tmp, AppData\\Temp)
    - Spot Linux memory-only processes whose disk binaries have been deleted ("(deleted)")
    - Understand how defensive EDR (Endpoint Detection & Response) systems evaluate processes

Dependencies: Python stdlib only (os, sys, re, platform, subprocess, json)

Usage:
    # Scan system for process anomalies
    python -m defense.process_inspector --anomalies

    # Render visual process hierarchy tree
    python -m defense.process_inspector --tree

    # Inspect a specific process by PID
    python -m defense.process_inspector --pid <PID>

    # Output full audit as JSON
    python -m defense.process_inspector --json
"""

import argparse
import json
import os
import platform
import subprocess
from typing import Any

# Suspicious parent-to-child process combinations
SUSPICIOUS_SPAWN_PATTERNS = [
    # Office / Reader spawning shells (macro / exploit behavior)
    {
        "parent": r"(?:winword|excel|powerpnt|acrord32|acrobat)\.exe",
        "child": r"(?:cmd|powershell|pwsh|wscript|cscript)\.exe",
    },
    # Web servers spawning shells directly
    {
        "parent": r"(?:nginx|apache2|httpd|tomcat|w3wp\.exe)",
        "child": r"(?:sh|bash|zsh|cmd\.exe|powershell\.exe)",
    },
    # Database servers spawning interactive shells
    {
        "parent": r"(?:mysqld|postgres|sqlservr\.exe)",
        "child": r"(?:sh|bash|cmd\.exe|powershell\.exe)",
    },
]

# Sensitive / temporary directories where persistent code execution is unusual
SUSPICIOUS_PATHS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
]


class ProcessNode:
    """Represents a process with its metadata and tree relationships."""

    def __init__(
        self,
        pid: int,
        ppid: int,
        name: str,
        cmdline: str = "",
        exe_path: str = "",
        user: str = "",
        is_deleted_exe: bool = False,
    ):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.cmdline = cmdline
        self.exe_path = exe_path
        self.user = user
        self.is_deleted_exe = is_deleted_exe
        self.children: list[ProcessNode] = []
        self.anomalies: list[str] = []

    def evaluate_anomalies(self) -> list[str]:
        """Perform heuristic checks against process attributes."""
        reasons = []

        # Check 1: Deleted executable running from memory (Linux /proc/<pid>/exe -> target (deleted))
        if self.is_deleted_exe:
            reasons.append(
                "Binary deleted from disk while still executing in memory (evasion indicator)"
            )

        # Check 2: Binary executing from temporary or world-writable directories
        lower_exe = self.exe_path.lower()
        for susp_path in SUSPICIOUS_PATHS:
            if susp_path in lower_exe:
                reasons.append(f"Executable resides in temporary directory ({susp_path})")
                break

        # Check 3: Encoded or obfuscated command line strings
        cmd_lower = self.cmdline.lower()
        if "-enc " in cmd_lower or "-encodedcommand" in cmd_lower:
            reasons.append("PowerShell executing base64-encoded command string")
        if "curl " in cmd_lower and ("| bash" in cmd_lower or "| sh" in cmd_lower):
            reasons.append("Piping untrusted remote download directly to shell interpreter")

        self.anomalies = reasons
        return reasons

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "cmdline": self.cmdline,
            "exe_path": self.exe_path,
            "user": self.user,
            "is_deleted_exe": self.is_deleted_exe,
            "anomalies": self.anomalies,
            "children_pids": [c.pid for c in self.children],
        }


# ─── Process Gathering Implementations ───────────────────────────


def _gather_linux_processes() -> dict[int, ProcessNode]:
    """Parse Linux /proc filesystem for fast, dependency-free process enumeration."""
    processes: dict[int, ProcessNode] = {}
    if not os.path.exists("/proc"):
        return processes

    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        proc_dir = os.path.join("/proc", entry)

        ppid = 0
        name = "unknown"
        cmdline = ""
        exe_path = ""
        is_deleted = False

        # Read stat for PPID and comm
        stat_path = os.path.join(proc_dir, "stat")
        if os.path.exists(stat_path):
            try:
                with open(stat_path) as f:
                    content = f.read()
                    # format: pid (comm) state ppid ...
                    start = content.find("(")
                    end = content.rfind(")")
                    if start != -1 and end != -1:
                        name = content[start + 1 : end]
                        rest = content[end + 2 :].split()
                        if len(rest) >= 2:
                            ppid = int(rest[1])
            except (OSError, ValueError):
                pass

        # Read cmdline
        cmd_path = os.path.join(proc_dir, "cmdline")
        if os.path.exists(cmd_path):
            try:
                with open(cmd_path, "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore").strip()
            except OSError:
                pass

        # Read exe symlink
        exe_link = os.path.join(proc_dir, "exe")
        try:
            target = os.readlink(exe_link)
            exe_path = target
            if "(deleted)" in target:
                is_deleted = True
        except (OSError, PermissionError):
            exe_path = ""

        node = ProcessNode(
            pid=pid,
            ppid=ppid,
            name=name,
            cmdline=cmdline,
            exe_path=exe_path,
            is_deleted_exe=is_deleted,
        )
        processes[pid] = node

    return processes


def _gather_windows_processes() -> dict[int, ProcessNode]:
    """Enumerate Windows processes via PowerShell CIM / WMI."""
    processes: dict[int, ProcessNode] = {}
    ps_cmd = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath | "
        "ConvertTo-Json -Compress"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        data = json.loads(res.stdout.strip())
        if isinstance(data, dict):
            data = [data]

        for item in data:
            pid = item.get("ProcessId")
            if not pid:
                continue
            ppid = item.get("ParentProcessId", 0)
            name = item.get("Name", "Unknown")
            cmdline = item.get("CommandLine") or ""
            exe_path = item.get("ExecutablePath") or ""

            processes[pid] = ProcessNode(
                pid=pid, ppid=ppid, name=name, cmdline=cmdline, exe_path=exe_path
            )
    except Exception:
        # Fallback to tasklist if PowerShell CIM fails
        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5
            )
            for line in res.stdout.strip().splitlines():
                parts = [p.strip(' "') for p in line.split('","')]
                if len(parts) >= 2 and parts[1].isdigit():
                    pid = int(parts[1])
                    processes[pid] = ProcessNode(pid=pid, ppid=0, name=parts[0])
        except Exception:
            pass

    return processes


def inspect_processes() -> dict[int, ProcessNode]:
    """Retrieve and build full process tree with anomaly annotations."""
    current_os = platform.system().lower()
    proc_map = _gather_windows_processes() if current_os == "windows" else _gather_linux_processes()

    # Link parent-child relationships
    for pid, node in proc_map.items():
        if node.ppid in proc_map and node.ppid != pid:
            proc_map[node.ppid].children.append(node)

    # Evaluate individual and lineage anomalies
    for node in proc_map.values():
        node.evaluate_anomalies()

        # Check lineage anomalies
        if node.ppid in proc_map:
            parent = proc_map[node.ppid]
            import re

            for pat in SUSPICIOUS_SPAWN_PATTERNS:
                if re.search(pat["parent"], parent.name, re.IGNORECASE) and re.search(
                    pat["child"], node.name, re.IGNORECASE
                ):
                    node.anomalies.append(
                        f"Suspicious spawn pattern: parent '{parent.name}' (PID {parent.pid}) spawned '{node.name}'"
                    )

    return proc_map


# ─── Tree Rendering & Formatting ─────────────────────────────────


def render_ascii_tree(root: ProcessNode, prefix: str = "", is_last: bool = True) -> list[str]:
    """Recursively format a subtree into an ASCII visual representation."""
    lines = []
    connector = "└── " if is_last else "├── "
    anomaly_tag = f" [!] ({', '.join(root.anomalies)})" if root.anomalies else ""
    lines.append(f"{prefix}{connector}{root.name} (PID: {root.pid}){anomaly_tag}")

    sub_prefix = prefix + ("    " if is_last else "│   ")
    for i, child in enumerate(root.children):
        last_child = i == len(root.children) - 1
        lines.extend(render_ascii_tree(child, sub_prefix, last_child))

    return lines


# ─── CLI Entrypoint ──────────────────────────────────────────────


class ProcessInspector:
    """Inspector interface for process diagnostics."""

    @staticmethod
    def audit() -> tuple[dict[int, ProcessNode], list[ProcessNode]]:
        procs = inspect_processes()
        anomalies = [p for p in procs.values() if p.anomalies]
        return procs, anomalies


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process Hierarchy & Anomaly Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--anomalies", action="store_true", help="Scan and list anomalous processes"
    )
    parser.add_argument("--tree", action="store_true", help="Render full process hierarchy tree")
    parser.add_argument(
        "--pid", type=int, default=None, help="Inspect detailed info for a specific PID"
    )
    parser.add_argument("--json", action="store_true", help="Output audit results as JSON")

    args = parser.parse_args()

    proc_map = inspect_processes()

    if args.pid:
        if args.pid in proc_map:
            print(json.dumps(proc_map[args.pid].to_dict(), indent=2))
        else:
            print(f"[ERROR] PID {args.pid} not found in active process table.")
        return

    if args.json:
        out = {str(pid): node.to_dict() for pid, node in proc_map.items()}
        print(json.dumps(out, indent=2))
        return

    anomalous = [p for p in proc_map.values() if p.anomalies]

    if args.tree:
        print("=" * 75)
        print(" Process Hierarchy Tree ")
        print("=" * 75)
        # Find roots (processes whose PPID is 0 or not in proc_map)
        roots = [p for p in proc_map.values() if p.ppid == 0 or p.ppid not in proc_map]
        for r in roots[:15]:  # limit top-level roots for readability
            tree_lines = render_ascii_tree(r)
            for line in tree_lines:
                print(line)
        print(
            f"\n[Total processes tracked: {len(proc_map)} | Root trees displayed: {min(15, len(roots))}]"
        )
        return

    # Default / Anomalies mode
    print("=" * 75)
    print(f" Process Security Audit ({len(proc_map)} processes analyzed) ")
    print("=" * 75)

    if not anomalous:
        print("\n✅ Clean Audit: No suspicious parent-child relationships, deleted binaries,")
        print("   or abnormal temporary directory executions detected.")
    else:
        print(f"\n⚠️  Found {len(anomalous)} process(es) with security flags:\n")
        for p in anomalous:
            print(f"[PID {p.pid}] {p.name} (PPID: {p.ppid})")
            if p.exe_path:
                print(f"  Executable: {p.exe_path}")
            if p.cmdline:
                print(f"  Command:    {p.cmdline[:90]}")
            for a in p.anomalies:
                print(f"  └── ⚠️  {a}")
            print()


if __name__ == "__main__":
    main()
