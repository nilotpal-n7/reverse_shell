"""
Platform Detection Module
=========================
Identifies OS, architecture, runtime environment, and available capabilities.
Designed to work across Windows, Linux (including WSL2), and Android (Termux).

Educational Goals:
    - Understand programmatic environment identification
    - Learn detection differences across OS families
    - Discover Android vs Linux detection challenges (see docs/android_detection.md)

Dependencies: Python stdlib only (os, sys, platform, shutil, subprocess)

Usage:
    # As a module
    from core.platform_detect import get_full_platform_report
    report = get_full_platform_report()

    # As a CLI
    python -m core.platform_detect          # Formatted output
    python -m core.platform_detect --json   # JSON output
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from typing import Any

# ─── Capability Definitions ─────────────────────────────────────
# Each entry maps a logical capability name to candidate binary names.
# The first binary found (via shutil.which) is used.

UTILITY_CHECKS: dict[str, list] = {
    "python3": ["python3", "python"],
    "bash": ["bash"],
    "powershell": ["pwsh", "powershell"],
    "curl": ["curl"],
    "wget": ["wget"],
    "openssl": ["openssl"],
    "ssh": ["ssh"],
    "nmap": ["nmap"],
    "tcpdump": ["tcpdump"],
    "wireshark": ["tshark"],  # CLI interface
    "systemctl": ["systemctl"],
    "sc": ["sc.exe"],  # Windows service control
    "netstat": ["netstat"],
    "ss": ["ss"],
    "ip": ["ip"],
    "adb": ["adb"],
    "gcc": ["gcc"],
    "make": ["make"],
    "git": ["git"],
}

# Version-detection flags per tool (some use non-standard flags)
_VERSION_FLAGS: dict[str, list] = {
    "python3": ["--version"],
    "python": ["--version"],
    "bash": ["--version"],
    "pwsh": ["--version"],
    "powershell": ["-Command", "$PSVersionTable.PSVersion.ToString()"],
    "curl": ["--version"],
    "wget": ["--version"],
    "openssl": ["version"],
    "ssh": ["-V"],  # Prints to stderr
    "gcc": ["--version"],
    "make": ["--version"],
    "git": ["--version"],
}


# ═══════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════


def detect_os() -> dict[str, str]:
    """Detect the base operating system.

    Returns:
        os_family:   'windows', 'linux', 'darwin', 'android', or 'unknown'
        os_name:     Distribution or edition name
        os_version:  Version string
        os_release:  Kernel or build release string

    Notes:
        Android is reported as a separate os_family because its userspace,
        permissions model, and available APIs differ significantly from
        desktop Linux, even though it shares the Linux kernel.
    """
    system = platform.system().lower()

    result = {
        "os_family": system if system in ("windows", "linux", "darwin") else "unknown",
        "os_name": "",
        "os_version": "",
        "os_release": platform.release(),
    }

    if system == "windows":
        try:
            edition = platform.win32_edition()
        except AttributeError:
            edition = ""
        result["os_name"] = f"Windows {edition}".strip() if edition else "Windows"
        result["os_version"] = platform.version()

    elif system == "linux":
        # Check for Android first (shares the Linux kernel)
        if _is_android():
            result["os_family"] = "android"
            result["os_name"] = "Android"
            result["os_version"] = _get_android_version()
        else:
            distro = _read_os_release()
            result["os_name"] = distro.get("NAME", "Linux")
            result["os_version"] = distro.get("VERSION_ID", distro.get("VERSION", ""))

    elif system == "darwin":
        result["os_name"] = "macOS"
        result["os_version"] = platform.mac_ver()[0]

    return result


def detect_architecture() -> dict[str, str]:
    """Detect CPU architecture and pointer size.

    Returns:
        machine:      Raw machine type from platform.machine()
        architecture: Normalized name (x86_64, arm64, armv7, x86, …)
        bits:         '32' or '64'
        byteorder:    'little' or 'big'
    """
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "x64": "x86_64",
        "i386": "x86",
        "i486": "x86",
        "i586": "x86",
        "i686": "x86",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
        "armv7": "armv7",
        "armv6l": "armv6",
    }

    return {
        "machine": platform.machine(),
        "architecture": arch_map.get(machine, machine),
        "bits": "64" if sys.maxsize > 2**32 else "32",
        "byteorder": sys.byteorder,
    }


def detect_runtime() -> dict[str, Any]:
    """Detect the runtime environment.

    Returns:
        environment:    'native', 'wsl2', 'wsl1', 'termux', 'container', 'ssh'
        python_version: e.g. '3.11.5'
        python_path:    Path to the running interpreter
        virtual_env:    Active virtualenv path or None
        details:        Additional environment-specific metadata
    """
    result: dict[str, Any] = {
        "environment": "native",
        "python_version": platform.python_version(),
        "python_path": sys.executable,
        "virtual_env": os.environ.get("VIRTUAL_ENV"),
        "details": {},
    }

    if platform.system() == "Linux":
        if _is_wsl():
            result["environment"] = _detect_wsl_version()
            result["details"]["wsl_distro"] = os.environ.get("WSL_DISTRO_NAME", "unknown")
            result["details"]["wsl_interop"] = os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop")
        elif _is_termux():
            result["environment"] = "termux"
            result["details"]["termux_prefix"] = os.environ.get("PREFIX", "")
            result["details"]["termux_version"] = os.environ.get("TERMUX_VERSION", "unknown")
        elif _is_container():
            result["environment"] = "container"
            result["details"]["container_type"] = _detect_container_type()

    # SSH session detection (any OS, additive)
    if os.environ.get("SSH_CLIENT") or os.environ.get("SSH_CONNECTION"):
        if result["environment"] == "native":
            result["environment"] = "ssh"
        result["details"]["ssh_session"] = True

    return result


def detect_capabilities() -> dict[str, dict[str, Any]]:
    """Probe which utilities, interpreters, and runtimes are available.

    For each capability, returns:
        available: bool
        path:      Absolute path to binary, or None
        binary:    Matched binary name, or None
        version:   First-line version string, or None
    """
    capabilities: dict[str, dict[str, Any]] = {}

    for name, candidates in UTILITY_CHECKS.items():
        found = False
        for candidate in candidates:
            path = shutil.which(candidate)
            if path:
                capabilities[name] = {
                    "available": True,
                    "path": path,
                    "binary": candidate,
                    "version": _get_tool_version(candidate),
                }
                found = True
                break

        if not found:
            capabilities[name] = {
                "available": False,
                "path": None,
                "binary": None,
                "version": None,
            }

    return capabilities


def get_full_platform_report() -> dict[str, Any]:
    """Generate a comprehensive platform report combining all detections.

    This is the primary entry point — returns a single dict suitable for
    JSON serialization and transmission to the controller.
    """
    return {
        "os": detect_os(),
        "architecture": detect_architecture(),
        "runtime": detect_runtime(),
        "capabilities": detect_capabilities(),
        "hostname": platform.node(),
        "username": _safe_get_username(),
    }


def print_platform_report(report: dict | None = None) -> None:
    """Pretty-print a platform report to stdout."""
    if report is None:
        report = get_full_platform_report()

    print("=" * 60)
    print("  PLATFORM DETECTION REPORT")
    print("=" * 60)

    # ── OS ──
    oi = report["os"]
    print(f"\n{'[Operating System]':─<60}")
    print(f"  Family:     {oi['os_family']}")
    print(f"  Name:       {oi['os_name']}")
    print(f"  Version:    {oi['os_version']}")
    print(f"  Release:    {oi['os_release']}")

    # ── Architecture ──
    ar = report["architecture"]
    print(f"\n{'[Architecture]':─<60}")
    print(f"  Machine:    {ar['machine']}")
    print(f"  Normalized: {ar['architecture']}")
    print(f"  Bits:       {ar['bits']}")
    print(f"  Byte Order: {ar['byteorder']}")

    # ── Runtime ──
    rt = report["runtime"]
    print(f"\n{'[Runtime Environment]':─<60}")
    print(f"  Environment:  {rt['environment']}")
    print(f"  Python:       {rt['python_version']}")
    print(f"  Interpreter:  {rt['python_path']}")
    if rt["virtual_env"]:
        print(f"  Virtual Env:  {rt['virtual_env']}")
    for k, v in rt.get("details", {}).items():
        print(f"  {k}: {v}")

    # ── Host ──
    print(f"\n{'[Host]':─<60}")
    print(f"  Hostname:   {report['hostname']}")
    print(f"  Username:   {report['username']}")

    # ── Capabilities ──
    caps = report["capabilities"]
    avail = {k: v for k, v in caps.items() if v["available"]}
    missing = {k: v for k, v in caps.items() if not v["available"]}

    print(f"\n{'[Capabilities]':─<60}")
    if avail:
        print("  Available:")
        for name, info in sorted(avail.items()):
            ver = f" ({info['version']})" if info["version"] else ""
            print(f"    \u2713 {name:<15} {info['path']}{ver}")
    if missing:
        print("  Not Found:")
        for name in sorted(missing.keys()):
            print(f"    \u2717 {name}")

    print("\n" + "=" * 60)


# ═══════════════════════════════════════════════════════════════
#  PRIVATE HELPERS
# ═══════════════════════════════════════════════════════════════


def _is_android() -> bool:
    """Detect Android.

    Limitations (see docs/android_detection.md):
        - A Linux container on Android may not expose /system/build.prop.
        - Termux sets ANDROID_ROOT but other Android shells may not.
        - /proc/version rarely contains "android" on stock kernels.
        - There is no single reliable indicator from the kernel alone.
    """
    if os.path.exists("/system/build.prop"):
        return True
    if shutil.which("getprop"):
        return True
    if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"):
        return True
    try:
        with open("/proc/version") as f:
            if "android" in f.read().lower():
                return True
    except (FileNotFoundError, PermissionError):
        pass
    return False


def _get_android_version() -> str:
    """Try to retrieve the Android version via getprop."""
    try:
        result = subprocess.run(
            ["getprop", "ro.build.version.release"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release (or /usr/lib/os-release) into a dict."""
    info: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, _, value = line.partition("=")
                        info[key] = value.strip('"').strip("'")
            break
        except FileNotFoundError:
            continue
    return info


def _is_wsl() -> bool:
    """Detect Windows Subsystem for Linux."""
    try:
        with open("/proc/version") as f:
            ver = f.read().lower()
            if "microsoft" in ver or "wsl" in ver:
                return True
    except FileNotFoundError:
        pass
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    return bool(os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"))


def _detect_wsl_version() -> str:
    """Distinguish WSL1 from WSL2.

    WSL2 runs a real Linux kernel inside a lightweight Hyper-V VM.
    Its /proc/version typically contains 'microsoft-standard-WSL2'.
    WSL1 translates Linux syscalls directly to NT kernel calls.
    """
    try:
        with open("/proc/version") as f:
            version = f.read()
            if "WSL2" in version or "microsoft-standard" in version:
                return "wsl2"
    except FileNotFoundError:
        pass
    return "wsl1"


def _is_termux() -> bool:
    """Detect Termux environment on Android."""
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    return bool(os.path.exists("/data/data/com.termux"))


def _is_container() -> bool:
    """Detect execution inside a container."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup") as f:
            content = f.read()
            for marker in ("docker", "containerd", "lxc", "kubepods"):
                if marker in content:
                    return True
    except (FileNotFoundError, PermissionError):
        pass
    return bool(
        os.environ.get("container")
        or os.environ.get("CONTAINER")
        or os.environ.get("KUBERNETES_SERVICE_HOST")
    )


def _detect_container_type() -> str:
    """Identify the container runtime."""
    if os.path.exists("/.dockerenv"):
        return "docker"
    try:
        with open("/proc/1/cgroup") as f:
            content = f.read()
            if "docker" in content:
                return "docker"
            if "lxc" in content:
                return "lxc"
            if "containerd" in content:
                return "containerd"
    except (FileNotFoundError, PermissionError):
        pass
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "kubernetes"
    return "unknown"


def _get_tool_version(tool: str) -> str | None:
    """Try to retrieve a single-line version string for a tool."""
    flags = _VERSION_FLAGS.get(tool, ["--version"])
    try:
        result = subprocess.run(
            [tool, *flags],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or result.stderr or "").strip()
        if output:
            return output.split("\n")[0].strip()[:120]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _safe_get_username() -> str:
    """Get the current username, safely, across platforms."""
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Detect platform, architecture, runtime, and capabilities",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of formatted text",
    )
    args = parser.parse_args()

    report = get_full_platform_report()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_platform_report(report)
