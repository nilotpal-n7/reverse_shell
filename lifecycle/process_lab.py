"""
Process Lifecycle Laboratory
============================
Educational exploration of process lifecycles across Linux, Windows, and Android.

Educational Objectives:
    - Process States: Running, Sleeping, Zombie/Defunct, Orphan, Terminated
    - Identifiers: PID, PPID, PGID (Process Group ID), SID (Session ID)
    - Foreground vs Background: Standard I/O detachment, daemonization, session creation
    - Signal Handling: POSIX signals (SIGINT, SIGTERM, SIGHUP, SIGKILL) vs Windows console control events
    - Process Tracking: PID files, liveness checks, and graceful shutdown patterns

Safety & Boundaries:
    - All background workers launched are explicitly tagged, trackable, and user-stoppable.
    - No stealth or masquerading techniques are used; processes report clear names and PIDs.
    - Demonstrations clean up all spawned child processes automatically on exit.

Dependencies: Python stdlib only (os, sys, time, signal, subprocess, json, atexit)

Usage:
    # Inspect current process details
    python -m lifecycle.process_lab --info

    # Run a foreground task
    python -m lifecycle.process_lab --foreground --duration 5

    # Run a detached background worker (with tracking PID file)
    python -m lifecycle.process_lab --background --duration 10

    # Test signal handling (Ctrl+C, kill -TERM <pid>, etc.)
    python -m lifecycle.process_lab --listen-signals

    # Demonstrate zombie/orphan mechanics (Linux/WSL2 educational demo)
    python -m lifecycle.process_lab --zombie-demo

    # Check status of a PID
    python -m lifecycle.process_lab --check-pid <PID>
"""

import argparse
import atexit
import json
import os
import platform
import signal
import subprocess
import sys
import time
from typing import Any

# ─── Process State & Identity Information ────────────────────────


def get_process_info(pid: int | None = None) -> dict[str, Any]:
    """
    Collect comprehensive metadata about a process.
    If pid is None, inspects the current process.
    """
    target_pid = pid or os.getpid()
    is_current = target_pid == os.getpid()
    current_os = platform.system().lower()

    info: dict[str, Any] = {
        "pid": target_pid,
        "is_current": is_current,
        "platform": current_os,
        "python_executable": sys.executable if is_current else None,
    }

    # PPID (Parent Process ID)
    if hasattr(os, "getppid"):
        info["ppid"] = os.getppid() if is_current else _get_ppid_for_pid(target_pid)
    else:
        info["ppid"] = None

    # Process Group & Session ID (POSIX only)
    if hasattr(os, "getpgrp") and is_current:
        info["pgid"] = os.getpgrp()
    elif hasattr(os, "getpgid"):
        try:
            info["pgid"] = os.getpgid(target_pid)
        except OSError:
            info["pgid"] = None
    else:
        info["pgid"] = None

    if hasattr(os, "getsid"):
        try:
            info["sid"] = os.getsid(target_pid if not is_current else 0)
        except OSError:
            info["sid"] = None
    else:
        info["sid"] = None

    # Linux /proc introspection (WSL2, native Linux, Android)
    if current_os == "linux" or "android" in sys.platform.lower():
        proc_status = _read_proc_status(target_pid)
        if proc_status:
            info["proc_status"] = proc_status

    return info


def _get_ppid_for_pid(pid: int) -> int | None:
    """Attempt to find PPID of an arbitrary PID across platforms."""
    # On Linux /proc
    stat_file = f"/proc/{pid}/stat"
    if os.path.exists(stat_file):
        try:
            with open(stat_file) as f:
                fields = f.read().split()
                # Field index 3 is ppid (0-indexed: pid=0, comm=1, state=2, ppid=3)
                if len(fields) >= 4:
                    return int(fields[3])
        except (OSError, ValueError):
            pass

    # Windows WMIC or PowerShell
    if platform.system().lower() == "windows":
        try:
            res = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).Parent.Id",
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )
            val = res.stdout.strip()
            if val.isdigit():
                return int(val)
        except Exception:
            pass

    return None


def _read_proc_status(pid: int) -> dict[str, str] | None:
    """Parse /proc/<pid>/status on Linux/Android."""
    status_path = f"/proc/{pid}/status"
    if not os.path.exists(status_path):
        return None

    result = {}
    try:
        with open(status_path) as f:
            for line in f:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    if key in ("Name", "State", "PPid", "Threads", "VmSize", "VmRSS"):
                        result[key] = val
    except OSError:
        return None
    return result


def is_pid_alive(pid: int) -> bool:
    """
    Check if a process with given PID is currently active.
    Works cross-platform without third-party libraries.
    """
    if pid <= 0:
        return False

    current_os = platform.system().lower()
    if current_os == "windows":
        # Windows: Use tasklist /FI "PID eq ..."
        try:
            res = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return str(pid) in res.stdout
        except Exception:
            return False
    else:
        # POSIX (Linux, WSL2, macOS, Android):
        # Sending signal 0 does not terminate the process, but performs error checking.
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            # Operation not permitted means process exists but belongs to another user
            return True
        except ProcessLookupError:
            return False
        except OSError:
            return False


# ─── PID File Management ─────────────────────────────────────────


class PidFileManager:
    """
    Safe PID file manager for tracking and managing running instances.
    Ensures stale PID detection and automatic cleanup on exit.
    """

    def __init__(self, filepath: str):
        self.filepath = os.path.abspath(filepath)
        self.registered = False

    def write(self, metadata: dict[str, Any] | None = None) -> None:
        """Write current PID and metadata to file."""
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        data = {
            "pid": os.getpid(),
            "ppid": os.getppid() if hasattr(os, "getppid") else None,
            "created_at": time.time(),
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "command": " ".join(sys.argv),
            "platform": platform.platform(),
            "metadata": metadata or {},
        }
        with open(self.filepath, "w") as f:
            json.dump(data, f, indent=2)

        if not self.registered:
            atexit.register(self.remove)
            self.registered = True

    def read(self) -> dict[str, Any] | None:
        """Read metadata from PID file if it exists."""
        if not os.path.exists(self.filepath):
            return None
        try:
            with open(self.filepath) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def is_running(self) -> bool:
        """Check if the PID listed in the file is currently running."""
        data = self.read()
        if not data or "pid" not in data:
            return False
        return is_pid_alive(data["pid"])

    def remove(self) -> None:
        """Remove the PID file."""
        try:
            if os.path.exists(self.filepath):
                # Only delete if it belongs to us or is dead
                data = self.read()
                if (
                    not data
                    or data.get("pid") == os.getpid()
                    or not is_pid_alive(data.get("pid", 0))
                ):
                    os.remove(self.filepath)
        except OSError:
            pass


# ─── Foreground and Background Execution ─────────────────────────


def run_worker_internal(duration: int, mode_label: str) -> None:
    """Internal loop executed by foreground or background workers."""
    print(
        f"[{mode_label}] Process started with PID {os.getpid()} (Parent: {os.getppid() if hasattr(os, 'getppid') else 'N/A'})"
    )
    print(
        f"[{mode_label}] Running for {duration} seconds. Press Ctrl+C or kill {os.getpid()} to stop."
    )

    start_time = time.time()
    count = 0
    try:
        while time.time() - start_time < duration:
            count += 1
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            print(
                f"[{mode_label}] Heartbeat {count} | Elapsed: {elapsed}s | Remaining: {remaining}s"
            )
            time.sleep(1)
        print(f"[{mode_label}] Completed designated duration ({duration}s). Exiting normally.")
    except KeyboardInterrupt:
        print(f"\n[{mode_label}] Caught KeyboardInterrupt (Ctrl+C). Cleaning up gracefully...")
    finally:
        print(f"[{mode_label}] Process {os.getpid()} terminated.")


def spawn_worker(duration: int = 10, background: bool = False, pid_file: str | None = None) -> int:
    """
    Spawns a worker process either in foreground (blocking) or background (detached).
    Demonstrates cross-platform detachment mechanics.
    """
    if not background:
        # Foreground: execute directly in current process
        if pid_file:
            pf = PidFileManager(pid_file)
            pf.write({"type": "foreground", "duration": duration})
        run_worker_internal(duration, "FOREGROUND")
        return os.getpid()

    # Background spawn
    cmd = [
        sys.executable,
        "-m",
        "lifecycle.process_lab",
        "--internal-worker",
        "--duration",
        str(duration),
    ]

    current_os = platform.system().lower()

    if current_os == "windows":
        # Windows: Use CREATE_NEW_PROCESS_GROUP and DETACHED_PROCESS flags
        # CREATE_NEW_PROCESS_GROUP: 0x00000200
        # DETACHED_PROCESS: 0x00000008
        creationflags = 0x00000200 | 0x00000008
        proc = subprocess.Popen(
            cmd,
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    else:
        # POSIX (Linux, WSL2, macOS, Android/Termux):
        # start_new_session=True calls os.setsid() in the child before exec,
        # detaching it from the controlling terminal session.
        proc = subprocess.Popen(
            cmd,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )

    print(f"[SPAWNER] Spawned background worker with PID: {proc.pid}")

    if pid_file:
        pf = PidFileManager(pid_file)
        data = {
            "pid": proc.pid,
            "ppid": os.getpid(),
            "created_at": time.time(),
            "duration": duration,
            "type": "background_detached",
        }
        with open(pf.filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[SPAWNER] Wrote PID info to: {pid_file}")

    return proc.pid


# ─── Signal Handling Demonstration ───────────────────────────────


def listen_for_signals() -> None:
    """
    Sets up signal traps and runs an interactive loop.
    Demonstrates how POSIX and Windows signals are intercepted.
    """
    current_pid = os.getpid()
    print("=" * 65)
    print(" Signal Listener Laboratory ")
    print("=" * 65)
    print(f"Current PID: {current_pid}")
    print(f"Platform:    {platform.system()} ({platform.release()})")
    print("\nRegistered signal handlers:")

    handled_signals: list[str] = []

    def signal_handler(signum, frame):
        try:
            signame = signal.Signals(signum).name
        except (ValueError, AttributeError):
            signame = f"SIG#{signum}"
        print(f"\n[SIGNAL CAUGHT] Received {signame} ({signum}) at time {time.strftime('%X')}")

        if signum in (signal.SIGINT, signal.SIGTERM):
            print("[SHUTDOWN] Graceful termination requested. Performing cleanup...")
            print("[SHUTDOWN] Releasing resources, flushing buffers, saving state.")
            print("[SHUTDOWN] Exiting with status 0.")
            sys.exit(0)
        elif hasattr(signal, "SIGHUP") and signum == signal.SIGHUP:
            print("[CONFIG RELOAD] Received SIGHUP! Simulating configuration reload...")
        else:
            print(f"[INFO] Signal {signame} handled without exiting.")

    # Standard POSIX & Cross-platform signals
    for sig_name in ["SIGINT", "SIGTERM"]:
        if hasattr(signal, sig_name):
            sig = getattr(signal, sig_name)
            signal.signal(sig, signal_handler)
            handled_signals.append(f"{sig_name} (clean exit)")

    # POSIX-only signals
    for sig_name in ["SIGHUP", "SIGUSR1", "SIGUSR2"]:
        if hasattr(signal, sig_name):
            sig = getattr(signal, sig_name)
            try:
                signal.signal(sig, signal_handler)
                handled_signals.append(f"{sig_name}")
            except (ValueError, OSError):
                pass

    for s in handled_signals:
        print(f"  - {s}")

    print("\nHow to test this:")
    print("  1. Press Ctrl+C in this terminal (sends SIGINT)")
    if platform.system().lower() != "windows":
        print(f"  2. In another terminal, run: kill -TERM {current_pid}")
        if hasattr(signal, "SIGHUP"):
            print(
                f"  3. In another terminal, run: kill -HUP {current_pid} (simulates config reload)"
            )
    else:
        print(f"  2. In PowerShell, run: Stop-Process -Id {current_pid}")

    print("\nListening for signals... (Press Ctrl+C to exit)\n")

    counter = 0
    try:
        while True:
            time.sleep(1)
            counter += 1
            if counter % 5 == 0:
                print(f"[ACTIVE] Still listening... (PID: {current_pid}, Uptime: {counter}s)")
    except SystemExit:
        raise
    except Exception as e:
        print(f"Exception: {e}")


# ─── Zombie & Orphan Process Demonstration (Educational) ─────────


def run_zombie_orphan_demo() -> None:
    """
    Demonstrates the difference between Zombie and Orphan processes.
    Safe educational demonstration using controlled fork() or subprocess.
    """
    print("=" * 65)
    print(" Educational Process Concepts: Zombies vs Orphans ")
    print("=" * 65)

    current_os = platform.system().lower()
    if current_os != "linux":
        print("\n[NOTE] True POSIX Zombie/Orphan semantics rely on POSIX fork() and /proc.")
        print(f"Current platform: {platform.system()}. Explaining the concepts theoretically:\n")
        print("1. Zombie Process (<defunct>):")
        print("   - When a child process terminates, its entry remains in the OS process table")
        print("     until its parent reads its exit status using wait() or waitpid().")
        print("   - During this window, the process consumes no memory or CPU, only a PID slot.")
        print("   - If the parent never calls wait(), zombies accumulate (PID table exhaustion).")
        print("\n2. Orphan Process:")
        print("   - When a parent process dies before its child, the child becomes an orphan.")
        print(
            "   - In Linux/POSIX, orphans are automatically adopted by PID 1 (init/systemd/launchd)."
        )
        print(
            "   - PID 1 periodically calls wait() to reap adopted child processes when they finish."
        )
        print("\n3. Windows Equivalence:")
        print(
            "   - Windows does not have traditional zombies; process handles remain open until all"
        )
        print("     handles (HANDLE) to the process object are closed via CloseHandle().")
        return

    # POSIX Linux / WSL2 implementation
    if not hasattr(os, "fork"):
        print("[ERROR] os.fork() is not available in this environment.")
        return

    print("\nStep 1: Demonstrating a Zombie Process in /proc...")
    print("Spawning child process that exits immediately while parent sleeps without wait().")

    pid = os.fork()
    if pid == 0:
        # Child process: exits immediately
        print(f"  [Child  PID {os.getpid()}] Running and exiting now with code 42...")
        sys.exit(42)
    else:
        # Parent process: sleeps before reaping
        print(
            f"  [Parent PID {os.getpid()}] Spawned child PID {pid}. Sleeping 3s without calling wait()..."
        )
        time.sleep(1)

        # Inspect child state in /proc/<pid>/status
        status_file = f"/proc/{pid}/status"
        if os.path.exists(status_file):
            with open(status_file) as f:
                for line in f:
                    if line.startswith("State:"):
                        print(
                            f"  [Parent Check] Child state in /proc/{pid}/status: -> {line.strip()}"
                        )
        else:
            print(f"  [Parent Check] /proc/{pid}/status not found.")

        print(
            "  Notice state 'Z (zombie)' or 'defunct'. The child finished, but entry is in process table."
        )
        print(f"  [Parent PID {os.getpid()}] Now reaping child PID {pid} via os.waitpid()...")
        reaped_pid, status = os.waitpid(pid, 0)
        exit_code = (
            os.waitstatus_to_exitcode(status)
            if hasattr(os, "waitstatus_to_exitcode")
            else (status >> 8)
        )
        print(
            f"  [Parent Reaped] Successfully reaped child PID {reaped_pid} with exit code {exit_code}."
        )
        print("  Child process has been completely removed from the process table.")

    print("\nStep 2: Orphan Process Explanation:")
    print("  When a parent process exits before its children, the child's PPID changes to PID 1")
    print(
        "  (systemd / init / subreaper). In WSL2, PID 1 reaps orphaned processes automatically.\n"
    )


# ─── CLI Entrypoint ──────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process Lifecycle & Signal Handling Laboratory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m lifecycle.process_lab --info
  python -m lifecycle.process_lab --foreground --duration 5
  python -m lifecycle.process_lab --background --duration 15 --pid-file worker.pid
  python -m lifecycle.process_lab --check-pid 1234
  python -m lifecycle.process_lab --listen-signals
  python -m lifecycle.process_lab --zombie-demo
""",
    )
    parser.add_argument(
        "--info", action="store_true", help="Display process metadata for current process"
    )
    parser.add_argument("--foreground", action="store_true", help="Run worker in foreground")
    parser.add_argument(
        "--background", action="store_true", help="Spawn detached worker in background"
    )
    parser.add_argument(
        "--duration", type=int, default=10, help="Worker run duration in seconds (default: 10)"
    )
    parser.add_argument(
        "--pid-file", type=str, default=None, help="Path to write/manage PID tracking file"
    )
    parser.add_argument(
        "--check-pid", type=int, default=None, help="Check if specified PID is alive"
    )
    parser.add_argument(
        "--listen-signals", action="store_true", help="Interactive signal handling demonstration"
    )
    parser.add_argument(
        "--zombie-demo", action="store_true", help="Educational zombie process demo (Linux/WSL2)"
    )
    parser.add_argument("--internal-worker", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.internal_worker:
        run_worker_internal(args.duration, "BACKGROUND_WORKER")
        return

    if args.info:
        info = get_process_info()
        print("\n=== Current Process Information ===")
        print(json.dumps(info, indent=2))
        return

    if args.check_pid is not None:
        alive = is_pid_alive(args.check_pid)
        print(f"PID {args.check_pid}: {'ALIVE' if alive else 'NOT RUNNING / DEAD'}")
        if alive:
            details = get_process_info(args.check_pid)
            print(json.dumps(details, indent=2))
        return

    if args.listen_signals:
        listen_for_signals()
        return

    if args.zombie_demo:
        run_zombie_orphan_demo()
        return

    if args.foreground:
        spawn_worker(duration=args.duration, background=False, pid_file=args.pid_file)
        return

    if args.background:
        pid = spawn_worker(duration=args.duration, background=True, pid_file=args.pid_file)
        print(f"Background worker launched with PID {pid}.")
        return

    # Default action if no args
    parser.print_help()


if __name__ == "__main__":
    main()
