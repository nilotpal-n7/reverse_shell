"""
Lifecycle Package
=================
Educational modules exploring operating system process lifecycles,
foreground/background execution, signal handling, termination behaviors,
and platform-specific background service architectures.
"""

from lifecycle.process_lab import (
    PidFileManager,
    get_process_info,
    is_pid_alive,
    spawn_worker,
)

__all__ = [
    "PidFileManager",
    "get_process_info",
    "is_pid_alive",
    "spawn_worker",
]
