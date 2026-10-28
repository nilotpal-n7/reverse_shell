"""
Defense Package
===============
Defensive security tools for network connection monitoring, process
hierarchy and anomaly inspection, file forensics, and packet capture analysis.
"""

from defense.file_forensics import FileForensicScanner, scan_file_forensics
from defense.network_monitor import NetworkMonitor, inspect_active_connections
from defense.process_inspector import ProcessInspector, inspect_processes

__all__ = [
    "FileForensicScanner",
    "NetworkMonitor",
    "ProcessInspector",
    "inspect_active_connections",
    "inspect_processes",
    "scan_file_forensics",
]
