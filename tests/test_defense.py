"""
Tests for Defensive Security Modules
====================================
Validates network monitoring parsing, process anomaly inspection, and file forensics.
"""

import os
import tempfile
import unittest

from defense.file_forensics import (
    extract_ascii_strings,
    scan_file_forensics,
)
from defense.network_monitor import SocketConnection, inspect_active_connections
from defense.process_inspector import ProcessNode, inspect_processes


class TestDefense(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_file_forensics_trailing_overlay(self):
        """Test detection of overlay data appended beyond PNG EOF."""
        png_path = os.path.join(self.dir_path, "tampered.png")
        # Valid minimal PNG bytes + appended overlay
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        overlay = b"OVERLAY_PAYLOAD_DATA_123456789"
        with open(png_path, "wb") as f:
            f.write(png_1x1 + overlay)

        report = scan_file_forensics(png_path)
        self.assertTrue(report["has_overlay"])
        self.assertEqual(report["overlay_bytes_length"], len(overlay))
        self.assertGreater(report["suspicion_score"], 20)

    def test_file_forensics_extension_mismatch(self):
        """Test detection of shell script disguised as a JPG."""
        fake_jpg = os.path.join(self.dir_path, "photo.jpg")
        with open(fake_jpg, "wb") as f:
            f.write(b"#!/bin/bash\necho 'disguised executable'\n")

        report = scan_file_forensics(fake_jpg)
        self.assertGreater(report["suspicion_score"], 20)
        self.assertTrue(any("mismatch" in a.lower() for a in report["anomalies"]))

    def test_ascii_string_extraction(self):
        data = b"\x00\x01\x02HelloSecurityLabWorld\x00\xffhttp://127.0.0.1:4444\x00"
        strings = extract_ascii_strings(data, min_length=5)
        self.assertIn("HelloSecurityLabWorld", strings)
        self.assertIn("http://127.0.0.1:4444", strings)

    def test_network_monitor_inspection(self):
        conns = inspect_active_connections()
        self.assertIsInstance(conns, list)
        for c in conns:
            self.assertIsInstance(c, SocketConnection)
            self.assertIsInstance(c.proto, str)

    def test_process_inspector(self):
        procs = inspect_processes()
        self.assertIsInstance(procs, dict)
        current_pid = os.getpid()
        self.assertIn(current_pid, procs)
        self.assertIsInstance(procs[current_pid], ProcessNode)


if __name__ == "__main__":
    unittest.main()
