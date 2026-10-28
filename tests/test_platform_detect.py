"""
Tests for Platform Detection Module
====================================
Validates OS identification, capability probing, and runtime environment discovery.
"""

import json
import unittest

from core.platform_detect import (
    detect_architecture,
    detect_capabilities,
    detect_os,
    detect_runtime,
    get_full_platform_report,
)


class TestPlatformDetect(unittest.TestCase):
    def test_detect_os(self):
        info = detect_os()
        self.assertIsInstance(info, dict)
        self.assertIn("os_family", info)
        self.assertIn("os_name", info)
        self.assertIn("os_release", info)
        self.assertTrue(len(info["os_family"]) > 0)

    def test_detect_architecture(self):
        arch = detect_architecture()
        self.assertIsInstance(arch, dict)
        self.assertIn("machine", arch)
        self.assertIn("architecture", arch)
        self.assertIn("bits", arch)

    def test_detect_runtime(self):
        runtime = detect_runtime()
        self.assertIsInstance(runtime, dict)
        self.assertIn("environment", runtime)
        self.assertIn("python_version", runtime)
        self.assertIn(
            runtime["environment"], ("native", "wsl2", "wsl1", "termux", "container", "ssh")
        )

    def test_detect_capabilities(self):
        caps = detect_capabilities()
        self.assertIsInstance(caps, dict)
        # python3/python should be probed
        self.assertIn("python3", caps)

    def test_get_full_platform_report(self):
        report = get_full_platform_report()
        self.assertIsInstance(report, dict)
        self.assertIn("os", report)
        self.assertIn("architecture", report)
        self.assertIn("runtime", report)
        self.assertIn("capabilities", report)

        # Must be strictly JSON serializable
        serialized = json.dumps(report)
        self.assertTrue(len(serialized) > 0)


if __name__ == "__main__":
    unittest.main()
