"""
Tests for Process Lifecycle Module
==================================
Validates process introspection, PID liveness checks, and PID file tracking.
"""

import os
import tempfile
import unittest

from lifecycle.process_lab import (
    PidFileManager,
    get_process_info,
    is_pid_alive,
)


class TestProcessLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_process_info_current(self):
        info = get_process_info()
        self.assertIsInstance(info, dict)
        self.assertEqual(info["pid"], os.getpid())
        self.assertTrue(info["is_current"])
        self.assertIn("platform", info)

    def test_is_pid_alive(self):
        # Current process is definitely alive
        self.assertTrue(is_pid_alive(os.getpid()))

        # Non-existent PID
        self.assertFalse(is_pid_alive(-1))
        self.assertFalse(is_pid_alive(0))
        self.assertFalse(is_pid_alive(999999999))

    def test_pid_file_lifecycle(self):
        pid_path = os.path.join(self.dir_path, "service.pid")
        manager = PidFileManager(pid_path)

        # Before writing
        self.assertIsNone(manager.read())
        self.assertFalse(manager.is_running())

        # Write current PID
        manager.write(metadata={"service": "unit_test"})
        self.assertTrue(os.path.exists(pid_path))

        # Read back
        data = manager.read()
        self.assertIsNotNone(data)
        self.assertEqual(data["pid"], os.getpid())
        self.assertEqual(data["metadata"]["service"], "unit_test")
        self.assertTrue(manager.is_running())

        # Cleanup
        manager.remove()
        self.assertFalse(os.path.exists(pid_path))


if __name__ == "__main__":
    unittest.main()
