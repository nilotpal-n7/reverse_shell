"""
Tests for Protocol Module
=========================
Validates message formatting, schema validation, length prefixing, and socket framing.
"""

import socket
import threading
import unittest

from core.protocol import (
    MessageType,
    create_auth_challenge,
    create_auth_response,
    create_auth_result,
    create_error,
    create_goodbye,
    create_heartbeat,
    create_heartbeat_ack,
    create_hello,
    create_message,
    create_status_report,
    recv_message,
    send_message,
    validate_message,
)


class TestProtocol(unittest.TestCase):
    def test_message_creation_and_validation(self):
        msg = create_hello({"os": "linux", "arch": "x86_64"})
        self.assertEqual(msg["type"], MessageType.HELLO.value)
        self.assertEqual(msg["version"], "1.0")
        self.assertIn("message_id", msg)
        self.assertIn("timestamp", msg)

        is_valid, err = validate_message(msg)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_validation_rejects_missing_fields(self):
        bad_msg = {"type": "HELLO", "version": "1.0"}
        is_valid, err = validate_message(bad_msg)
        self.assertFalse(is_valid)
        self.assertIn("Missing required fields", err)

    def test_validation_rejects_unknown_type(self):
        msg = create_message("INVALID_TYPE", {"foo": "bar"})
        is_valid, err = validate_message(msg)
        self.assertFalse(is_valid)
        self.assertIn("Unknown message type", err)

    def test_convenience_builders(self):
        builders = [
            create_auth_challenge("nonce-1234"),
            create_auth_response("nonce-1234", "token-hash", "client-1"),
            create_auth_result(True, session_id="sess-999"),
            create_status_report({"cpu": 12.5}, session_id="sess-999"),
            create_heartbeat(),
            create_heartbeat_ack("2026-10-28T12:00:00Z"),
            create_error("ERR_AUTH", "Failed authentication"),
            create_goodbye("normal"),
        ]
        for msg in builders:
            is_valid, err = validate_message(msg)
            self.assertTrue(is_valid, f"Failed for {msg['type']}: {err}")

    def test_socket_send_recv_loopback(self):
        """Test wire-level sending and receiving over a local socket pair."""
        server_sock, client_sock = socket.socketpair()

        test_msg = create_hello({"os": "arch", "kernel": "6.18"})
        received_msg = None

        def receiver():
            nonlocal received_msg
            received_msg = recv_message(server_sock, timeout=5.0)

        t = threading.Thread(target=receiver)
        t.start()

        send_message(client_sock, test_msg)
        t.join(timeout=5.0)

        server_sock.close()
        client_sock.close()

        self.assertIsNotNone(received_msg)
        self.assertEqual(received_msg["type"], MessageType.HELLO.value)
        self.assertEqual(received_msg["payload"]["platform"]["os"], "arch")


if __name__ == "__main__":
    unittest.main()
