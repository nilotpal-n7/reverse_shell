"""
Protocol Module
===============
Defines the JSON message format, wire framing, validation, and send/receive
operations for controller ↔ client communication.

Wire Format:
    ┌──────────────────────┬────────────────────────────┐
    │ 4 bytes (big-endian) │ UTF-8 JSON payload         │
    │   payload length     │ (up to 1 MB)               │
    └──────────────────────┴────────────────────────────┘

Message Schema:
    {
        "version":    "1.0",
        "type":       "<MessageType>",
        "timestamp":  "<ISO-8601 UTC>",
        "message_id": "<UUID4>",
        "payload":    { … }
    }

Dependencies: Python stdlib only (json, struct, uuid, socket, datetime, enum)

Usage:
    from core.protocol import send_message, recv_message, create_hello
    msg = create_hello(platform_info)
    send_message(tls_socket, msg)
    reply = recv_message(tls_socket)
"""

import json
import socket
import struct
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# ═══════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════

PROTOCOL_VERSION = "1.0"
MAX_MESSAGE_SIZE = 1_048_576  # 1 MB
HEADER_SIZE = 4  # 4-byte uint32 length prefix
RECV_TIMEOUT = 30.0  # Default receive timeout (seconds)


class MessageType(str, Enum):
    """All valid message types in the protocol.

    Auth flow:  HELLO → AUTH_CHALLENGE → AUTH_RESPONSE → AUTH_RESULT
    Operation:  STATUS_REPORT ↔ STATUS_ACK,  HEARTBEAT ↔ HEARTBEAT_ACK
    Control:    ERROR,  GOODBYE
    """

    HELLO = "HELLO"
    AUTH_CHALLENGE = "AUTH_CHALLENGE"
    AUTH_RESPONSE = "AUTH_RESPONSE"
    AUTH_RESULT = "AUTH_RESULT"
    STATUS_REPORT = "STATUS_REPORT"
    STATUS_ACK = "STATUS_ACK"
    HEARTBEAT = "HEARTBEAT"
    HEARTBEAT_ACK = "HEARTBEAT_ACK"
    ERROR = "ERROR"
    GOODBYE = "GOODBYE"


# Fields every message must contain
REQUIRED_FIELDS = frozenset({"version", "type", "timestamp", "message_id", "payload"})


# ═══════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ═══════════════════════════════════════════════════════════════


class ProtocolError(Exception):
    """Base exception for protocol-related errors."""


class MessageTooLarge(ProtocolError):
    """Serialized message exceeds MAX_MESSAGE_SIZE."""


class MalformedMessage(ProtocolError):
    """Message does not conform to the protocol schema."""


class ConnectionClosed(ProtocolError):
    """The remote end closed the connection."""


# ═══════════════════════════════════════════════════════════════
#  MESSAGE CONSTRUCTION
# ═══════════════════════════════════════════════════════════════


def create_message(
    msg_type: MessageType, payload: dict[str, Any], message_id: str | None = None
) -> dict[str, Any]:
    """Create a properly formatted protocol message.

    Args:
        msg_type:   MessageType enum value (or raw string)
        payload:    Message-specific payload dictionary
        message_id: Optional custom UUID (auto-generated if omitted)

    Returns:
        Complete message dict ready for send_message()
    """
    return {
        "version": PROTOCOL_VERSION,
        "type": msg_type.value if isinstance(msg_type, MessageType) else msg_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "message_id": message_id or str(uuid.uuid4()),
        "payload": payload,
    }


# ═══════════════════════════════════════════════════════════════
#  VALIDATION
# ═══════════════════════════════════════════════════════════════


def validate_message(msg: Any) -> tuple[bool, str | None]:
    """Validate a parsed message against the protocol schema.

    Returns:
        (True, None) on success, or (False, "<description>") on failure.
    """
    if not isinstance(msg, dict):
        return False, "Message must be a JSON object"

    missing = REQUIRED_FIELDS - set(msg.keys())
    if missing:
        return False, f"Missing required fields: {missing}"

    if msg["version"] != PROTOCOL_VERSION:
        return False, f"Unsupported protocol version: {msg['version']}"

    valid_types = {t.value for t in MessageType}
    if msg["type"] not in valid_types:
        return False, f"Unknown message type: {msg['type']}"

    if not isinstance(msg["payload"], dict):
        return False, "payload must be a JSON object"

    if not isinstance(msg["message_id"], str) or not msg["message_id"]:
        return False, "message_id must be a non-empty string"

    if not isinstance(msg["timestamp"], str) or not msg["timestamp"]:
        return False, "timestamp must be a non-empty string"

    return True, None


# ═══════════════════════════════════════════════════════════════
#  WIRE-LEVEL I/O
# ═══════════════════════════════════════════════════════════════


def send_message(sock: socket.socket, msg: dict[str, Any]) -> int:
    """Send a length-prefixed JSON message.

    Args:
        sock: Connected socket (plain or TLS-wrapped)
        msg:  Validated message dictionary

    Returns:
        Total bytes sent (header + payload)

    Raises:
        MalformedMessage, MessageTooLarge, ConnectionClosed
    """
    is_valid, error = validate_message(msg)
    if not is_valid:
        raise MalformedMessage(f"Cannot send invalid message: {error}")

    # Compact JSON (no unnecessary whitespace)
    payload_bytes = json.dumps(msg, separators=(",", ":")).encode("utf-8")

    if len(payload_bytes) > MAX_MESSAGE_SIZE:
        raise MessageTooLarge(f"Message size {len(payload_bytes)} exceeds limit {MAX_MESSAGE_SIZE}")

    header = struct.pack("!I", len(payload_bytes))

    try:
        sock.sendall(header + payload_bytes)
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        raise ConnectionClosed(f"Connection lost during send: {exc}") from exc

    return HEADER_SIZE + len(payload_bytes)


def recv_message(sock: socket.socket, timeout: float | None = RECV_TIMEOUT) -> dict[str, Any]:
    """Receive a length-prefixed JSON message.

    Args:
        sock:    Connected socket (plain or TLS-wrapped)
        timeout: Receive timeout in seconds (None = blocking)

    Returns:
        Parsed and validated message dictionary

    Raises:
        ConnectionClosed, MalformedMessage, MessageTooLarge, socket.timeout
    """
    saved_timeout = sock.gettimeout()
    try:
        if timeout is not None:
            sock.settimeout(timeout)

        # Read 4-byte length header
        header = _recv_exact(sock, HEADER_SIZE)
        payload_length = struct.unpack("!I", header)[0]

        if payload_length > MAX_MESSAGE_SIZE:
            raise MessageTooLarge(
                f"Declared size {payload_length} exceeds limit {MAX_MESSAGE_SIZE}"
            )
        if payload_length == 0:
            raise MalformedMessage("Empty message payload")

        # Read full payload
        payload_bytes = _recv_exact(sock, payload_length)

        # Decode & parse
        try:
            msg = json.loads(payload_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MalformedMessage(f"Invalid JSON payload: {exc}") from exc

        # Validate
        is_valid, error = validate_message(msg)
        if not is_valid:
            raise MalformedMessage(f"Validation failed: {error}")

        return msg

    finally:
        sock.settimeout(saved_timeout)


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Receive exactly *num_bytes*, handling partial reads.

    Raises ConnectionClosed if the peer disconnects mid-stream.
    """
    buf = bytearray()
    while len(buf) < num_bytes:
        try:
            chunk = sock.recv(num_bytes - len(buf))
        except (ConnectionResetError, OSError) as exc:
            raise ConnectionClosed(f"Connection lost during receive: {exc}") from exc
        if not chunk:
            raise ConnectionClosed(f"Connection closed after {len(buf)}/{num_bytes} bytes")
        buf.extend(chunk)
    return bytes(buf)


# ═══════════════════════════════════════════════════════════════
#  CONVENIENCE BUILDERS
# ═══════════════════════════════════════════════════════════════


def create_hello(platform_info: dict[str, Any]) -> dict[str, Any]:
    """HELLO — client sends its platform report."""
    return create_message(MessageType.HELLO, {"platform": platform_info})


def create_auth_challenge(nonce: str) -> dict[str, Any]:
    """AUTH_CHALLENGE — server sends a random nonce."""
    return create_message(
        MessageType.AUTH_CHALLENGE,
        {
            "nonce": nonce,
            "algorithm": "hmac-sha256",
        },
    )


def create_auth_response(nonce: str, token: str, client_id: str) -> dict[str, Any]:
    """AUTH_RESPONSE — client sends HMAC(nonce, psk)."""
    return create_message(
        MessageType.AUTH_RESPONSE,
        {
            "nonce": nonce,
            "token": token,
            "client_id": client_id,
        },
    )


def create_auth_result(
    success: bool, session_id: str | None = None, reason: str | None = None
) -> dict[str, Any]:
    """AUTH_RESULT — server accepts or rejects."""
    payload: dict[str, Any] = {"authenticated": success}
    if session_id:
        payload["session_id"] = session_id
    if reason:
        payload["reason"] = reason
    return create_message(MessageType.AUTH_RESULT, payload)


def create_status_report(status: dict[str, Any], session_id: str) -> dict[str, Any]:
    """STATUS_REPORT — client sends periodic system status."""
    return create_message(
        MessageType.STATUS_REPORT,
        {
            "session_id": session_id,
            "status": status,
        },
    )


def create_heartbeat() -> dict[str, Any]:
    """HEARTBEAT — server pings client."""
    return create_message(
        MessageType.HEARTBEAT,
        {
            "ping": datetime.now(UTC).isoformat(),
        },
    )


def create_heartbeat_ack(ping_timestamp: str) -> dict[str, Any]:
    """HEARTBEAT_ACK — client responds to ping."""
    return create_message(
        MessageType.HEARTBEAT_ACK,
        {
            "ping": ping_timestamp,
            "pong": datetime.now(UTC).isoformat(),
        },
    )


def create_error(
    error_code: str, description: str, reference_id: str | None = None
) -> dict[str, Any]:
    """ERROR — either side reports an error."""
    payload: dict[str, Any] = {
        "error_code": error_code,
        "description": description,
    }
    if reference_id:
        payload["reference_id"] = reference_id
    return create_message(MessageType.ERROR, payload)


def create_goodbye(reason: str = "normal") -> dict[str, Any]:
    """GOODBYE — graceful disconnect."""
    return create_message(MessageType.GOODBYE, {"reason": reason})


# ═══════════════════════════════════════════════════════════════
#  CLI DEMO
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Protocol Message Examples")
    print("=" * 60)

    examples = [
        ("HELLO", create_hello({"os": "linux", "arch": "x86_64"})),
        ("AUTH_CHALLENGE", create_auth_challenge("abc123nonce")),
        ("AUTH_RESPONSE", create_auth_response("abc123nonce", "hmac_tok", "c1")),
        ("AUTH_RESULT", create_auth_result(True, session_id="sess-001")),
        ("STATUS_REPORT", create_status_report({"uptime": 3600}, "sess-001")),
        ("HEARTBEAT", create_heartbeat()),
        ("ERROR", create_error("AUTH_FAILED", "Invalid credentials")),
        ("GOODBYE", create_goodbye("shutdown")),
    ]

    for name, msg in examples:
        print(f"\n{name}:")
        print(json.dumps(msg, indent=2))

    print("\n" + "=" * 60)
    print("Validation Tests:")

    good = create_hello({"os": "linux"})
    ok, err = validate_message(good)
    print(f"  Valid HELLO:  ok={ok}, error={err}")

    bad = {"type": "HELLO"}
    ok, err = validate_message(bad)
    print(f"  Invalid msg:  ok={ok}, error={err}")
