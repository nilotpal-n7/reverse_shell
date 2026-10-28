"""
Status-Reporting Client
=======================
Connects to the controller over TLS, authenticates with HMAC-SHA256,
and periodically sends harmless status reports containing platform info.

Features:
    - TLS-encrypted connection to the controller
    - HMAC-SHA256 challenge-response authentication
    - Automatic platform detection (OS, arch, runtime, capabilities)
    - Periodic status updates (configurable interval)
    - Heartbeat response
    - Graceful disconnect via Ctrl+C

Architecture:
    Main Thread    — Receives messages (heartbeat, ack, goodbye)
    Status Thread  — Sends periodic status reports

Usage:
    python -m core.client --host 127.0.0.1 --port 4444
    python -m core.client --host 127.0.0.1 --port 4444 --interval 10 --debug

Dependencies: Python stdlib only
"""

import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.crypto_utils import (
    DEFAULT_CERT_DIR,
    compute_auth_token,
    create_client_ssl_context,
    load_psk,
)
from core.platform_detect import get_full_platform_report
from core.protocol import (
    ConnectionClosed,
    MalformedMessage,
    MessageType,
    create_auth_response,
    create_goodbye,
    create_heartbeat_ack,
    create_hello,
    create_status_report,
    recv_message,
    send_message,
)

# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════

DEFAULT_HOST = os.environ.get("LAB_CLIENT_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("LAB_CLIENT_PORT", "4444"))
STATUS_INTERVAL = int(os.environ.get("LAB_STATUS_INTERVAL", "30"))  # seconds between status reports
RECONNECT_DELAY = 5  # not used in v1, reserved for future auto-reconnect


# ═══════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("client")
    logger.setLevel(level)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(h)
    return logger


# ═══════════════════════════════════════════════════════════════
#  STATUS CLIENT
# ═══════════════════════════════════════════════════════════════


class StatusClient:
    """Connects to the controller, authenticates, and reports status.

    Lifecycle::

        client = StatusClient(host="127.0.0.1", port=4444)
        if client.connect():
            client.run()      # blocks until Ctrl+C
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        cert_dir: Path | None = None,
        psk: str | None = None,
        client_id: str | None = None,
        status_interval: int = STATUS_INTERVAL,
    ):
        self.host = host
        self.port = port
        self.cert_dir = (cert_dir or DEFAULT_CERT_DIR).resolve()
        self.psk = psk
        self.client_id = client_id or f"client-{uuid.uuid4().hex[:8]}"
        self.status_interval = status_interval

        self.logger = setup_logging()
        self.conn: ssl.SSLSocket | None = None
        self.session_id: str | None = None
        self._running = False
        self._platform_report: dict | None = None

    # ─── Public API ──────────────────────────────────────────

    def connect(self) -> bool:
        """Connect to the controller, perform TLS + auth handshake.

        Returns True on success.
        """
        # Load PSK
        if not self.psk:
            try:
                self.psk = load_psk(self.cert_dir / "psk.key")
            except FileNotFoundError as exc:
                self.logger.error(str(exc))
                return False

        # TLS context
        try:
            ssl_ctx = create_client_ssl_context(self.cert_dir)
        except Exception as exc:
            self.logger.error("TLS context failed: %s", exc)
            return False

        # TCP + TLS connect
        self.logger.info("Connecting to %s:%d …", self.host, self.port)
        try:
            raw = socket.create_connection((self.host, self.port), timeout=10)
            self.conn = ssl_ctx.wrap_socket(raw, server_hostname=self.host)
            self.logger.info("TLS established  (protocol %s)", self.conn.version())
        except ConnectionRefusedError:
            self.logger.error(
                "Connection refused — is the controller running on %s:%d?",
                self.host,
                self.port,
            )
            return False
        except ssl.SSLCertVerificationError as exc:
            self.logger.error("Certificate verification failed: %s", exc)
            return False
        except TimeoutError:
            self.logger.error("Connection timed out")
            return False
        except OSError as exc:
            self.logger.error("Connection failed: %s", exc)
            return False

        # Authenticate
        try:
            return self._authenticate()
        except Exception as exc:
            self.logger.error("Authentication error: %s", exc)
            self._close()
            return False

    def run(self) -> None:
        """Enter the main loop: send status, respond to heartbeats.

        Blocks until Ctrl+C or server disconnect.
        """
        if not self.conn or not self.session_id:
            self.logger.error("Not connected — call connect() first")
            return

        self._running = True
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info("=" * 56)
        self.logger.info("  Client '%s' running  (session %s)", self.client_id, self.session_id)
        self.logger.info("  Status interval: %ds", self.status_interval)
        self.logger.info("  Press Ctrl+C to disconnect")
        self.logger.info("=" * 56)

        # Start status-report thread
        threading.Thread(target=self._status_loop, daemon=True).start()

        # Main receive loop
        self._receive_loop()
        self.disconnect()

    def disconnect(self) -> None:
        """Gracefully disconnect from the controller."""
        if not self._running and not self.conn:
            return

        self._running = False

        if self.conn:
            try:
                send_message(self.conn, create_goodbye("client_shutdown"))
                self.logger.info("GOODBYE sent")
                # Wait briefly for acknowledgment
                try:
                    self.conn.settimeout(3)
                    msg = recv_message(self.conn, timeout=3)
                    if msg["type"] == MessageType.GOODBYE.value:
                        self.logger.info("Server acknowledged disconnect")
                except Exception:
                    pass
            except Exception:
                pass
            self._close()

        self.logger.info("Client stopped.")

    # ─── Authentication ──────────────────────────────────────

    def _authenticate(self) -> bool:
        """Execute the HELLO → CHALLENGE → RESPONSE → RESULT flow."""
        # 1. Send HELLO
        self._platform_report = get_full_platform_report()
        send_message(self.conn, create_hello(self._platform_report))
        self.logger.info(
            "HELLO sent  (OS=%s  arch=%s  runtime=%s)",
            self._platform_report.get("os", {}).get("os_name", "?"),
            self._platform_report.get("architecture", {}).get("architecture", "?"),
            self._platform_report.get("runtime", {}).get("environment", "?"),
        )

        # 2. Receive AUTH_CHALLENGE
        msg = recv_message(self.conn, timeout=15)
        if msg["type"] == MessageType.ERROR.value:
            self.logger.error("Server error: %s", msg["payload"].get("description"))
            return False
        if msg["type"] != MessageType.AUTH_CHALLENGE.value:
            self.logger.error("Expected AUTH_CHALLENGE, got %s", msg["type"])
            return False

        nonce = msg["payload"].get("nonce", "")
        self.logger.debug("Challenge received (nonce %s…)", nonce[:16])

        # 3. Send AUTH_RESPONSE
        token = compute_auth_token(nonce, self.psk)
        send_message(self.conn, create_auth_response(nonce, token, self.client_id))

        # 4. Receive AUTH_RESULT
        msg = recv_message(self.conn, timeout=15)
        if msg["type"] != MessageType.AUTH_RESULT.value:
            self.logger.error("Expected AUTH_RESULT, got %s", msg["type"])
            return False

        if msg["payload"].get("authenticated"):
            self.session_id = msg["payload"].get("session_id")
            self.logger.info("\u2713 Authenticated!  session=%s", self.session_id)
            return True
        else:
            reason = msg["payload"].get("reason", "unknown")
            self.logger.error("\u2717 Authentication failed: %s", reason)
            return False

    # ─── Receive Loop ────────────────────────────────────────

    def _receive_loop(self) -> None:
        """Process incoming messages until disconnect."""
        while self._running:
            try:
                self.conn.settimeout(self.status_interval + 60)
                msg = recv_message(self.conn)
                mt = msg["type"]

                if mt == MessageType.HEARTBEAT.value:
                    ping = msg["payload"].get("ping", "")
                    send_message(self.conn, create_heartbeat_ack(ping))
                    self.logger.debug("Heartbeat ACK sent")

                elif mt == MessageType.STATUS_ACK.value:
                    rn = msg["payload"].get("report_number", "?")
                    self.logger.info("Status report #%s acknowledged", rn)

                elif mt == MessageType.GOODBYE.value:
                    reason = msg["payload"].get("reason", "?")
                    self.logger.info("Server GOODBYE: %s", reason)
                    self._running = False

                elif mt == MessageType.ERROR.value:
                    self.logger.warning("Server error: %s", msg["payload"].get("description", "?"))

                else:
                    self.logger.debug("Received %s", mt)

            except TimeoutError:
                continue
            except ConnectionClosed:
                self.logger.warning("Connection closed by server")
                self._running = False
            except MalformedMessage as exc:
                self.logger.warning("Malformed from server: %s", exc)

    # ─── Status Reporting ────────────────────────────────────

    def _status_loop(self) -> None:
        """Periodically send status reports."""
        count = 0
        while self._running:
            time.sleep(self.status_interval)
            if not self._running:
                break
            try:
                count += 1
                status = self._collect_status()
                send_message(
                    self.conn,
                    create_status_report(status, self.session_id),
                )
                self.logger.info("Status report #%d sent", count)
            except ConnectionClosed:
                self.logger.warning("Connection lost during status send")
                self._running = False
            except Exception as exc:
                self.logger.error("Status send failed: %s", exc)

    def _collect_status(self) -> dict[str, Any]:
        """Collect current status (benign, non-sensitive data only)."""
        status: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "uptime_seconds": round(time.monotonic(), 1),
            "pid": os.getpid(),
            "client_id": self.client_id,
        }

        # Load average (Unix only — not available on Windows)
        try:
            la = os.getloadavg()
            status["load_average"] = {"1m": la[0], "5m": la[1], "15m": la[2]}
        except (OSError, AttributeError):
            pass

        return status

    # ─── Helpers ─────────────────────────────────────────────

    def _signal_handler(self, _signum, _frame) -> None:
        self._running = False

    def _close(self) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Security Lab Client — TLS status reporter",
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST, help=f"Controller address (default: {DEFAULT_HOST})"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"Controller port (default: {DEFAULT_PORT})"
    )
    parser.add_argument("--cert-dir", type=Path, default=None, help="Certificate directory")
    parser.add_argument("--psk", default=None, help="Pre-shared key (overrides file)")
    parser.add_argument("--client-id", default=None, help="Client ID (auto-generated if omitted)")
    parser.add_argument(
        "--interval",
        type=int,
        default=STATUS_INTERVAL,
        help=f"Status interval in seconds (default: {STATUS_INTERVAL})",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    if args.debug:
        setup_logging(logging.DEBUG)

    client = StatusClient(
        host=args.host,
        port=args.port,
        cert_dir=args.cert_dir,
        psk=args.psk,
        client_id=args.client_id,
        status_interval=args.interval,
    )

    if client.connect():
        client.run()
    else:
        sys.exit(1)
