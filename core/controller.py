"""
Controller (Server)
===================
TCP server that accepts client connections over TLS, authenticates them
using HMAC-SHA256 challenge-response, and manages status-reporting sessions.

Features:
    - TLS-encrypted connections (TLS 1.2+)
    - HMAC-SHA256 challenge-response authentication with PSK
    - Concurrent client handling via threading
    - Periodic heartbeat monitoring
    - Structured logging to stdout
    - Graceful shutdown via Ctrl+C or GOODBYE

Architecture:
    Main Thread       — Accepts incoming TLS connections
    Per-Client Thread — Handles auth + message loop for one client
    Heartbeat Thread  — Sends periodic keep-alive pings to all clients

Usage:
    # 1. Generate certs and PSK (one-time setup):
    python -m core.crypto_utils --generate-certs --generate-psk

    # 2. Start the controller:
    python -m core.controller --host 127.0.0.1 --port 4444

    # 3. Stop:  Ctrl+C

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
    create_server_ssl_context,
    generate_nonce,
    load_psk,
    verify_auth_token,
)
from core.protocol import (
    ConnectionClosed,
    MalformedMessage,
    MessageType,
    create_auth_challenge,
    create_auth_result,
    create_error,
    create_goodbye,
    create_heartbeat,
    create_message,
    recv_message,
    send_message,
)

# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════

DEFAULT_HOST = os.environ.get("LAB_CONTROLLER_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("LAB_CONTROLLER_PORT", "4444"))
HEARTBEAT_INTERVAL = int(
    os.environ.get("LAB_HEARTBEAT_INTERVAL", "60")
)  # seconds between heartbeats
AUTH_TIMEOUT = 15  # seconds to complete authentication
CLIENT_TIMEOUT = 120  # seconds of silence → consider dead


# ═══════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure the controller logger."""
    logger = logging.getLogger("controller")
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
#  CLIENT SESSION
# ═══════════════════════════════════════════════════════════════


class ClientSession:
    """Represents one authenticated client connection.

    Attributes:
        conn:           TLS-wrapped socket
        addr:           (ip, port) tuple
        client_id:      Self-reported client identifier
        session_id:     Server-assigned session UUID fragment
        platform_info:  Client's platform report dict
        status_reports: List of received status reports
    """

    def __init__(
        self,
        conn: ssl.SSLSocket,
        addr: tuple,
        client_id: str,
        session_id: str,
        platform_info: dict[str, Any],
    ):
        self.conn = conn
        self.addr = addr
        self.client_id = client_id
        self.session_id = session_id
        self.platform_info = platform_info
        self.authenticated = True
        self.connected_at = datetime.now(UTC)
        self.last_seen = self.connected_at
        self.status_reports: list = []

    def update_last_seen(self) -> None:
        self.last_seen = datetime.now(UTC)

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serializable summary of this session."""
        os_info = self.platform_info.get("os", {})
        arch_info = self.platform_info.get("architecture", {})
        rt_info = self.platform_info.get("runtime", {})
        return {
            "client_id": self.client_id,
            "session_id": self.session_id,
            "address": f"{self.addr[0]}:{self.addr[1]}",
            "os": os_info.get("os_name", "unknown"),
            "arch": arch_info.get("architecture", "unknown"),
            "runtime": rt_info.get("environment", "unknown"),
            "connected_at": self.connected_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "reports": len(self.status_reports),
        }


# ═══════════════════════════════════════════════════════════════
#  CONTROLLER
# ═══════════════════════════════════════════════════════════════


class Controller:
    """Main controller server.

    Lifecycle::

        ctrl = Controller(host="127.0.0.1", port=4444)
        ctrl.start()          # blocks until Ctrl+C or ctrl.stop()
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        cert_dir: Path | None = None,
        psk: str | None = None,
    ):
        self.host = host
        self.port = port
        self.cert_dir = (cert_dir or DEFAULT_CERT_DIR).resolve()
        self.psk = psk

        self.logger = setup_logging()
        self.sessions: dict[str, ClientSession] = {}
        self._lock = threading.Lock()
        self._running = False
        self._server_socket: socket.socket | None = None

    # ─── Public ──────────────────────────────────────────────

    def start(self) -> None:
        """Bind, listen, and accept clients.  Blocks until stopped."""
        self._load_credentials()
        ssl_ctx = self._create_tls_context()

        # Bind server socket
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        try:
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(5)
        except OSError as exc:
            self.logger.error("Cannot bind to %s:%d — %s", self.host, self.port, exc)
            sys.exit(1)

        self._running = True
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info("=" * 56)
        self.logger.info("  Controller listening on %s:%d  (TLS 1.2+)", self.host, self.port)
        self.logger.info("  Cert dir:  %s", self.cert_dir)
        self.logger.info("  Press Ctrl+C to stop")
        self.logger.info("=" * 56)

        # Start heartbeat daemon
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

        # Accept loop
        self._accept_loop(ssl_ctx)
        self._cleanup()

    def stop(self) -> None:
        """Signal the controller to shut down."""
        self.logger.info("Shutdown requested …")
        self._running = False

    def list_clients(self) -> list:
        """Return summaries of all connected clients."""
        with self._lock:
            return [s.summary() for s in self.sessions.values()]

    # ─── Accept Loop ─────────────────────────────────────────

    def _accept_loop(self, ssl_ctx: ssl.SSLContext) -> None:
        while self._running:
            try:
                raw_conn, addr = self._server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._running:
                    self.logger.error("Socket error in accept loop")
                break

            self.logger.info("Connection from %s:%d", *addr)

            try:
                tls_conn = ssl_ctx.wrap_socket(raw_conn, server_side=True)
                self.logger.info(
                    "TLS handshake OK  %s:%d  (protocol %s)",
                    addr[0],
                    addr[1],
                    tls_conn.version(),
                )
            except ssl.SSLError as exc:
                self.logger.warning("TLS handshake FAILED  %s:%d — %s", *addr, exc)
                raw_conn.close()
                continue

            threading.Thread(
                target=self._handle_client,
                args=(tls_conn, addr),
                daemon=True,
            ).start()

    # ─── Per-Client Handler ──────────────────────────────────

    def _handle_client(self, conn: ssl.SSLSocket, addr: tuple) -> None:
        """Handle one client: authenticate, then enter the message loop.

        Authentication Flow:
            1. Client → HELLO  (with platform_info)
            2. Server → AUTH_CHALLENGE  (random nonce)
            3. Client → AUTH_RESPONSE   (HMAC-SHA256 of nonce)
            4. Server → AUTH_RESULT     (success / failure)
        """
        session: ClientSession | None = None

        try:
            # ── Step 1: Receive HELLO ──
            conn.settimeout(AUTH_TIMEOUT)
            msg = recv_message(conn, timeout=AUTH_TIMEOUT)

            if msg["type"] != MessageType.HELLO.value:
                self.logger.warning("%s:%d  expected HELLO, got %s", *addr, msg["type"])
                send_message(conn, create_error("PROTOCOL", "Expected HELLO"))
                return

            platform_info = msg["payload"].get("platform", {})
            os_name = platform_info.get("os", {}).get("os_name", "?")
            arch = platform_info.get("architecture", {}).get("architecture", "?")
            self.logger.info("%s:%d  HELLO  OS=%s  arch=%s", *addr, os_name, arch)

            # ── Step 2: Send AUTH_CHALLENGE ──
            nonce = generate_nonce()
            send_message(conn, create_auth_challenge(nonce))

            # ── Step 3: Receive AUTH_RESPONSE ──
            msg = recv_message(conn, timeout=AUTH_TIMEOUT)
            if msg["type"] != MessageType.AUTH_RESPONSE.value:
                self.logger.warning("%s:%d  expected AUTH_RESPONSE, got %s", *addr, msg["type"])
                send_message(conn, create_error("PROTOCOL", "Expected AUTH_RESPONSE"))
                return

            token = msg["payload"].get("token", "")
            client_id = msg["payload"].get("client_id", f"anon-{addr[0]}")

            # ── Step 4: Validate ──
            if not verify_auth_token(nonce, self.psk, token):
                self.logger.warning("%s:%d  AUTH FAILED for '%s'", *addr, client_id)
                send_message(conn, create_auth_result(False, reason="Invalid credentials"))
                return

            session_id = uuid.uuid4().hex[:8]
            session = ClientSession(conn, addr, client_id, session_id, platform_info)

            with self._lock:
                self.sessions[session_id] = session

            send_message(conn, create_auth_result(True, session_id=session_id))
            self.logger.info(
                "\u2713 Authenticated  client='%s'  session=%s  addr=%s:%d",
                client_id,
                session_id,
                *addr,
            )

            # ── Step 5: Message loop ──
            conn.settimeout(CLIENT_TIMEOUT)
            self._message_loop(session)

        except ConnectionClosed as exc:
            self.logger.info("%s:%d  connection closed: %s", *addr, exc)
        except MalformedMessage as exc:
            self.logger.warning("%s:%d  malformed: %s", *addr, exc)
            try:
                send_message(conn, create_error("MALFORMED", str(exc)))
            except Exception:
                pass
        except TimeoutError:
            self.logger.warning("%s:%d  auth timed out", *addr)
        except Exception as exc:
            self.logger.error("%s:%d  unexpected: %s", *addr, exc, exc_info=True)
        finally:
            if session:
                with self._lock:
                    self.sessions.pop(session.session_id, None)
                self.logger.info(
                    "Disconnected  client='%s'  session=%s",
                    session.client_id,
                    session.session_id,
                )
            try:
                conn.close()
            except Exception:
                pass

    # ─── Message Loop ────────────────────────────────────────

    def _message_loop(self, session: ClientSession) -> None:
        """Process messages from an authenticated client until disconnect."""
        while self._running and session.authenticated:
            try:
                msg = recv_message(session.conn, timeout=CLIENT_TIMEOUT)
                session.update_last_seen()
                mt = msg["type"]

                if mt == MessageType.STATUS_REPORT.value:
                    status = msg["payload"].get("status", {})
                    session.status_reports.append(
                        {
                            "timestamp": msg["timestamp"],
                            "status": status,
                        }
                    )
                    self.logger.info(
                        "[%s] Status report #%d from '%s'",
                        session.session_id,
                        len(session.status_reports),
                        session.client_id,
                    )
                    ack = create_message(
                        MessageType.STATUS_ACK,
                        {
                            "session_id": session.session_id,
                            "report_number": len(session.status_reports),
                            "received": True,
                        },
                    )
                    send_message(session.conn, ack)

                elif mt == MessageType.HEARTBEAT_ACK.value:
                    self.logger.debug("[%s] heartbeat ACK", session.session_id)

                elif mt == MessageType.GOODBYE.value:
                    reason = msg["payload"].get("reason", "normal")
                    self.logger.info(
                        "[%s] GOODBYE from '%s': %s",
                        session.session_id,
                        session.client_id,
                        reason,
                    )
                    send_message(session.conn, create_goodbye("acknowledged"))
                    session.authenticated = False

                elif mt == MessageType.ERROR.value:
                    self.logger.warning(
                        "[%s] Client error: %s",
                        session.session_id,
                        msg["payload"].get("description", "?"),
                    )

                else:
                    self.logger.warning("[%s] unexpected type: %s", session.session_id, mt)
                    send_message(
                        session.conn,
                        create_error(
                            "UNEXPECTED",
                            f"Unexpected message type: {mt}",
                        ),
                    )

            except TimeoutError:
                self.logger.warning(
                    "[%s] '%s' timed out (%ds)",
                    session.session_id,
                    session.client_id,
                    CLIENT_TIMEOUT,
                )
                break
            except ConnectionClosed:
                break
            except MalformedMessage as exc:
                self.logger.warning("[%s] malformed: %s", session.session_id, exc)
                try:
                    send_message(session.conn, create_error("MALFORMED", str(exc)))
                except Exception:
                    break

    # ─── Heartbeat ───────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """Periodically ping every connected client."""
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            with self._lock:
                sessions = list(self.sessions.values())
            for s in sessions:
                try:
                    send_message(s.conn, create_heartbeat())
                except Exception:
                    self.logger.warning(
                        "[%s] heartbeat send failed for '%s'",
                        s.session_id,
                        s.client_id,
                    )

    # ─── Internals ───────────────────────────────────────────

    def _load_credentials(self) -> None:
        if not self.psk:
            try:
                self.psk = load_psk(self.cert_dir / "psk.key")
                self.logger.info("Loaded PSK from %s", self.cert_dir / "psk.key")
            except FileNotFoundError as exc:
                self.logger.error(str(exc))
                sys.exit(1)

    def _create_tls_context(self) -> ssl.SSLContext:
        try:
            ctx = create_server_ssl_context(self.cert_dir)
            self.logger.info("TLS context ready (TLS 1.2+)")
            return ctx
        except Exception as exc:
            self.logger.error("TLS context failed: %s", exc)
            self.logger.error("Run:  python -m core.crypto_utils --generate-certs")
            sys.exit(1)

    def _signal_handler(self, signum, _frame) -> None:
        self.stop()

    def _cleanup(self) -> None:
        self.logger.info("Shutting down …")
        with self._lock:
            for s in self.sessions.values():
                try:
                    send_message(s.conn, create_goodbye("server_shutdown"))
                    s.conn.close()
                except Exception:
                    pass
            self.sessions.clear()
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        self.logger.info("Controller stopped.")


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Security Lab Controller — TLS status-reporting server",
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST})"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"Bind port (default: {DEFAULT_PORT})"
    )
    parser.add_argument("--cert-dir", type=Path, default=None, help="Certificate directory")
    parser.add_argument("--psk", default=None, help="Pre-shared key (overrides file)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    if args.debug:
        setup_logging(logging.DEBUG)

    Controller(
        host=args.host,
        port=args.port,
        cert_dir=args.cert_dir,
        psk=args.psk,
    ).start()
