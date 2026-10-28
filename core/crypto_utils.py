"""
Cryptographic Utilities
=======================
TLS certificate management, SSL context creation, and HMAC-SHA256
token authentication for the controller ↔ client protocol.

Certificate Generation:
    Uses the ``openssl`` CLI to create a self-signed CA, server certificate,
    and client certificate.  This avoids adding the ``cryptography`` library
    as a dependency.

Authentication:
    Uses HMAC-SHA256 with a pre-shared key (PSK) for the challenge-response
    authentication flow.

Dependencies:
    Python stdlib:  ssl, hmac, hashlib, secrets, subprocess, shutil
    External:       openssl CLI (for certificate generation only)

Usage:
    # Generate certs + PSK
    python -m core.crypto_utils --generate-certs --generate-psk

    # Check status
    python -m core.crypto_utils
"""

import hashlib
import hmac
import os
import secrets
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
#  PATH CONSTANTS
# ═══════════════════════════════════════════════════════════════

DEFAULT_CERT_DIR = Path(__file__).resolve().parent.parent / "certs"

CA_CERT = "ca.pem"
CA_KEY = "ca.key"
SERVER_CERT = "server.pem"
SERVER_KEY = "server.key"
CLIENT_CERT = "client.pem"
CLIENT_KEY = "client.key"
PSK_FILE = "psk.key"


# ═══════════════════════════════════════════════════════════════
#  OPENSSL HELPERS
# ═══════════════════════════════════════════════════════════════


def check_openssl() -> tuple[bool, str | None]:
    """Check whether the ``openssl`` CLI is available.

    Returns:
        (available, version_string)
    """
    path = shutil.which("openssl")
    if not path:
        return False, None
    try:
        result = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return True, result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return False, None


def _run_openssl(args: list) -> subprocess.CompletedProcess:
    """Run an ``openssl`` sub-command and raise on failure."""
    result = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            "openssl",
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


# ═══════════════════════════════════════════════════════════════
#  CERTIFICATE GENERATION
# ═══════════════════════════════════════════════════════════════


def generate_certificates(
    cert_dir: Path | None = None, hostname: str = "localhost", days: int = 365
) -> Path:
    """Generate a self-signed CA, server cert, and client cert.

    Creates six files in *cert_dir*::

        ca.key   / ca.pem       — Certificate Authority
        server.key / server.pem — Server cert (signed by CA)
        client.key / client.pem — Client cert (signed by CA)

    Args:
        cert_dir:  Output directory (created if needed)
        hostname:  Server hostname for CN and SAN
        days:      Certificate validity period

    Returns:
        Resolved path to *cert_dir*

    Raises:
        FileNotFoundError:  if ``openssl`` is not installed
        CalledProcessError: if any openssl command fails
    """
    available, version = check_openssl()
    if not available:
        raise FileNotFoundError(
            "openssl CLI is required for certificate generation.\n"
            "Install it with:\n"
            "  Arch Linux:     sudo pacman -S openssl\n"
            "  Debian/Ubuntu:  sudo apt install openssl\n"
            "  Windows:        choco install openssl  (or download from slproweb.com)\n"
        )

    cert_dir = (cert_dir or DEFAULT_CERT_DIR).resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)

    print(f"[crypto] Using {version}")
    print(f"[crypto] Output directory: {cert_dir}")

    # ── 1. Certificate Authority ──
    print("[crypto] 1/3  Creating Certificate Authority …")
    _run_openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-sha256",
            "-days",
            str(days),
            "-nodes",
            "-keyout",
            str(cert_dir / CA_KEY),
            "-out",
            str(cert_dir / CA_CERT),
            "-subj",
            "/CN=SecurityLab CA/O=Security Lab/OU=Education",
        ]
    )

    # ── 2. Server certificate ──
    print("[crypto] 2/3  Creating server certificate …")
    _generate_signed_cert(
        cert_dir,
        "server",
        hostname,
        days,
        subject=f"/CN={hostname}/O=Security Lab/OU=Server",
    )

    # ── 3. Client certificate ──
    print("[crypto] 3/3  Creating client certificate …")
    _generate_signed_cert(
        cert_dir,
        "client",
        hostname,
        days,
        subject="/CN=client/O=Security Lab/OU=Client",
    )

    # Restrict private-key permissions on Unix
    if sys.platform != "win32":
        for name in (CA_KEY, SERVER_KEY, CLIENT_KEY):
            key_path = cert_dir / name
            if key_path.exists():
                os.chmod(key_path, 0o600)

    print("[crypto] Certificate generation complete!")
    print(f"[crypto]   CA cert:     {cert_dir / CA_CERT}")
    print(f"[crypto]   Server cert: {cert_dir / SERVER_CERT}")
    print(f"[crypto]   Client cert: {cert_dir / CLIENT_CERT}")
    return cert_dir


def _generate_signed_cert(
    cert_dir: Path, name: str, hostname: str, days: int, subject: str
) -> None:
    """Generate a key + CSR, sign with the CA, clean up temporaries."""
    key_path = cert_dir / f"{name}.key"
    csr_path = cert_dir / f"{name}.csr"
    cert_path = cert_dir / f"{name}.pem"
    ext_path = cert_dir / f"{name}_ext.cnf"

    # SAN extension config (required for modern TLS clients)
    ext_path.write_text(
        f"[v3_ext]\nsubjectAltName = DNS:{hostname},DNS:localhost,IP:127.0.0.1,IP:::1\n"
    )

    # Generate private key + CSR
    _run_openssl(
        [
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(csr_path),
            "-subj",
            subject,
            "-addext",
            f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1",
        ]
    )

    # Sign with CA
    _run_openssl(
        [
            "x509",
            "-req",
            "-in",
            str(csr_path),
            "-CA",
            str(cert_dir / CA_CERT),
            "-CAkey",
            str(cert_dir / CA_KEY),
            "-CAcreateserial",
            "-out",
            str(cert_path),
            "-days",
            str(days),
            "-sha256",
            "-extfile",
            str(ext_path),
            "-extensions",
            "v3_ext",
        ]
    )

    # Remove temporaries
    for tmp in (csr_path, ext_path, cert_dir / "ca.srl"):
        tmp.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════
#  TLS CONTEXT CREATION
# ═══════════════════════════════════════════════════════════════


def create_server_ssl_context(cert_dir: Path | None = None) -> ssl.SSLContext:
    """Create a TLS context for the controller (server side).

    - Enforces TLS 1.2+
    - Loads server certificate and private key
    - Loads CA cert for optional mutual-TLS client verification
    - Client certificates are **not** required by default
      (token auth is used instead)
    """
    cert_dir = (cert_dir or DEFAULT_CERT_DIR).resolve()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(
        certfile=str(cert_dir / SERVER_CERT),
        keyfile=str(cert_dir / SERVER_KEY),
    )
    ctx.load_verify_locations(cafile=str(cert_dir / CA_CERT))
    ctx.verify_mode = ssl.CERT_NONE  # Token auth; set CERT_REQUIRED for mTLS
    return ctx


def create_client_ssl_context(cert_dir: Path | None = None) -> ssl.SSLContext:
    """Create a TLS context for the client.

    - Enforces TLS 1.2+
    - Verifies the server certificate against the CA
    - Optionally loads a client certificate for mutual TLS
    """
    cert_dir = (cert_dir or DEFAULT_CERT_DIR).resolve()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(cert_dir / CA_CERT))

    # Load client cert if available (for mutual TLS)
    client_cert = cert_dir / CLIENT_CERT
    client_key = cert_dir / CLIENT_KEY
    if client_cert.exists() and client_key.exists():
        ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))

    return ctx


# ═══════════════════════════════════════════════════════════════
#  HMAC-SHA256 TOKEN AUTHENTICATION
# ═══════════════════════════════════════════════════════════════


def generate_psk(length: int = 32) -> str:
    """Generate a cryptographically secure pre-shared key (hex).

    Default 32 bytes = 256-bit key strength.
    """
    return secrets.token_hex(length)


def generate_nonce(length: int = 32) -> str:
    """Generate a random nonce for auth challenges (hex)."""
    return secrets.token_hex(length)


def compute_auth_token(nonce: str, psk: str) -> str:
    """Compute HMAC-SHA256(nonce, psk) → hex digest."""
    return hmac.new(
        psk.encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_auth_token(nonce: str, psk: str, token: str) -> bool:
    """Verify an auth token using constant-time comparison."""
    expected = compute_auth_token(nonce, psk)
    return hmac.compare_digest(expected, token)


# ── PSK file I/O ────────────────────────────────────────────────


def save_psk(psk: str, filepath: Path | None = None) -> Path:
    """Save a PSK to a file with restrictive permissions."""
    filepath = (filepath or DEFAULT_CERT_DIR / PSK_FILE).resolve()
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(psk)

    if sys.platform != "win32":
        os.chmod(filepath, 0o600)

    return filepath


def load_psk(filepath: Path | None = None) -> str:
    """Load a PSK from a file.

    Raises FileNotFoundError with helpful instructions if missing.
    """
    filepath = (filepath or DEFAULT_CERT_DIR / PSK_FILE).resolve()

    if not filepath.exists():
        raise FileNotFoundError(
            f"Pre-shared key not found at {filepath}\n"
            f"Generate one with:  python -m core.crypto_utils --generate-psk"
        )

    return filepath.read_text().strip()


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Cryptographic utilities for the Security Lab",
    )
    parser.add_argument(
        "--generate-certs", action="store_true", help="Generate CA + server + client certificates"
    )
    parser.add_argument(
        "--generate-psk", action="store_true", help="Generate and save a pre-shared key"
    )
    parser.add_argument(
        "--cert-dir",
        type=Path,
        default=None,
        help=f"Certificate directory (default: {DEFAULT_CERT_DIR})",
    )
    parser.add_argument(
        "--hostname",
        default="localhost",
        help="Hostname for the server certificate (default: localhost)",
    )

    args = parser.parse_args()

    if args.generate_certs:
        generate_certificates(cert_dir=args.cert_dir, hostname=args.hostname)

    if args.generate_psk:
        psk = generate_psk()
        out = save_psk(psk, filepath=((args.cert_dir or DEFAULT_CERT_DIR) / PSK_FILE))
        print(f"[crypto] Pre-shared key saved to {out}")
        print(f"[crypto] Key: {psk}")
        print("[crypto] Share this key securely with authorized clients only.")

    if not args.generate_certs and not args.generate_psk:
        has, ver = check_openssl()
        print(f"OpenSSL available: {has}")
        if ver:
            print(f"  Version: {ver}")

        cd = (args.cert_dir or DEFAULT_CERT_DIR).resolve()
        print(f"\nCertificate directory: {cd}")
        for name in (CA_CERT, CA_KEY, SERVER_CERT, SERVER_KEY, CLIENT_CERT, CLIENT_KEY, PSK_FILE):
            p = cd / name
            status = "\u2713 exists" if p.exists() else "\u2717 missing"
            print(f"  {name:<15} {status}")
