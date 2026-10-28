"""
Core Networking Modules
======================
Controller/client architecture with TLS, JSON messaging, platform detection,
and HMAC-SHA256 authentication.

Modules:
    platform_detect  — OS, architecture, runtime, and capability detection
    protocol         — JSON message schema, framing, and validation
    crypto_utils     — TLS certificate management and token authentication
    controller       — TCP server (controller)
    client           — Status-reporting client
"""
