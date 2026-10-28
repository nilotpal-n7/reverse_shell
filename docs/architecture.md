# System Architecture & Design Specification

Comprehensive architecture documentation for the Cross-Platform Remote Administration and Steganography Security Lab.

---

## 1. System Overview

The system is designed as a modular, educational security research laboratory emphasizing defensive security, cross-platform systems programming, protocol design, process lifecycles, and steganographic data hiding.

```text
                                  ┌──────────────────────────────┐
                                  │      Controller Server       │
                                  │  (Arch Linux / WSL2 / Any)   │
                                  │  - TLS 1.3 / TCP Socket      │
                                  │  - HMAC Challenge-Response   │
                                  │  - Telemetry Registry        │
                                  └──────────────▲───────────────┘
                                                 │ TLS Encrypted
                                                 │ Newline-Delimited JSON
                   ┌─────────────────────────────┼─────────────────────────────┐
                   │                             │                             │
    ┌──────────────┴──────────────┐┌─────────────┴───────────────┐┌────────────┴─────────────┐
    │     Linux / WSL2 Client     ││       Windows Client        ││    Android (Termux)     │
    │  - Platform Capability Prober││  - Platform Capability Prober││  - Platform Capability  │
    │  - /proc & systemd inspector││  - SCM & Task Scheduler     ││  - getprop & wake locks  │
    │  - Status Telemetry Worker  ││  - Status Telemetry Worker  ││  - Status Telemetry      │
    └─────────────────────────────┘└─────────────────────────────┘└──────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Networking & Communication (`core/`)

- **Transport**: Raw TCP wrapped in standard TLS (`ssl.create_default_context`). Enforces mutual cipher negotiation, certificate verification, and anti-eavesdropping guarantees.
- **Framing**: Stream-oriented TCP framing using newline-delimited JSON (`\n`). Handled transparently by `core.protocol.MessageFramer`.
- **Authentication**: HMAC-SHA256 challenge-response exchange.
  - Controller generates a 32-byte cryptographically secure random challenge.
  - Client computes `HMAC_SHA256(challenge, psk)` and transmits the hex digest.
  - Mitigates replay attacks without transmitting the secret over the wire.
- **Resilience**: Client features exponential backoff reconnection logic (1s, 2s, 4s... capped at 30s) to survive network fluctuations or controller restarts.

### 2.2 Steganography & Detection (`stego/`)

- **PNG LSB Steganography (`png_stego.py`)**:
  - Hides payload bits inside least significant bits of image color channels (R, G, B).
  - Prepends a magic header and 32-bit length prefix for deterministic extraction.
  - Includes capacity calculation and statistical degradation metrics.
- **PDF Steganography (`pdf_stego.py`)**:
  - Constructs compliant, lightweight PDF documents from scratch.
  - Embeds payload data into non-rendering PDF comment syntax (`% ...`) or designated annotation objects.
  - Inert text storage with zero code execution.
- **Forensic Detection (`detection.py`)**:
  - Evaluates byte entropy, Chi-square statistical LSB distribution, magic byte consistency, and trailer anomalies.

### 2.3 Process Lifecycle Laboratory (`lifecycle/`)

- **Execution Modes**: Foreground (blocking) vs background detached execution (POSIX `setsid()` / Windows `DETACHED_PROCESS`).
- **Signal Handling**: Catches POSIX `SIGINT`, `SIGTERM`, `SIGHUP` and Windows console events to demonstrate graceful shutdown and state flushing.
- **Process State Inspection**: Live inspection of PIDs, PPIDs, PGIDs, SIDs, and educational demonstrations of zombie/orphan process states.
- **PID File Management**: Robust PID file lifecycle with stale process detection and `atexit` cleanup.

### 2.4 Defensive Security & Forensics (`defense/`)

- **Network Connection Monitor (`network_monitor.py`)**: Real-time snapshot and watch modes mapping open sockets to local processes via procfs, `ss`, and Windows `netstat`.
- **Process Inspector (`process_inspector.py`)**: Reconstructs system process trees and detects abnormal parent-child execution lineages, memory-only deleted binaries, and suspicious paths.
- **File Forensics (`file_forensics.py`)**: Deep file analyzer calculating Shannon entropy, checking file extension against magic byte headers, and identifying trailing overlay payloads.
- **Packet Capture Guide (`wireshark_guide.md`)**: Educational guide for dissecting TLS handshakes and identifying periodic beaconing signatures.

---

## 3. Protocol Message Specification

All messages are UTF-8 encoded JSON objects ending with a newline (`\n`).

### Message Schema Table

| Message Type | Sender | Key Fields | Purpose |
| :--- | :--- | :--- | :--- |
| `auth_challenge` | Controller | `challenge` (hex string) | Initiates HMAC mutual verification |
| `auth_response` | Client | `response` (hex string), `client_id` | Proves knowledge of shared secret |
| `auth_success` | Controller | `status`: "ok", `session_id` | Confirms authentication; unlocks telemetry |
| `status_report` | Client | `platform`, `capabilities`, `uptime` | Periodic telemetric status update |
| `heartbeat` | Client | `timestamp`, `sequence` | Liveness check |
| `heartbeat_ack` | Controller | `timestamp`, `received_seq` | Confirms controller liveness |
| `error` | Either | `code`, `message` | Structured error reporting |

---

## 4. Threat Model & Educational Boundaries

> [!CAUTION]
> **Strict Operational Boundaries:**
>
> - The communication protocol is strictly limited to telemetry reporting, capability discovery, and heartbeats.
> - No remote shell execution, arbitrary command execution, or dynamic code evaluation (`eval`/`exec`) is implemented.
> - No persistence mechanisms (such as silent registry writing or unauthorized daemon installation) are automated.
> - Steganography demonstrations store benign data and do NOT execute code.
