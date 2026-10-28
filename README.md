# Cross-Platform Remote Administration & Steganography Security Lab

A structured, hands-on cybersecurity research and learning lab covering OS internals, networking, remote administration, steganography, process lifecycles, and defensive security across **Linux (Arch / WSL2)**, **Windows**, and **Android (Termux)**.

> **Ethics Statement:** All testing must take place on devices and virtual machines that you own or are explicitly authorized to administer. This project is strictly designed for educational exploration in a controlled laboratory environment.

---

## Features

- **Encrypted Networking & Telemetry** — TLS 1.3 / TCP socket server with newline-delimited JSON protocol and HMAC-SHA256 challenge-response mutual authentication.
- **Cross-Platform Probing** — Automatic detection of operating system families, architecture, runtime environment (native, WSL2, container, Termux), and installed security/compiler toolchains.
- **Steganography Laboratory** —
  - PNG Least Significant Bit (LSB) substitution with magic header framing and capacity calculations.
  - PDF comment/attachment text hiding with zero dependencies.
  - Video container metadata and lossy compression analysis notes.
- **Process Lifecycle Lab** — Foreground vs. background detached execution, signal interception (`SIGINT`, `SIGTERM`, `SIGHUP`), PID file tracking, and safe educational demonstrations of zombie/orphan processes.
- **Defensive Monitoring & Forensics** —
  - Network connection observer mapping active sockets to process IDs.
  - Process hierarchy inspector detecting suspicious parentage, temporary execution paths, and memory-only deleted binaries.
  - File forensics detector measuring Shannon entropy, verifying magic bytes against extensions, and detecting trailing overlay data.
  - Packet capture and Wireshark dissection walkthrough.
- **Complete Test Suite** — Comprehensive `unittest` suite covering all modules.

---

## Using the Makefile

A cross-platform [Makefile](file:///c:/Users/nilot/Documents/VSCode/reverse_shell/Makefile) is provided for convenience across Arch Linux / WSL2, macOS, and Windows:

| Make Command | Action | Equivalent Python Command |
| :--- | :--- | :--- |
| `make setup` | Create `.venv` and install dependencies | `python -m venv .venv && pip install -r requirements.txt ruff` |
| `make certs` | Generate TLS certificates and HMAC key | `python -m core.crypto_utils --generate-certs --generate-psk` |
| `make probe` | Run environment & capability detection | `python -m core.platform_detect` |
| `make controller` | Start TLS controller server | `python -m core.controller` |
| `make client` | Start telemetry client | `python -m core.client` |
| `make test` | Run all 23 unit tests | `python -m unittest discover -s tests -p "test_*.py" -v` |
| `make lint` | Check linting with Ruff | `python -m ruff check .` |
| `make format` | Auto-format codebase with Ruff | `python -m ruff format .` |
| `make stego-demo` | Run PNG & PDF steganography demos | `python -m stego.png_stego --demo && python -m stego.pdf_stego --demo` |
| `make defense-demo` | Run file forensics anomaly demo | `python -m defense.file_forensics --demo` |
| `make clean` | Remove caches and test outputs | Removes `__pycache__`, `.ruff_cache`, `output_*.png` |

---

## Where is the `certs/` Directory? (Auto-Generated)

> [!NOTE]
> **Why `certs/` is not committed to Git:**
> In accordance with cybersecurity and cryptographic hygiene best practices, private keys (`*.key`) and pre-shared authentication tokens (`psk.key`) must **never be checked into version control**. For this reason, `certs/` is explicitly listed in [`.gitignore`](file:///c:/Users/nilot/Documents/VSCode/reverse_shell/.gitignore).

### Auto-Generation

The `certs/` directory is **automatically generated on demand** when you run:

```bash
make certs
# or
python -m core.crypto_utils --generate-certs --generate-psk
```

When executed, `core.crypto_utils` uses your local OpenSSL CLI to create a dedicated local Public Key Infrastructure (PKI):

```text
certs/
├── ca.key         # Root Certificate Authority private key
├── ca.pem         # Root Certificate Authority public certificate
├── server.key     # Controller server private key
├── server.pem     # Controller server certificate signed by local CA
├── client.key     # Client private key
├── client.pem     # Client certificate signed by local CA
└── psk.key        # Cryptographic 32-byte pre-shared HMAC secret token
```

Both `core.controller` and `core.client` automatically read their certificates and PSK from `certs/` (or from the `LAB_CERTS_DIR` variable configured in [`.env`](file:///c:/Users/nilot/Documents/VSCode/reverse_shell/.env)).

---

## Quick Start (Manual Commands)

### 1. Environment Setup

```bash
# Clone and enter the repository
cd reverse_shell

# Create and activate virtual environment
python -m venv .venv

# On Linux / WSL2:
source .venv/bin/activate
# On Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt ruff
```

### 2. Generate Cryptographic Credentials

```bash
python -m core.crypto_utils --generate-certs --generate-psk
```

### 3. Run Platform Capability Probing

```bash
python -m core.platform_detect
```

### 4. Start Controller & Client

```bash
# Terminal 1: Start Controller
python -m core.controller --host 127.0.0.1 --port 4444

# Terminal 2: Start Status Telemetry Client
python -m core.client --host 127.0.0.1 --port 4444
```

### 5. Steganography Experiments

```bash
# PNG LSB Steganography Demo
python -m stego.png_stego --demo

# PDF Attachment Steganography Demo
python -m stego.pdf_stego --demo

# Forensic Steganalysis & Entropy Audit
python -m stego.detection --analyze output_stego.png
```

### 6. Process Lifecycle & Signal Handling

```bash
# Inspect current process metadata
python -m lifecycle.process_lab --info

# Spawn a tracked background worker
python -m lifecycle.process_lab --background --duration 10 --pid-file worker.pid

# Interactive signal handling laboratory
python -m lifecycle.process_lab --listen-signals

# Educational zombie/orphan process demonstration (Linux/WSL2)
python -m lifecycle.process_lab --zombie-demo
```

### 7. Defensive Monitoring & Forensics

```bash
# Monitor active network connections and alert on socket changes
python -m defense.network_monitor --watch --port 4444

# Audit process hierarchy for suspicious parent-child relationships
python -m defense.process_inspector --anomalies
python -m defense.process_inspector --tree

# Scan files for anomalies, entropy, and trailing overlay payloads
python -m defense.file_forensics --demo
```

### 8. Run Automated Test Suite

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Project Structure

```text
reverse_shell/
├── Makefile                     # Cross-platform build & run automation
├── .env.example                 # Environment configuration template
├── .gitignore                   # Excludes .venv, certs, .env, and caches
├── pyproject.toml               # Project metadata & Ruff linter configuration
├── requirements.txt             # Minimal dependencies (Pillow)
├── certs/                       # TLS certificates & PSK (auto-generated, gitignored)
├── core/                        # Controller & client networking
│   ├── platform_detect.py       # OS, architecture, and runtime capability probing
│   ├── protocol.py              # JSON message schema, validation, length prefixing
│   ├── crypto_utils.py          # TLS certificates and HMAC token authentication
│   ├── controller.py            # Async/threaded TLS TCP server (controller)
│   └── client.py                # Status-reporting client with backoff reconnection
├── stego/                       # Steganography laboratory
│   ├── png_stego.py             # PNG LSB pixel embedding & extraction
│   ├── pdf_stego.py             # Benign text attachment in PDF documents
│   ├── detection.py             # Forensic entropy & statistical detection
│   └── video_notes.md           # Video container education & lossy compression
├── lifecycle/                   # Process lifecycle experiments
│   ├── process_lab.py           # FG/BG workers, signals, zombie/orphan demo, PID files
│   └── platform_services.md     # systemd, Windows SCM/Tasks, Android background services
├── defense/                     # Defensive security & inspection tools
│   ├── network_monitor.py       # Real-time socket observer & process mapping
│   ├── process_inspector.py     # Process hierarchy tree & anomaly detector
│   ├── file_forensics.py        # File entropy, magic byte verification & overlay detector
│   └── wireshark_guide.md       # Packet capture, TLS dissection & beaconing guide
├── docs/                        # Architecture & reference documentation
│   ├── architecture.md          # Full system architecture specification
│   ├── android_detection.md     # Android vs Linux detection & Termux internals
│   ├── wsl2_networking.md       # WSL2 NAT vs mirrored networking, port forwarding
│   ├── dependency_strategies.md # Python vs Native C vs PowerShell comparative analysis
│   └── test_plan.md             # End-to-end verification and testing procedures
└── tests/                       # Automated unit and integration tests
    ├── test_platform_detect.py  # Tests for environment and capability probing
    ├── test_protocol.py         # Tests for message schemas and socket framing
    ├── test_stego.py            # Tests for PNG/PDF stego and entropy calculation
    ├── test_lifecycle.py        # Tests for process info and PID file management
    └── test_defense.py          # Tests for network monitor, process tree, and forensics
```

---

## Security Boundaries

This educational laboratory explicitly adheres to strict defensive and safety boundaries:

- **No Remote Code Execution**: No arbitrary remote shell execution, code evaluation (`eval`), or command execution.
- **No Masquerading**: Processes report clear names and PIDs without hiding from system tables.
- **Benign Storage**: Steganography modules embed inert text; media files never execute code.
- **No Unauthorized Persistence**: No automatic background persistence without explicit user configuration.
- **Controlled Environment**: Designed for local development and authorized devices.
