# Cross-Platform Dependency & Implementation Strategies

A comparative analysis of engineering strategies for deploying administration and monitoring agents across heterogeneous platforms (Linux, Windows, Android).

---

## 1. Strategy Comparison Matrix

| Metric | Strategy A: Python Prototype | Strategy B1: Native C (POSIX/Winsock) | Strategy B2: PowerShell (Windows Native) | Strategy C: Dynamic Adaptive (Probe & Fallback) |
| :--- | :--- | :--- | :--- | :--- |
| **Prerequisites** | Python 3.8+ runtime | None (static) or OS libc | PowerShell 5.1+ (Built into Windows) | Dynamic (uses whatever is present) |
| **Binary / Script Size** | ~50 KB scripts (+ ~30MB Python) | ~50 KB – 500 KB compiled binary | Single ~15 KB script | Small modular bootstrap |
| **RAM Footprint** | ~15 – 30 MB (Python interpreter) | ~2 – 5 MB | ~30 – 50 MB (PowerShell runtime) | Depends on selected runtime |
| **Startup Latency** | ~50 – 150 ms | < 5 ms | ~500 – 1500 ms (PowerShell JIT) | Varies |
| **Maintenance Cost** | Low (rapid prototyping, readable) | High (memory management, platform APIs) | Medium (Windows only) | Medium |
| **EDR / Antivirus Scrutiny** | Low to Medium | Low (unless packed) | High (PowerShell script block logging) | Varies |

---

## 2. Strategy A: Python Prototype (Our Primary Lab Implementation)

### Advantages

- **Fast Iteration**: Built-in JSON serialization, standard `ssl` library supporting TLS 1.3, cross-platform `os` and `subprocess` abstractions.
- **Portability**: The identical Python codebase executes on Arch Linux (WSL2), Windows 11, Ubuntu, macOS, and Android (via Termux).
- **Security & Inspection**: Easy to audit and read. Clear educational value.

### Limitations

- Requires a Python interpreter. Stock Windows installations and minimal container/embedded Linux images do not ship with Python by default.
- On Android, requires the user to install Termux and run `pkg install python`.

---

## 3. Strategy B: Native Implementations

### B.1 Linux & Android: Native POSIX C Client

For zero-dependency deployment on minimal Linux systems or embedded devices without Python:

- **Networking**: Standard POSIX sockets (`socket()`, `connect()`, `send()`, `recv()`).
- **TLS Encryption**: Linked against OpenSSL (`libssl.so` / `libcrypto.so`) or embedded MbedTLS.
- **Cross-Compilation**: Easily compiled with `aarch64-linux-gnu-gcc` for Android or ARM64 boards, or `x86_64-linux-gnu-gcc` for Linux.
- **Pros**: Sub-millisecond startup, minimal memory footprint (< 3 MB).

### B.2 Windows: Native PowerShell Client

On Windows machines where Python is not installed, PowerShell is already present on every Windows 10/11 system:

- **Networking & TLS**: Uses `.NET` `System.Net.Sockets.TcpClient` and `System.Net.Security.SslStream`.
- **JSON Handling**: Native `ConvertTo-Json` and `ConvertFrom-Json`.
- **Zero Installation**: Runs directly in memory without installing external interpreters.
- **Defensive Note**: PowerShell activity is monitored by Windows Defender Antivirus, AMSI (Antimalware Scan Interface), and Script Block Logging (Event ID 4104).

---

## 4. Strategy C: Capability Detection & Adaptive Negotiation Layer

Rather than assuming a uniform runtime environment across all targets, modern multi-platform architectures utilize a **Capability Detection Layer**:

```text
                        [ Target Node Bootstrap ]
                                    │
                        ┌───────────┴───────────┐
                        │   Probe Environment   │
                        └───────────┬───────────┘
                                    │
            ┌───────────────────────┼────────────────────────┐
            │                       │                        │
       Python Found?         PowerShell Found?          POSIX Sockets?
            │                       │                        │
            ▼                       ▼                        ▼
    Launch Python Agent      Launch PowerShell        Launch Native ELF
     (Full Feature Set)         (Windows Zero-Dep)       (Linux / Android)
```

### Detection Logic in `core.platform_detect`

1. **Probe System**: Check `shutil.which("python3")`, `which("pwsh")`, `which("powershell")`, `which("curl")`, `which("openssl")`.
2. **Feature Reporting**: Telemetry reports available toolchains (e.g. `has_compiler`, `has_powershell`, `has_wireshark`).
3. **Graceful Degradation**: If advanced capabilities (like `Pillow` for PNG steganography) are unavailable, client reports format as unsupported without crashing.
