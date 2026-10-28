# Comprehensive Lab Test Plan

A step-by-step verification plan to test all components of the Cross-Platform Remote Administration & Steganography Security Lab across Arch Linux (WSL2), Windows, and Android.

---

## 1. Automated Test Suite Execution

Run the complete unit and integration test suite using Python's built-in `unittest` runner:

```bash
# Run all tests
python -m unittest discover -s tests -p "test_*.py" -v
```

Expected Outcome: All tests pass with code `0`.

---

## 2. Test Phase 1: Cryptographic Setup & Platform Probing

### Step 2.1: Certificate & Key Generation

```bash
python -m core.crypto_utils --generate-certs --generate-psk
```

- **Verify**: Inspect `certs/` directory. Should contain `ca.pem`, `server.pem`, `server.key`, `client.pem`, `client.key`, and `psk.secret`.
- **Security Check**: Verify `certs/` is listed in `.gitignore`.

### Step 2.2: Platform Detection

```bash
python -m core.platform_detect
```

- **Verify**: Correctly identifies OS (`Linux` or `Windows`), architecture (`x86_64`), runtime environment (e.g. `WSL2`), and installed system utilities (`curl`, `openssl`, etc.).

---

## 3. Test Phase 2: Secure Controller & Client Networking

### Step 3.1: Start Controller (Terminal 1)

```bash
python -m core.controller --host 127.0.0.1 --port 4444
```

- **Verify**: Displays controller listening on `127.0.0.1:4444` with TLS enabled.

### Step 3.2: Connect Client (Terminal 2)

```bash
python -m core.client --host 127.0.0.1 --port 4444
```

- **Verify Handshake**:
  1. Controller issues `auth_challenge` (32-byte hex).
  2. Client computes HMAC-SHA256 and replies with `auth_response`.
  3. Controller verifies HMAC match and issues `auth_success`.
  4. Client sends periodic `status_report` telemetry.
  5. Controller logs client system specifications.

### Step 3.3: Authentication Failure Test

Test connection with an invalid pre-shared key:

```bash
python -m core.client --host 127.0.0.1 --port 4444 --psk "WRONG_SECRET_KEY"
```

- **Verify**: Controller immediately terminates connection due to HMAC mismatch. No telemetry is accepted.

---

## 4. Test Phase 3: Steganography & Detection

### Step 4.1: PNG LSB Embedding & Extraction

```bash
python -m stego.png_stego --demo
```

- **Verify**: Creates clean image, embeds secret text payload into pixel LSBs, extracts extracted text, and verifies bit-for-bit equivalence.

### Step 4.2: PDF Text Attachment Steganography

```bash
python -m stego.pdf_stego --demo
```

- **Verify**: Synthesizes clean minimal PDF, embeds payload as comment/attachment, extracts payload, and displays document structure.

### Step 4.3: Forensic Detection Audit

```bash
python -m stego.detection --demo
python -m defense.file_forensics --demo
```

- **Verify**:
  - Distinguishes clean images from stego images via entropy and chi-squared analysis.
  - Detects trailing overlay bytes appended past the EOF terminator.
  - Flags magic-byte vs extension mismatches.

---

## 5. Test Phase 4: Process Lifecycle & Signal Handling

### Step 5.1: Process Metadata Inspection

```bash
python -m lifecycle.process_lab --info
```

- **Verify**: Outputs current PID, PPID, session ID, process group ID, and `/proc` status on Linux.

### Step 5.2: Detached Background Execution & PID Tracking

```bash
python -m lifecycle.process_lab --background --duration 10 --pid-file test_worker.pid
```

- **Verify**: Background PID is reported. `test_worker.pid` is created.
- **Check Liveness**:

  ```bash
  python -m lifecycle.process_lab --check-pid <SPAWNED_PID>
  ```

- **Verify**: Reports alive. After 10 seconds, status changes to dead and PID file is cleaned up.

### Step 5.3: Signal Interception

```bash
python -m lifecycle.process_lab --listen-signals
```

- **Action**: In the terminal, press `Ctrl+C`.
- **Verify**: Intercepts `SIGINT`, performs graceful resource cleanup message, and exits with status 0.

---

## 6. Test Phase 5: Defensive Security & Inspection

### Step 6.1: Live Socket Observation

In Terminal 3, run:

```bash
python -m defense.network_monitor --watch --port 4444
```

- **Action**: Start and stop the client in Terminal 2.
- **Verify**: Network monitor alerts on `[NEW]` socket opened, reports process PID and name, and alerts on `[CLOSED]` socket.

### Step 6.2: Process Hierarchy & Anomaly Inspection

```bash
python -m defense.process_inspector --anomalies
python -m defense.process_inspector --tree
```

- **Verify**: Renders visual process tree and audits processes for suspicious parentage or execution paths.

---

## 7. Test Phase 6: Cross-Device Remote Administration

### Test Setup: Arch Linux Controller + Android / Windows Client

1. **Configure WSL2 Networking**: Ensure Mirrored Mode is enabled in `~/.wslconfig` or portproxy rule is active (see `docs/wsl2_networking.md`).
2. **Start Controller in WSL2**:

   ```bash
   python -m core.controller --host 0.0.0.0 --port 4444
   ```

3. **On Android Device (Termux)**:
   - Copy `certs/ca.pem` and `certs/psk.secret` to phone.
   - Run:

     ```bash
     python -m core.client --host <WINDOWS_HOST_WIFI_IP> --port 4444
     ```

4. **Verification**:
   - Controller logs Android device model (`getprop ro.product.model`), Android release, battery/runtime environment, and Termux capabilities.
