# WSL2 Networking: Architecture, NAT vs. Mirrored, and Cross-Device Routing

A complete operational guide for configuring network connectivity between your **Arch Linux WSL2 controller**, the **Windows host machine**, and external **Android / Linux devices** on your local area network (LAN).

---

## 1. The WSL2 Networking Problem

When running an administration server (such as `core.controller`) inside Arch Linux on WSL2, external devices (such as an Android phone connected via Wi-Fi) cannot reach WSL2 out of the box.

This occurs because WSL2 operates as a lightweight Hyper-V virtual machine with its own virtualized network stack.

```text
       [ Android Device (Wi-Fi) ]
             IP: 192.168.1.105
                    │
                    ▼  (Requests port 4444)
    ┌───────────────────────────────────────────────┐
    │ Windows Host Physical NIC (Wi-Fi)             │
    │ IP: 192.168.1.50                              │
    │                                               │
    │ ─── NAT Barrier (Default WSL2) ────────────── │
    │                                               │
    │ Hyper-V Virtual Switch: 172.28.0.1            │
    └───────────────────────┬───────────────────────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────┐
    │ Arch Linux WSL2 VM (eth0)                     │
    │ IP: 172.28.14.92                              │
    │ Controller listening on port 4444             │
    └───────────────────────────────────────────────┘
```

---

## 2. Solution 1: Mirrored Mode (Recommended for Windows 11)

In modern WSL releases (WSL 2.0+ on Windows 11 22H2+), Microsoft introduced **Mirrored Mode networking**. In mirrored mode, WSL2 shares the exact network interfaces, IP addresses, and routing table as your Windows host machine.

### How to Enable Mirrored Mode

1. On your Windows host, open or create `%USERPROFILE%\.wslconfig` (e.g. `C:\Users\nilot\.wslconfig`).
2. Add the following configuration:

   ```ini
   [wsl2]
   networkingMode=mirrored
   firewall=true
   dnsTunneling=true
   autoProxy=true
   ```

3. Restart WSL from PowerShell:

   ```powershell
   wsl --shutdown
   ```

4. Verify in Arch Linux:

   ```bash
   # Run in Arch Linux:
   ip addr show
   ```

   You will now see your physical Wi-Fi/Ethernet IP (e.g., `192.168.1.50`) directly inside Arch Linux!
5. Start your controller in Arch Linux bound to all interfaces:

   ```bash
   python -m core.controller --host 0.0.0.0 --port 4444
   ```

6. Your Android device or Windows client can now connect directly to `192.168.1.50:4444`.

---

## 3. Solution 2: NAT Mode with Port Forwarding (Windows 10 / Legacy)

If mirrored mode is not supported on your Windows build, use standard NAT mode and configure Windows port forwarding (`portproxy`):

### Step 1: Discover WSL2 Internal IP Address

In your Arch Linux terminal:

```bash
ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
# Example output: 172.28.14.92
```

### Step 2: Configure Port Forwarding on Windows Host

In an **Administrator PowerShell** on Windows, map incoming port 4444 to WSL2's internal IP:

```powershell
$wslIp = (wsl ip -4 addr show eth0 | Select-String -Pattern '(?<=inet\s)\d+(\.\d+){3}').Matches.Value
Write-Host "WSL2 IP is: $wslIp"

# Add port proxy rule
netsh interface portproxy add v4tov4 listenport=4444 listenaddress=0.0.0.0 connectport=4444 connectaddress=$wslIp

# Verify rule
netsh interface portproxy show v4tov4
```

### Step 3: Open Windows Defender Firewall Port

Allow external traffic through the Windows firewall:

```powershell
New-NetFirewallRule -DisplayName "Security Lab Controller 4444" `
    -Direction Inbound `
    -LocalPort 4444 `
    -Protocol TCP `
    -Action Allow
```

---

## 4. Cross-Platform IP Addressing Cheat Sheet

| Communication Link | Target Address to Connect To |
| :--- | :--- |
| **Arch Linux → Arch Linux (Same WSL)** | `127.0.0.1:4444` |
| **Windows Host → Arch Linux (Mirrored Mode)** | `127.0.0.1:4444` |
| **Windows Host → Arch Linux (NAT Mode)** | `127.0.0.1:4444` (WSL localhost-forwarding handles this) |
| **Android Device → Arch Linux (Same Wi-Fi)** | `<Windows_Host_WiFi_IP>:4444` (e.g. `192.168.1.50:4444`) |
| **Arch Linux → Windows Host Services** | In Mirrored Mode: `127.0.0.1` In NAT Mode: IP in `/etc/resolv.conf` |

---

## 5. Diagnostic Commands

If a client cannot connect, troubleshoot with these commands:

```bash
# 1. On Arch Linux: Verify controller is listening
ss -tulpn | grep 4444

# 2. On Windows Host (PowerShell): Test TCP port open
Test-NetConnection -ComputerName 127.0.0.1 -Port 4444

# 3. On Android (in Termux): Test TCP connectivity
nc -zv 192.168.1.50 4444
# or with curl
curl -k -v https://192.168.1.50:4444
```
