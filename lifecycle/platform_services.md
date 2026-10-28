# Background Services & Daemons Across Platforms

A comprehensive educational reference on how operating systems manage long-running background tasks, background services, daemonization, and supervision across Linux, Windows, and Android.

---

## 1. Conceptual Comparison

| OS / Environment | Primary Service Manager | Background Mechanism | Supervision / Respawn | Diagnostic Tools |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Systemd)** | `systemd` (PID 1) | System / User Units (`.service`) | Built-in (`Restart=always`) | `systemctl`, `journalctl` |
| **Linux (Legacy/WSL)** | SysV init / OpenRC / nohup | Backgrounding, double-fork | Manual or wrapper (supervisord) | `ps`, `/proc`, `top` |
| **Windows** | Service Control Manager (SCM) | Windows Services (`.exe`) | SCM Recovery tab / automatic | `sc.exe`, `Get-Service`, `services.msc` |
| **Windows (Tasks)** | Task Scheduler | Scheduled / Triggered Tasks | Configured triggers / repetition | `schtasks.exe`, Task Scheduler GUI |
| **Android (App)** | Android OS / ActivityManager | Foreground / Bound Services | WorkManager, JobScheduler | `adb shell dumpsys activity`, Logcat |
| **Android (Termux)** | Termux environment | nohup, Termux:Boot, wake-lock | Runit (`termux-services`) | `sv status`, `ps` |

---

## 2. Linux Service Architecture: systemd

On modern Linux systems (including Arch Linux and modern WSL2 with `[boot] systemd=true` in `/etc/wsl.conf`), `systemd` is PID 1 and manages all system and user services.

### 2.1 System Service vs User Service

- **System Services** (`/etc/systemd/system/`):
  - Run as `root` (or a designated non-root user via `User=nobody`).
  - Start at system boot before any user logs in.
  - Require root privileges (`sudo systemctl`) to manage.
- **User Services** (`~/.config/systemd/user/`):
  - Run as the specific user.
  - Start when the user logs in and stop on logout (unless lingering is enabled: `loginctl enable-linger <user>`).
  - Do NOT require root privileges (`systemctl --user`).

### 2.2 Complete Example: User Unit (`security-agent.service`)

Create file `~/.config/systemd/user/security-lab-agent.service`:

```ini
[Unit]
Description=Security Lab Status Reporting Agent (Educational)
Documentation=https://github.com/your-repo/reverse_shell
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/reverse_shell
ExecStart=/usr/bin/python3 -m core.client --host 127.0.0.1 --port 4444
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

# Security Sandboxing Flags (Defensive Hardening)
ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=true

[Install]
WantedBy=default.target
```

### 2.3 Management Commands

```bash
# Reload unit files after editing
systemctl --user daemon-reload

# Start and enable on login
systemctl --user enable --now security-lab-agent.service

# Check status and logs
systemctl --user status security-lab-agent.service
journalctl --user-unit security-lab-agent.service -f

# Stop and disable
systemctl --user stop security-lab-agent.service
systemctl --user disable security-lab-agent.service
```

### 2.4 WSL2 Considerations

WSL2 does not run systemd by default on older setups. To enable systemd in WSL2:

1. Edit `/etc/wsl.conf`:

   ```ini
   [boot]
   systemd=true
   ```

2. Restart WSL from Windows PowerShell: `wsl --shutdown`.

---

## 3. Windows Service Architecture

Windows differentiates between interactive applications and non-interactive Windows Services.

### 3.1 What is a Windows Service?

- Managed by the Service Control Manager (SCM).
- Runs under system accounts (`LocalSystem`, `NetworkService`, `LocalService`) or a domain/local user account.
- Must implement the SCM handshake (`ServiceMain` and `Handler` callback functions). A plain `.exe` or script cannot run as a Windows Service directly without a wrapper or SCM integration.

### 3.2 Service Wrappers: NSSM and `sc.exe`

A standard tool used in testing and operations to run scripts as managed Windows services is **NSSM (Non-Sucking Service Manager)**:

```powershell
# Using NSSM to install a Python service:
nssm install SecurityLabClient "C:\Python311\python.exe" "-m core.client --host 127.0.0.1 --port 4444"
nssm set SecurityLabClient AppDirectory "C:\Users\nilot\Documents\VSCode\reverse_shell"
nssm start SecurityLabClient

# Query service status:
nssm status SecurityLabClient
Get-Service SecurityLabClient
```

Using native Windows `sc.exe` (native service control):

```powershell
# Query service configuration
sc.exe query SecurityLabClient

# Check service configuration
sc.exe qc SecurityLabClient

# Stop service
sc.exe stop SecurityLabClient

# Delete service
sc.exe delete SecurityLabClient
```

### 3.3 Windows Task Scheduler

For lightweight scripts, Windows Task Scheduler is often used instead of full SCM services:

```powershell
# Create a task triggered at user logon
schtasks.exe /Create /SC ONLOGON /TN "SecurityLab\Agent" `
    /TR "python -m core.client --host 127.0.0.1 --port 4444" `
    /RL LIMITED

# Query registered task
schtasks.exe /Query /TN "SecurityLab\Agent" /FO LIST /V

# Delete task
schtasks.exe /Delete /TN "SecurityLab\Agent" /F
```

---

## 4. Android Service Architecture & Restrictions

Android's process lifecycle is heavily constrained by battery management and RAM pressure.

### 4.1 Native App Background Restrictions

- **Background Execution Limits (Android 8.0+)**: Apps cannot freely run background services when the app is in the background.
- **Foreground Services (with Notification)**:
  - Required if an app needs ongoing background network access.
  - MUST show a persistent notification in the notification bar (user visibility).
  - Subject to power-saving exemptions.
- **WorkManager**:
  - The recommended modern Android API for deferrable, guaranteed background work.
  - Handles scheduling around battery constraints and network availability.
- **Doze Mode & App Standby**:
  - When an Android device is unplugged and stationary with screen off, network access is restricted to periodic maintenance windows.

### 4.2 Termux Environment (Terminal on Android)

When running Linux/Python tools on an Android device via Termux:

1. **Wake Lock**:
   - By default, Android suspends Termux CPU activity when the screen turns off.
   - Run `termux-wake-lock` to acquire a `PARTIAL_WAKE_LOCK`.
   - Release it with `termux-wake-unlock`.
2. **Background Execution**:
   - `nohup python -m core.client &` runs the client detached.
   - Or use the `termux-services` package (based on `runit`):

     ```bash
     pkg install termux-services
     # create service run script in $PREFIX/var/service/<name>/run
     sv-enable <name>
     sv status <name>
     ```

3. **Termux:Boot**:
   - An add-on app that allows running scripts located in `~/.termux/boot/` when the Android device finishes booting.

---

## 5. Defensive Auditing & Detection

How defenders discover unknown or unauthorized background services:

### On Linux

```bash
# List all running and enabled systemd services
systemctl list-unit-files --type=service --state=enabled
systemctl --user list-unit-files --type=service --state=enabled

# Inspect unusual unit definitions
find /etc/systemd/system/ ~/.config/systemd/user/ -name "*.service" -exec ls -la {} +

# Check cron and timer jobs
crontab -l
systemctl list-timers
```

### On Windows

```powershell
# List third-party services (excluding Microsoft built-in)
Get-WmiObject win32_service | Where-Object { $_.PathName -notlike "*C:\Windows\*" } | Select-Object Name, DisplayName, State, PathName

# List scheduled tasks created in root
Get-ScheduledTask | Where-Object { $_.TaskPath -eq "\" -and $_.Author -ne "Microsoft" } | Select-Object TaskName, State, Actions

# Inspect persistence registry keys
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

### On Android

```bash
# Dump active services via ADB
adb shell dumpsys activity services

# List apps with device admin or wake lock permissions
adb shell pm list packages -d
```
