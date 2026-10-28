# Android vs. Linux: Detection Challenges & Runtime Internals

A technical deep dive into identifying Android environments, distinguishing them from generic Linux distributions, and handling mobile-specific constraints.

---

## 1. The Detection Problem

When executing Python or native C code on Android (e.g., inside Termux or an embedded shell), calling standard operating system introspection APIs produces misleading results:

```python
import platform

print(platform.system())  # Outputs: 'Linux'
print(platform.release())  # Outputs: '5.10.136-android12-9-...' (or a generic kernel version)
```

Because Android runs on top of the Linux kernel, the kernel reports its name as `Linux`. However, the **userland environment** of Android is fundamentally different from a GNU/Linux distribution (like Arch Linux, Ubuntu, or Debian).

| Characteristic | Standard GNU/Linux (Arch, Ubuntu) | Android (Userland / Termux) |
| :--- | :--- | :--- |
| **C Standard Library** | `glibc` or `musl` | `bionic` (Google's BSD-derived libc) |
| **Dynamic Linker** | `/lib64/ld-linux-x86-64.so.2` | `/system/bin/linker64` |
| **Init System** | `systemd`, `OpenRC`, or `SysV` | `init` (Android init with `.rc` scripts) |
| **Filesystem Hierarchy** | FHS compliant (`/bin`, `/etc`, `/usr`) | Non-standard (`/system`, `/data`, `/apex`) |
| **Device Configuration** | `/etc/os-release`, `/etc/issue` | Android System Properties (`getprop`) |
| **Process Security** | Standard DAC, optional AppArmor/SELinux | Enforcing SELinux with strict app sandboxes |

---

## 2. Multi-Layer Detection Strategy

To accurately determine whether code is running on Android, `core/platform_detect.py` uses a multi-layered verification strategy:

```text
                           ┌───────────────────────────┐
                           │   Is platform == Linux?   │
                           └─────────────┬─────────────┘
                                         │ Yes
                                         ▼
                     ┌───────────────────────────────────────┐
                     │ Layer 1: Check Environment Variables  │
                     │  - $ANDROID_ROOT (/system)            │
                     │  - $ANDROID_DATA (/data)              │
                     │  - $PREFIX contains 'com.termux'      │
                     │  - $TERMUX_VERSION set                │
                     └───────────────────┬───────────────────┘
                                         │ If not conclusive
                                         ▼
                     ┌───────────────────────────────────────┐
                     │ Layer 2: Check Android Filesystem     │
                     │  - /system/build.prop exists?         │
                     │  - /system/bin/getprop exists?        │
                     │  - /data/data/com.termux exists?      │
                     └───────────────────┬───────────────────┘
                                         │ If present
                                         ▼
                     ┌───────────────────────────────────────┐
                     │ Layer 3: Query Android System Props   │
                     │  - Execute: getprop ro.build.version  │
                     │  - Execute: getprop ro.product.model  │
                     └───────────────────┬───────────────────┘
                                         │
                                         ▼
                        [ Definitively Android / Termux ]
```

### 2.1 Layer 1: Environment Variables

Inside the Termux terminal app on Android:

- `os.environ.get("PREFIX")`: Points to `/data/data/com.termux/files/usr`.
- `os.environ.get("TERMUX_VERSION")`: Contains the Termux application version string.
- `os.environ.get("ANDROID_ROOT")`: Standard Android environment variable set to `/system`.

### 2.2 Layer 2: Android System Properties (`getprop`)

Android stores OS properties in a shared memory region managed by `init`. These properties can be queried via the CLI utility `/system/bin/getprop`:

```bash
# Get Android API level
/system/bin/getprop ro.build.version.sdk

# Get user-facing Android OS release (e.g. "13" or "14")
/system/bin/getprop ro.build.version.release

# Get device hardware model (e.g. "Pixel 7" or "SM-G998U")
/system/bin/getprop ro.product.model
```

### 2.3 Layer 3: Filesystem Markers

Even if environment variables have been stripped (e.g., in a sanitized subshell), the existence of `/system/build.prop` or the Android runtime APEX directory (`/apex/com.android.runtime`) confirms an Android userland.

---

## 3. Practical Differences When Porting Code to Android

### 3.1 Network Observation Constraints (SELinux)

On modern Android (Android 10+ / API 29+), SELinux policy blocks non-root applications from reading `/proc/net/tcp` and `/proc/net/udp` to prevent malicious apps from snooping on other apps' connections:

- In `defense/network_monitor.py`, attempts to inspect raw `/proc/net/tcp` on unrooted Android will raise `PermissionError`.
- The code gracefully handles this permission denial and reports an informational status rather than crashing.

### 3.2 Battery Management & Doze Mode

- In standard Linux, background processes run indefinitely until killed.
- On Android, the OS suspends CPU execution when the screen is off (Doze mode).
- In Termux, scripts requiring ongoing network communication must acquire a wake lock via `termux-wake-lock`.

### 3.3 Dynamic Binary Execution

Android userland binaries must be compiled against Google's `Bionic` libc using the Android NDK (Native Development Kit), not GNU libc. A standard x86_64 or ARM64 Linux binary will fail to execute on Android with `No such file or directory` due to the missing GNU dynamic linker (`ld-linux`).
