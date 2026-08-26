# WiFi Jammer Tools

Utility scripts supporting the WiFi Jammer project. Client-kicking lives in
the package itself now (`NetcutAttack` + the CLI discover/kick flow), so the
former standalone `netcut.py` / `kick_clients.py` scripts were removed.

## Available Tools

### check_root.py - Diagnostic Script

Quick diagnostic tool to verify your environment is ready for WiFi attacks.

**Usage:**
```bash
python3 tools/check_root.py          # environment check
sudo python3 tools/check_root.py     # with root access test
```

**What it checks:** root/admin privileges, scapy functionality, interface
availability, and macOS `/dev/bpf*` access.

---

### demo.py - Comprehensive Demo

Educational demo script that shows all features of the WiFi Jammer tool
without sending real packets.

**Usage:**
```bash
python3 tools/demo.py    # or: make demo
```

**Covers:** interface detection, simulated scanning, all attack types,
configuration management, security features, and tool architecture.

---

### setup_macos.py - Location Services Setup

Grants Python Location Services permission on macOS so SSID/BSSID are
visible. Run automatically by `install.sh`; can also be run manually:

```bash
python3 tools/setup_macos.py
```

---

### check_module_size.py - God-File Ratchet Gate

CI/lint gate enforcing the project's module-size limit (no file over 1000
lines, working target <=900):

```bash
python3 tools/check_module_size.py --limit 900
```
