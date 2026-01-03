# WiFi Jammer Tools

This directory contains utility scripts and tools for the WiFi Jammer project.

## Available Tools

### NetCut - WiFi Client Manager

A robust NetCut-style tool for macOS that allows you to discover and manage clients on your WiFi network.

## Features

- 🔍 **Auto-discover network info** - Automatically detects your current WiFi network, BSSID, and channel
- 👥 **Client discovery** - Sniffs network traffic to find all connected devices
- 🎯 **Selective kicking** - Kick specific clients while staying connected yourself
- 🚀 **Kick all** - Remove all other clients from the network
- 📡 **Broadcast mode** - Nuclear option to kick everyone (including yourself)

## Quick Start

```bash
# Make sure you're connected to the target WiFi network first
sudo ./venv/bin/python3 netcut.py
```

## How It Works

1. **Discovers your network** - Reads your current WiFi connection details
2. **Sets monitoring channel** - Tunes to your AP's channel
3. **Sniffs traffic** - Captures packets to identify connected clients
4. **Selective deauth** - Sends deauthentication frames to kick specific devices

## Menu Options

1. **Discover/Refresh clients** - Scan for 30 seconds to find connected devices
2. **Kick specific client** - Choose a client and kick them for a specified duration
3. **Kick ALL clients (except you)** - Remove everyone else from the network
4. **Kick everyone (broadcast)** - Nuclear option (will disconnect you too!)

## Usage Example

```bash
$ sudo ./venv/bin/python3 netcut.py

[*] Getting network information...
[+] Network: KOST BERLIAN
[+] BSSID: 10:8f:fe:00:a3:e0
[+] Channel: 149
[+] Your MAC: 5a:fe:e4:59:42:af
[*] Setting channel to 149...

==================================================
NetCut - WiFi Client Manager
==================================================

No clients discovered yet

Options:
  1. Discover/Refresh clients
  2. Kick specific client
  3. Kick ALL clients (except you)
  4. Kick everyone (broadcast)
  0. Exit

Enter choice: 1
```

## Important Notes

- ⚠️ **Requires root** - Must run with `sudo`
- 📶 **Must be connected** - You need to be connected to the target WiFi network
- 🔒 **Educational purposes only** - Use responsibly and only on networks you own
- 🍎 **macOS only** - Uses macOS-specific tools (`wdutil`, `airport`)

## Tips

- Generate traffic on other devices (browse, stream) to discover them faster
- The tool automatically excludes your MAC address from kicks
- Deauth attacks are bidirectional (AP→Client and Client→AP) for better effectiveness

---

### check_root.py - Diagnostic Script

Quick diagnostic tool to verify your environment is ready for WiFi attacks.

**Usage:**
```bash
# Check root access and Scapy installation
python3 tools/check_root.py

# Or with sudo to test root access
sudo python3 tools/check_root.py
```

**What it checks:**
- ✅ Root/admin privileges (EUID on Unix, Admin on Windows)
- ✅ Scapy installation and functionality
- ✅ Network interface availability
- ✅ macOS-specific: /dev/bpf* device access

**Output:**
- Shows detailed diagnostic information
- Provides helpful error messages if something is missing
- Gives installation instructions for missing dependencies

---

### demo.py - Comprehensive Demo

Educational demo script that shows all features of the WiFi Jammer tool without sending real packets.

**Usage:**
```bash
# Run the full demo
python3 tools/demo.py

# Or via Makefile
make demo
```

**What it demonstrates:**
- 🔍 Interface detection
- 📡 Network scanning (simulated)
- ⚔️ All attack types
- 🚀 Attack configuration
- ⚙️ Configuration management
- 🔒 Security features
- 🏗️ Tool architecture

**Features:**
- Safe demo mode - no actual packets sent
- Educational - shows how to use the tool
- Comprehensive - covers all major features
