# WiFi Jammer Tool - Overview

## What is this system?

WiFi Jammer Tool is a cross-platform Python utility for WiFi network analysis and security testing. It provides network scanning capabilities and various attack vectors for testing WiFi network security and resilience.

## Target Audience

- Security professionals conducting authorized WiFi penetration testing
- Network administrators testing network resilience
- Educational purposes for learning about WiFi security vulnerabilities
- Researchers studying WiFi protocol weaknesses

## Tech Stack

- **Language**: Python 3.9+
- **Core Dependencies**:
  - `scapy` - Packet manipulation and network scanning
  - `rich` - Terminal UI and formatting
  - `textual` - Modern TUI (Terminal User Interface)
  - `PyQt6` - Optional GUI interface
  - `click` - CLI framework
  - `cryptography` - Cryptographic operations
  - `psutil` - System utilities
  - `pyyaml` - Configuration management

## Architecture Summary

The system follows a modular architecture with clear separation of concerns:

```
wifi_jammer/
├── attacks/          # Attack implementations (deauth, flood, evil twin, etc.)
├── cli.py            # Main CLI entry point
├── core/             # Core interfaces and platform abstraction
├── factory/          # Attack factory pattern implementation
├── gui/              # PyQt6 GUI (optional)
├── scanner/          # Network scanning (cross-platform)
├── tui.py            # Textual TUI
└── utils/            # Utilities (logger, validators, crypto, etc.)
```

## Key Features

- **Cross-platform scanning**: Linux, macOS, Windows support
- **Multiple attack types**: Deauth, disassoc, beacon flood, auth flood, evil twin, PMKID capture, channel hop, netcut
- **Multiple interfaces**: CLI, TUI, optional GUI
- **Real-time progress monitoring**: Live statistics during attacks
- **Cross-platform privilege handling**: Root/admin detection and warnings
- **Client discovery and targeting**: Selective client deauthentication

## Security Model

- **Defensive posture**: Tool designed for authorized testing only
- **Privilege awareness**: Explicit root/admin checks with clear warnings
- **No persistence**: No installation of persistent components
- **Audit trail**: Comprehensive logging of all operations

## Getting Started

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run CLI
python -m wifi_jammer

# Run TUI
python -m wifi_jammer.tui <interface>

# Run GUI
python -m wifi_jammer --gui
```

## License

MIT License - See LICENSE file for details.