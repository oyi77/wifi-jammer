# WiFi Jammer — Advanced WiFi Security Testing Tool | Python 802.11 Frame Injection

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-purple.svg)](https://oyi77.github.io/wifi-jammer/)

WiFi Jammer is an educational Python tool for WiFi security testing and penetration testing. It supports multiple 802.11 frame injection attack types including deauthentication, disassociation, beacon flooding, authentication flooding, association flooding, and probe response flooding. Cross-platform CLI, TUI, and GUI interfaces with SOLID architecture.

## Features

**Attack Types**
- Deauthentication attack (targeted and broadcast)
- Disassociation attack
- Beacon flood attack
- Authentication flood attack
- Association flood attack
- Probe response flood attack
- Channel hopping automation (auto-cycles channels during deauth)
- PMKID and WPA handshake capture
- Evil twin attack (AP spoofing + deauth)
- Client discovery with selective device kicking (NetCut-style)

**User Interfaces**

Optional installs: `pip install 'wifi-jammer[tui]'` for the terminal UI,
`pip install 'wifi-jammer[gui]'` for the Qt GUI.
- Rich CLI with progress bars, tables, and interactive prompts
- Modern TUI built with Textual
- Cross-platform Qt GUI built with PyQt6 (Linux, macOS, Windows)

**Platform Support**
- Linux: Full support with monitor mode via iwconfig
- macOS: CoreWLAN scanning with Location Services integration (Intel and Apple Silicon)
- Windows: Basic network scanning (no packet injection)

## Quick Install

### One-liner (Linux/macOS)

```bash
curl -sSL https://raw.githubusercontent.com/oyi77/wifi-jammer/main/quick_install.sh | bash
```

### Git Clone

```bash
git clone https://github.com/oyi77/wifi-jammer.git
cd wifi-jammer
bash install.sh
```

### Manual Setup

```bash
git clone https://github.com/oyi77/wifi-jammer.git
cd wifi-jammer
pip install -r requirements.txt

# macOS only — optional CoreWLAN support
pip install -r requirements-optional.txt
```

## Usage

### CLI Mode

Scan for available WiFi networks:

```bash
sudo wifi-jammer scan -i wlan0
```

Launch a targeted deauthentication attack:

```bash
sudo wifi-jammer attack -i wlan0 -t AA:BB:CC:DD:EE:FF -a deauth
```

Full attack command with options:

```bash
sudo wifi-jammer attack \
  --interface wlan0 \
  --target AA:BB:CC:DD:EE:FF \
  --attack deauth \
  --channel 6 \
  --count 1000 \
  --delay 0.1 \
  --verbose
```

### TUI Mode

```bash
sudo wifi-jammer --tui
```

The Textual-based terminal UI provides an interactive interface for scanning networks, selecting targets, configuring attacks, and monitoring progress in real time.

### GUI Mode

```bash
sudo wifi-jammer --gui
# or
sudo wifi-jammer-gui
```

The PyQt6 GUI provides point-and-click network scanning, attack configuration, and live progress monitoring. Works on Linux, macOS, and Windows.

### Wrapper Script

The included wrapper script auto-detects the best Python interpreter on your system:

```bash
sudo ./wifi-jammer.sh scan
sudo ./wifi-jammer.sh attack --tui
sudo ./wifi-jammer.sh attack --interface en0 --target AA:BB:CC:DD:EE:FF --attack deauth
```

## Architecture

WiFi Jammer follows SOLID principles with clear separation of concerns:

```
wifi_jammer/
├── core/                          # Interfaces and data structures
│   ├── interfaces.py              # AttackType, AttackConfig, INetworkScanner, IAttackStrategy
│   └── platform_interface.py      # Platform abstraction (Linux/macOS/Windows)
├── scanner/
│   ├── network_scanner.py         # ScapyNetworkScanner — orchestration + platform dispatch
│   ├── macos_permissions.py       # macOS Location Services permission handling
│   ├── macos_corewlan.py          # macOS CoreWLAN-framework scanning
│   ├── macos_systools.py          # wdutil/airport/system_profiler scanning+parsing
│   ├── macos_current_network.py   # current-network discovery via system tools
│   ├── packet_processor.py        # 802.11 frame parsing
│   └── scan_state.py              # shared scan results + lock
├── attacks/
│   ├── base_attack.py             # BaseAttack — shared attack logic, stats tracking
│   ├── deauth_attack.py           # DeauthAttack, DisassocAttack
│   ├── flood_attacks.py           # BeaconFlood, AuthFlood, AssocFlood, ProbeResponse
│   ├── channel_hop_attack.py      # ChannelHopAttack — multi-channel deauth
│   ├── pmkid_capture_attack.py    # PmkidCaptureAttack — WPA handshake capture
│   ├── evil_twin_attack.py        # EvilTwinAttack — AP spoofing + deauth
│   └── netcut_attack.py           # NetcutAttack — selective client kicking
├── factory/
│   └── attack_factory.py          # AttackFactory — strategy pattern for attack creation
├── gui/                           # PyQt6 GUI components
│   ├── main_window.py             # Main application window
│   ├── network_scanner_widget.py  # Network discovery widget
│   ├── attack_config_widget.py    # Attack configuration panel
│   └── progress_monitor_widget.py # Live attack progress display
├── utils/                         # Logger, validators, platform utilities
├── config.py                      # ConfigManager with YAML persistence
├── cli.py                         # Click-based CLI entry point
└── tui.py                         # Textual TUI application
```

**Key design patterns:**

- **Strategy pattern**: Each attack type implements `IAttackStrategy`, making them interchangeable
- **Factory pattern**: `AttackFactory` creates attack instances by type, supports runtime registration
- **Interface segregation**: Separate interfaces for scanning (`INetworkScanner`), attacks (`IAttackStrategy`), monitoring (`IMonitor`), logging (`ILogger`), and configuration (`IConfigManager`)
- **Platform abstraction**: `PlatformInterfaceFactory` returns the correct platform implementation (Linux/macOS/Windows) at runtime

## Platform Support

| Platform | Scanning | Packet Injection | Monitor Mode | GUI | TUI |
|----------|----------|-----------------|-------------|-----|-----|
| Linux    | Full     | Full            | iwconfig    | Yes | Yes |
| macOS    | CoreWLAN | Limited         | Limited     | Yes | Yes |
| Windows  | Basic    | No              | No          | Yes | Yes |

**macOS note**: Location Services permission is required for SSID/BSSID visibility. Run `bash install.sh` to configure this automatically, or enable Python in System Settings > Privacy & Security > Location Services.

## Attack Types

| Attack | Description | Use Case |
|--------|-------------|----------|
| `deauth` | Sends 802.11 deauthentication frames to disconnect clients from an AP | Testing client disconnection resilience |
| `disassoc` | Sends 802.11 disassociation frames to remove client associations | Testing reassociation handling |
| `beacon_flood` | Broadcasts fake beacon frames with randomized SSIDs | Testing AP discovery and rogue AP detection |
| `auth_flood` | Floods an AP with authentication requests | Testing authentication rate limiting |
| `assoc_flood` | Floods an AP with association requests | Testing association capacity limits |
| `probe_response` | Responds to probe requests with fake network information | Testing probe response validation |
| `channel_hop` | Auto-cycles channels during deauth to maximize coverage | Testing multi-channel resilience |
| `pmkid_capture` | Captures WPA PMKID and handshake for offline analysis | Testing WPA key exchange security |
| `evil_twin` | Spoofs AP beacon and deauths real AP to capture clients | Testing rogue AP detection |
| `netcut` | Selectively kicks specific clients from a WiFi network | Testing per-device access control |

All attacks support configurable packet count, delay, source MAC spoofing, and channel selection.

## Testing

Run the full test suite:

```bash
python run_tests.py
```

Or use pytest directly:

```bash
pytest tests/ -v
```

Tests cover the scanner, attack strategies, factory pattern, CLI, configuration management, validators, platform utilities, and crypto modules.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-attack-type`)
3. Add your attack class in `wifi_jammer/attacks/` extending `BaseAttack`
4. Register it in `wifi_jammer/factory/attack_factory.py`
5. Add corresponding `AttackType` enum value in `wifi_jammer/core/interfaces.py`
6. Write tests in `tests/`
7. Submit a pull request

**Adding a new attack type:**

```python
from wifi_jammer.attacks.base_attack import BaseAttack

class MyCustomAttack(BaseAttack):
    def _create_packet(self):
        # Construct and return your 802.11 packet
        return packet
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Use it exclusively on networks you own or have explicit written permission to test. Unauthorized use of this tool against networks you do not own is illegal and unethical. The authors and contributors assume no liability for misuse. Always comply with local, state, and federal laws regarding network security testing.
