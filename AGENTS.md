# WiFi Jammer — Agent Context

## What This Is
WiFi Jammer is an educational WiFi security testing tool built with Python. It implements 802.11 frame injection attacks for authorized penetration testing and security research.

## Architecture
- **SOLID principles**: interfaces (core/interfaces.py), strategies (attacks/), factory (factory/), platform abstraction (core/platform_interface.py)
- **3 UIs**: CLI (click+rich), TUI (textual), GUI (PyQt6)
- **Cross-platform**: Linux (primary), macOS (CoreWLAN), Windows (limited)
- **Attack types (10)**: deauth, disassoc, beacon flood, auth flood, assoc flood, probe response, channel hop, PMKID capture, evil twin, netcut

## Key Files
- `wifi_jammer/cli.py` — CLI entry point (click commands)
- `wifi_jammer/tui.py` — Textual TUI app
- `wifi_jammer/gui/` — PyQt6 GUI (main_window.py entry)
- `wifi_jammer/core/interfaces.py` — AttackType enum, AttackConfig, INetworkScanner, IAttackStrategy
- `wifi_jammer/attacks/` — Attack implementations: base_attack.py, deauth_attack.py, flood_attacks.py, channel_hop_attack.py, pmkid_capture_attack.py, evil_twin_attack.py, netcut_attack.py
- `wifi_jammer/scanner/network_scanner.py` — ScapyNetworkScanner (1600+ lines, macOS fallbacks)
- `wifi_jammer/core/platform_interface.py` — Platform abstraction (Linux/macOS/Windows)
- `wifi_jammer/factory/attack_factory.py` — Factory pattern for creating attacks
- `wifi_jammer/config.py` — ConfigManager with YAML persistence
- `wifi_jammer/utils/` — Logger, validators, platform utils, python detector

## How To Run
```bash
pip install -r requirements.txt
sudo wifi-jammer --tui          # TUI mode
sudo wifi-jammer --gui          # GUI mode
sudo wifi-jammer scan -i wlan0  # CLI scan
sudo wifi-jammer attack -i wlan0 -t AA:BB:CC:DD:EE:FF -a deauth  # CLI attack
```

## Testing
```bash
python run_tests.py
# or
pytest tests/ -v
```

## Dependencies
- scapy (packet crafting)
- textual (TUI)
- PyQt6 (GUI)
- rich, click (CLI)
- pyyaml (config)
- cryptography (optional)
- pyobjc-framework-CoreWLAN (macOS optional)

## Platform Notes
- Linux: Full support, monitor mode via iwconfig
- macOS: Limited monitor mode, CoreWLAN for scanning, Location Services permission required
- Windows: Basic scanning only, no packet injection
