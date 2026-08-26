# CODEBASE.md — wifi-jammer
> Auto-generated codebase memory for AI agents. Last updated: 2026-08-08.

## Purpose
Educational WiFi security testing and penetration testing tool — supports 10 802.11 frame injection attack types (deauth, disassoc, beacon flood, auth flood, assoc flood, probe response, channel hop, PMKID capture, evil twin, netcut) with CLI, TUI, and GUI interfaces across Linux/macOS/Windows.

## Tech Stack
- **Languages**: Python ≥ 3.10
- **Frameworks**: Click (CLI), Textual (TUI), PyQt6 (GUI)
- **Key Libraries**: scapy (packet crafting), psutil, colorama, rich, click, pyyaml, cryptography. Optional extras: `textual` (TUI), `PyQt6` (GUI)

## Entry Points
- **CLI**: `wifi_jammer/cli.py` (Click-based, installed as `wifi-jammer`)
- **TUI**: `wifi_jammer/tui.py` (Textual app, `wifi-jammer --tui`)
- **GUI**: `wifi_jammer/gui/` (PyQt6, `wifi-jammer --gui` or `wifi-jammer-gui`)
- **Wrapper**: `wifi-jammer.sh` (auto-detects best Python interpreter)

## Directory Structure
| Directory | Description |
|-----------|-------------|
| `wifi_jammer/` | Main package — CLI, TUI, config manager |
| `wifi_jammer/core/` | Interfaces and data structures (AttackType, AttackConfig, INetworkScanner, IAttackStrategy) |
| `wifi_jammer/scanner/` | Network scanning — orchestrator (network_scanner), macOS-only logic split into collaborators (macos_permissions, macos_corewlan, macos_systools, macos_current_network), packet parsing (packet_processor), shared scan state (scan_state) |
| `wifi_jammer/attacks/` | Attack implementations — base_attack, deauth, flood, channel_hop, pmkid_capture, evil_twin, netcut |
| `wifi_jammer/factory/` | AttackFactory — strategy pattern for attack creation |
| `wifi_jammer/gui/` | PyQt6 GUI — main_window, network_scanner_widget, attack_config_widget, progress_monitor_widget |
| `wifi_jammer/utils/` | Logger, validators, platform utilities |
| `tests/` | Test suite — CLI, scanner, attacks, factory, config, validators, platform utils, crypto |
| `tools/` | Utilities — demo.py, setup_macos.py, check_root.py, check_module_size.py (module-size ratchet gate) |
| `examples/` | Example usage scripts |
| `docs/` | GitHub Pages documentation site |
| `Formula/` | Homebrew formula (wifi-jammer.rb) |

## Key Files
| File | Purpose |
|------|---------|
| `wifi_jammer/cli.py` | Click CLI wiring |
| `wifi_jammer/cli_session.py` | Interactive session coordinator (WiFiJammerCLI) |
| `wifi_jammer/cli_display.py` | Rich attack progress display |
| `wifi_jammer/cli_launcher.py` | Shared GUI/TUI launch helpers for all CLI commands |
| `wifi_jammer/tui.py` | Textual TUI — interactive scanning and attack interface |
| `wifi_jammer/core/interfaces.py` | AttackType enum, AttackConfig, interface definitions |
| `wifi_jammer/core/platform_interface.py` | Platform abstraction (Linux/macOS/Windows) |
| `wifi_jammer/attacks/base_attack.py` | BaseAttack — shared logic, stats tracking |
| `wifi_jammer/factory/attack_factory.py` | Strategy pattern — creates attacks by type |
| `wifi_jammer/config.py` | ConfigManager with YAML persistence |
| `pyproject.toml` | Package config with entry points |
| `Makefile` | Build/test/lint shortcuts |

## Architecture
SOLID architecture with clear separation of concerns. **Strategy pattern**: each attack type implements `IAttackStrategy` (interchangeable). **Factory pattern**: `AttackFactory` creates attack instances by type with runtime registration support. **Interface segregation**: separate interfaces for scanning, attacks, monitoring, logging, and config. **Platform abstraction**: `PlatformInterfaceFactory` returns correct platform impl at runtime (Linux: full iwconfig monitor mode, macOS: CoreWLAN with Location Services, Windows: basic scanning only).

## Run Commands
```bash
pip install -e .                    # Core CLI install
pip install -e '.[gui,tui]'         # + GUI/TUI surfaces
sudo wifi-jammer scan -i wlan0      # Scan networks
sudo wifi-jammer attack -i wlan0 -t AA:BB:CC:DD:EE:FF -a deauth  # Targeted attack
sudo wifi-jammer --tui              # Terminal UI
sudo wifi-jammer --gui              # PyQt6 GUI
pytest tests/ -v                    # Run tests
make lint                           # Lint with flake8
make format                         # Format with black + isort
```

## Configuration
No environment variables required. Configuration via YAML config file managed by
`ConfigManager` (`~/.wifi_jammer/config.yaml`). Enforced security settings:
`rate_limit_enabled` + `max_packets_per_second` cap the attack loop's packet rate
(via `BaseAttack._effective_delay`); `require_confirmation` makes the CLI ask
before launching an attack (TUI/GUI launches are explicit button gestures).
