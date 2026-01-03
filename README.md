# WiFi Jammer Tool

Advanced WiFi jamming tool built with Python, following SOLID principles and designed for educational purposes.

## 🚀 Quick Installation

### macOS (Automated Setup):
```bash
git clone https://github.com/oyi77/wifi-jammer.git
cd wifi-jammer
bash install.sh
# or for quick install:
bash quick_install.sh
```
This will automatically:
- Install all dependencies
- Request Location Services permission
- Detect which Python has permission
- Set everything up for you

### One-liner installation (All Platforms):
```bash
# Linux/macOS
curl -sSL https://raw.githubusercontent.com/oyi77/wifi-jammer/main/quick_install.sh | bash

# Windows (PowerShell)
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/oyi77/wifi-jammer/main/quick_install.sh" -UseBasicParsing).Content
```

### Manual installation:
```bash
git clone https://github.com/oyi77/wifi-jammer.git
cd wifi-jammer
bash install.sh
```

## 📋 Features

- **Multiple Attack Types**: Deauth, Disassoc, Beacon Flood, Auth Flood, Assoc Flood, Probe Response Flood
- **Network Scanning**: Automatic network discovery and analysis
- **Cross-Platform Qt GUI**: Modern graphical user interface using PyQt6 (Windows, macOS, Linux)
- **Modern TUI**: Beautiful, responsive Text-based User Interface using Textual
- **NetCut Tool**: Interactive client discovery and selective device kicking (see `tools/`)
- **SOLID Architecture**: Clean, maintainable code following SOLID principles
- **Cross-Platform**: Enhanced support for macOS (including M1/M2/M3 ARM chips) and Linux
- **Rich CLI**: Beautiful terminal interface with progress bars and tables
- **Easy Installation**: One-command setup with automatic dependency management

## 🛠️ Architecture

The tool follows SOLID principles:

- **Single Responsibility**: Each class has one clear purpose
- **Open/Closed**: Easy to extend with new attack types
- **Liskov Substitution**: All attack strategies are interchangeable
- **Interface Segregation**: Clean interfaces for each component
- **Dependency Inversion**: High-level modules don't depend on low-level modules

### Core Components:

```
wifi_jammer/
├── core/           # Core interfaces and data structures
├── scanner/        # Network scanning functionality
├── attacks/        # Attack strategy implementations
├── factory/        # Factory pattern for creating attacks
├── utils/          # Utility functions and logging
└── cli.py         # Command-line interface
```

## 🎯 Usage

### Qt GUI Mode (Recommended):
```bash
# Launch the cross-platform Qt GUI
sudo wifi-jammer --gui
# or
sudo ./venv/bin/python3 -m wifi_jammer.gui
# or use the dedicated entry point
sudo wifi-jammer-gui
```

### Entry Points:

**Option 1: Using the wrapper script (recommended - auto-detects best Python):**
```bash
# Scan networks
./wifi-jammer.sh scan

# Launch TUI
sudo ./wifi-jammer.sh attack --tui

# Direct attack
sudo ./wifi-jammer.sh attack --interface en0 --target 00:11:22:33:44:55 --attack deauth
```

**Option 2: Using installed command (after `pip install -e .`):**
```bash
# Scan networks
wifi-jammer scan

# Launch TUI
sudo wifi-jammer attack --tui

# Direct attack
sudo wifi-jammer attack --interface en0 --target 00:11:22:33:44:55 --attack deauth
```

**Option 3: Using Python module directly:**
```bash
# Scan networks
python3 -m wifi_jammer.cli scan

# Launch TUI
sudo python3 -m wifi_jammer.cli attack --tui

# Direct attack
sudo python3 -m wifi_jammer.cli attack --interface en0 --target 00:11:22:33:44:55 --attack deauth
```

### Command-line Options:
```bash
# Direct attack with options
sudo ./wifi-jammer.sh attack --interface en0 --target 00:11:22:33:44:55 --attack deauth
```

### Scan Only:
```bash
# Scan networks without attacking
sudo ./wifi-jammer.sh --scan-only
```

### Available Attacks:
- `deauth` - Deauthentication attack
- `disassoc` - Disassociation attack
- `beacon_flood` - Beacon flood attack
- `auth_flood` - Authentication flood attack
- `assoc_flood` - Association flood attack
- `probe_response` - Probe response flood attack

## 🎯 Client Discovery & Selective Kicking

The WiFi Jammer now includes built-in NetCut-style functionality! When using deauth or disassoc attacks, you can:

**Discover connected clients:**
```bash
sudo ./wifi-jammer.sh --interface en0
# Select your target network
# Choose deauth attack
# Answer "yes" when asked to discover clients
```

**The tool will:**
1. 🔍 Scan for 30 seconds to discover all connected devices
2. 📋 Show you a list of discovered clients (excluding your device)
3. 🎯 Let you select specific clients to kick OR kick all
4. ⚡ Send targeted deauth packets to only those clients
5. 💻 Keep you connected while others are kicked

**Standalone NetCut Tool:**
For a dedicated NetCut experience, use:
```bash
sudo python3 tools/netcut.py
```


## 🔧 Requirements

- Python 3.8+
- Root privileges (for wireless interface access on Linux/macOS)
- Wireless interface with monitor mode support
- Linux, macOS, or Windows (limited functionality)

## 📦 Dependencies

- **scapy**: Packet manipulation
- **netifaces**: Network interface management
- **psutil**: System utilities
- **rich**: Beautiful terminal output
- **click**: CLI framework
- **colorama**: Cross-platform colored output
- **PyQt6**: Cross-platform GUI framework (for GUI mode)

### macOS-Specific Dependencies

On macOS, the tool automatically installs:
- **pyobjc-framework-CoreWLAN**: Better WiFi network access (auto-installed on first run)

This is automatically installed when you run the tool on macOS, or you can install it manually:
```bash
pip install pyobjc-framework-CoreWLAN
```

## ⚠️ Legal Notice

**This tool is for educational purposes only!**

- Use only on networks you own or have explicit permission to test
- Respect local laws and regulations
- The authors are not responsible for misuse
- Intended for security research and penetration testing education

## 🐛 Troubleshooting

### Common Issues:

1. **"No wireless interfaces found"**
   - Check if your wireless card supports monitor mode
   - Run `iwconfig` to see available interfaces

2. **"Permission denied"**
   - Make sure to run with `sudo`
   - Check if your user has wireless permissions

3. **"Interface not found"**
   - Verify interface name with `iwconfig`
   - Some interfaces may have different names

4. **macOS: "SSID/BSSID are None" or networks show as `<redacted>`**
   - **Location Services permission required!**
   - **Quick fix**: Run `bash install.sh` or `bash quick_install.sh` - they automatically run setup and request permission
   - Or manually:
     1. System Settings → Privacy & Security → Location Services
     2. Enable Location Services (toggle ON)
     3. Find "Python" or "python3" in the list and check the box ✅
   - **Note**: The tool automatically detects which Python has permission and uses it

### Debug Mode:
```bash
sudo wifi-jammer --verbose
```

## 🔄 Development

### Adding New Attack Types:

1. Create new attack class in `wifi_jammer/attacks/`
2. Inherit from `BaseAttack`
3. Implement `_create_packet()` method
4. Register in `AttackFactory`

### Example:
```python
class MyCustomAttack(BaseAttack):
    def _create_packet(self) -> Packet:
        # Create your custom packet
        return packet
```

## 📄 License

MIT License - see LICENSE file for details.

## 👨‍💻 Author

**Paijo** - Advanced WiFi jamming tool with SOLID principles

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally!
