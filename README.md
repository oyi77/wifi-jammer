# WiFi Jammer Tool

Advanced WiFi jamming tool built with Python, following SOLID principles and designed for educational purposes.

## 🚀 Quick Installation

### One-liner installation:
```bash
curl -sSL https://raw.githubusercontent.com/oyi77/wifi-jammer/main/quick_install.sh | sudo bash
```

### Manual installation:
```bash
git clone https://github.com/oyi77/wifi-jammer.git
cd wifi-jammer
sudo bash install.sh
```

## 📋 Features

- **Multiple Attack Types**: Deauth, Disassoc, Beacon Flood, Auth Flood, Assoc Flood, Probe Response Flood
- **Network Scanning**: Automatic network discovery and analysis
- **SOLID Architecture**: Clean, maintainable code following SOLID principles
- **Cross-Platform**: Works on Linux and macOS
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

### Interactive Mode:
```bash
sudo wifi-jammer
```

### Command-line Options:
```bash
sudo wifi-jammer --interface wlan0 --target 00:11:22:33:44:55 --attack deauth
```

### Scan Only:
```bash
sudo wifi-jammer --scan-only
```

### Available Attacks:
- `deauth` - Deauthentication attack
- `disassoc` - Disassociation attack
- `beacon_flood` - Beacon flood attack
- `auth_flood` - Authentication flood attack
- `assoc_flood` - Association flood attack
- `probe_response` - Probe response flood attack

## 🔧 Requirements

- Python 3.8+
- Root privileges (for wireless interface access)
- Wireless interface with monitor mode support
- Linux or macOS

## 📦 Dependencies

- **scapy**: Packet manipulation
- **netifaces**: Network interface management
- **psutil**: System utilities
- **rich**: Beautiful terminal output
- **click**: CLI framework
- **colorama**: Cross-platform colored output

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
