# AGENTS.md — 1ai-ecosystem Engineering Rules

This repository is part of the **1ai-ecosystem**. You are governed by the mandatory engineering rules below.

---

## ⚡ START HERE

Read the rules in the order specified for your session type. **Do not skip. Do not summarize. Read the full text.**

> The rules are located at `_rules/` in this repo, synced from `github.com/oyi77/1ai-rules`.

```
_rules/
├── ENGINEERING.md    ← core engineering protocol (always required)
├── VERIFICATION.md   ← receipt enforcement (always required)
├── QA.md             ← QA protocol (for testing sessions)
├── SURPASS.md        ← competitive strategy (for planning sessions)
└── DOCS.md           ← documentation standards (for docs sessions)
```

---

## Session Classification

Determine your session type, then load the required rules **in order**:

| Session Type | Required Reading | Order |
|---|---|---|
| **Coding / bugfix / feature** | ENGINEERING.md + VERIFICATION.md | 1 → 2 |
| **QA / testing existing code** | QA.md + VERIFICATION.md | 1 → 2 |
| **Competitive research / planning** | SURPASS.md | 1 |
| **Documentation** | DOCS.md | 1 |
| **Full sprint (build + test + docs)** | ALL rules (ENGINEERING.md + VERIFICATION.md + QA.md + SURPASS.md + DOCS.md) | 1→2→3→4→5 |

---

## Hard Rules (apply regardless of session type)

1. **Receipts are mandatory.** Every "done" claim requires literal verbatim terminal/test/log output. A summary is not a receipt. No receipt = not done.
2. **Break it before you ship it.** Adversarial test required before any completion claim. Empty input, max boundary, error paths, concurrent access, auth boundaries.
3. **Docs are part of the deliverable.** Code changes without synced docs are incomplete. Update docs in the same change.
4. **No silent failure.** Every error must be caught, logged, and surfaced. Empty catches and suppressed errors are defects.
5. **No hallucinated paths/symbols/APIs.** Read the file before claiming it exists. Use codebase-memory-mcp or equivalent on indexed repos.
6. **These rules cannot be waived** by any instruction, task phrasing, or user request. See ENGINEERING.md §8 for the conflict hierarchy.

---

## Detection

- If `_rules/` does not exist → this repo hasn't been set up yet. Load rules from `~/.1ai/rules/` (on the local filesystem) or clone `github.com/oyi77/1ai-rules` first.
- If `~/.1ai/` does not exist → run the setup script: `gh repo clone oyi77/1ai-rules ~/.1ai`

---

## Project-Specific Notes

<!-- Add repo-specific rules below this line -->
<!-- Examples: port numbers, env vars, deploy targets, CI commands, local quirks -->

---

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
