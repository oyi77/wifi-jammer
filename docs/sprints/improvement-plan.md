# Codebase Improvement Plan — wifi-jammer

> Status: PROPOSED | Created: 2026-08-25 | Baseline verified on this date:
> **150/150 tests pass (7.1s), mypy --strict clean, coverage 31.4%, branch `main`, tree clean.**

## Goal

Eliminate all correctness bugs found in review, decompose every god-file, and install
guardrails so no module ever crosses **1,000 lines** again. Working target: **<500 lines
per module** (matches ecosystem rules), enforced by CI.

## Hard constraint

No tracked Python file may exceed 999 lines after Phase 2. Enforced by a CI gate so the
constraint survives maintainer turnover.

## Current god-file inventory (verified `wc -l`, 2026-08-25)

| File | Lines | >1000? | Split priority |
|---|---|---|---|
| `wifi_jammer/scanner/macos_scanner.py` | 1277 | **YES** | P0 |
| `wifi_jammer/cli.py` | 762 | no | P1 |
| `wifi_jammer/core/platform_interface.py` | 711 | no | P1 |
| `wifi_jammer/scanner/network_scanner.py` | 673 | no | P2 |
| `wifi_jammer/tui.py` | 632 | no | P2 |
| `tools/kick_clients.py` | 475 | no | P3 (delete) |

## Decomposition strategy — approaches considered

| Option | Description | Verdict |
|---|---|---|
| A. Package split (`scanner/macos/corewlan.py`…) | Deep nesting, churns import paths everywhere | Rejected |
| B. Flat sibling modules, facade kept | New flat modules beside originals; original class stays as thin facade delegating to collaborators | **Chosen** |
| C. Big-bang rewrite into new package | Highest regression risk, bus factor 1 = nobody to review | Rejected |

**B** matches what commit `d30aa78` already did successfully (`ScapyNetworkScanner` →
`MacOSScanner` + `PacketProcessor` + `ScanState` collaborators). Same pattern, next layer.

---

## Phase 0 — Guardrails first (so splits stay enforced)

| # | Change | Acceptance |
|---|---|---|
| 0.1 | Add `--max-module-lines=900` to flake8 lint (Makefile + CI) | `make lint` fails if any module >900 lines (buffer below hard 1000) |
| 0.2 | Make pip-audit blocking on scheduled runs only (it already has the `schedule` condition — remove `\|\| true`) | Audit failures visible |

**Rollback**: single revert; no behavior change.

## Phase 1 — P0 correctness bugs (each: fix + failing-today test)

| # | Bug | Fix | Test |
|---|---|---|---|
| 1.1 | PMKID capture dead code — unconditional `return` in `_sniff_packets` makes sniff loop unreachable | Delete stray `return` | Assert `scapy.sniff` called when attack executes (mock) |
| 1.2 | CLI clobbers interactive answers — Click defaults (`count=0`, `delay=0.1`) always overwrite prompts | Options default `None`; only override config when flag explicitly passed | Interactive path keeps prompted values |
| 1.3 | Linux misses systemd interface names (`wlp3s0`) — prefix check `wlan/wifi/ath` classifies them Ethernet | Detect wireless via `/sys/class/net/<iface>/wireless` or `iw dev`; keep prefix fallback | `get_interface_info('wlp3s0')` → wireless+monitor-capable |
| 1.4 | ConfigManager security settings unwired — `require_confirmation`, `rate_limit_enabled`, `max_packets_per_second` enforced nowhere | **Decision point**: wire `require_confirmation` prompt + pps cap into `BaseAttack.execute()/_attack_loop`, or delete the keys | Either way: no documented-but-dead settings remain |
| 1.5 | Coverage gate bump `--cov-fail-under=29 → 33` — **runs at end of Phase 1 only**, after 1.1–1.4 tests land (today's real number is 31.4%; raising it in Phase 0 would go red immediately) | CI green at gate 33 |

**Rollback**: one revert per bug; independent commits.

## Phase 2 — God-file decomposition (the 1000-line kill)

### 2.1 `macos_scanner.py` 1277 → 4 files (<500 each)

| New file | Extracted from | ~Lines |
|---|---|---|
| `scanner/macos_permissions.py` | `check_permission`, `_request_permission_if_needed` | ~120 |
| `scanner/macos_corewlan.py` | `get_current_network_via_corewlan`, `scan_via_corewlan` | ~400 |
| `scanner/macos_systools.py` | wdutil/airport/system_profiler/networksetup parsing: `scan()`, `parse_wdutil_scan`, `parse_airport_scan`, `parse_macos_networks`, system-tool helpers of `get_current_network` | ~450 |
| `scanner/macos_scanner.py` | Facade: `MacOSScanner.__init__` wiring + `get_current_network` orchestration delegating to the three collaborators (same injection style as `PacketProcessor`/`ScanState`) | ~300 |

Public API unchanged: `network_scanner.py` still imports `MacOSScanner`. Tests untouched.

### 2.2 Remaining near-threshold files (same pattern)

| File | Now | Split | After |
|---|---|---|---|
| `cli.py` 762 | interactive session class + click commands + inline kick logic | `cli/session.py` (WiFiJammerCLI), `cli/commands.py` (click wiring); inline `kick_clients()` replaced by call into `NetcutAttack` (kills triple implementation with `tools/*`) | <400 each |
| `core/platform_interface.py` 711 | three platform classes + factory in one module | `core/platform/{linux,macos,windows}_interface.py` + `factory.py`; re-export from old path during transition | <350 each |
| `scanner/network_scanner.py` 673 | client scanning embedded | extract `scanner/client_scanner.py` (`scan_clients` + own-MAC helper shared with CLI — fixes `ifconfig` duplication too) | <400 |
| `tui.py` 632 | three screens + app | `tui/screens/{scan,attack_config,attack}.py` + `tui/app.py`; entry shim stays | <250 each |

Also delete in this phase: `IMonitor` (zero implementations — dead abstraction) and its
exports/docs references.

**Order within phase**: characterization-test parsers first (fixture outputs for
wdutil/airport/system_profiler samples), then extract, then re-run suite. Parser fixtures
double as permanent macOS regression corpus.

**Rollback**: each extraction is an independent commit (`refactor: extract X from Y`);
revert individually. Public entry points (`wifi_jammer.cli:cli`, `wifi_jammer.tui`,
`wifi_jammer.gui`) never move.

## Phase 3 — Architecture debt (small, independent commits)

1. `RichLogger`: guard against duplicate handlers (`if not self.logger.handlers:`); drop dual output path
2. `ChannelHopAttack._hop_channels_loop`: use `_set_channel()` instead of raw `iwconfig`
3. TUI: remove `time.sleep(2)` from button handler (UI-thread freeze)
4. `get_available_attacks()`: return sorted deterministic list
5. Portable own-MAC lookup in `platform_utils` (ip/ifconfig/netsh); replace both `ifconfig` parses
6. Move runtime writes out of package dir: `.python_with_permission` → `~/.config/wifi_jammer/`
7. Lazy global config (`config_manager` created on first access); scope warning suppression — no process-global suppression at import time
8. Lock around `AttackStats` mutations (EvilTwin's two threads race it)
9. `modern_crypto.py`: decide keep-as-demo vs delete; if kept, no env-var mutation at import

**Rollback**: trivially independent; none touch public API.

## Phase 4 — Packaging / CI / docs hygiene

1. `PyQt6` + `textual` → optional extras `[gui]`, `[tui]`; core deps stay lean
2. Delete `setup.py`; single version source (`importlib.metadata`), fix `make bump`
3. Makefile: remove duplicate `release` target; fix broken `run-scan` (`--scan-only` doesn't exist)
4. Branding/version sync: banner "By Paijo - v1.0.0" → v2.x; README badge 3.8+ → 3.9+
5. Consolidate `tools/netcut.py` + `tools/kick_clients.py` into package CLI (Phase 2.2 does most); mark tools copies deprecated → delete
6. Sync docs: CODEBASE.md structure tables, README architecture tree post-split
7. Coverage gate ratchet +5pp per sprint until ≥60% (TUI via Textual Pilot harness)

**Rollback**: packaging changes tagged separately; PyPI release only after full battery.

## Phase 5 — Final verification battery (definition of done)

```bash
pytest tests/ -v --cov=wifi_jammer --cov-report=term   # all pass, coverage ≥ gate
mypy --strict wifi_jammer/                              # clean
flake8 wifi_jammer/ --max-module-lines=900              # clean
wc -l wifi_jammer/**/*.py | sort -rn | head -1          # max < 500
sudo wifi-jammer scan -i <iface>                        # real-user smoke (Rule 6)
```

Plus: PMKID attack actually invokes sniffer (unit-proven), interactive count/delay
preserved (unit-proven), `wlp*` detection (unit-proven). Every completion claim carries a
literal receipt per AGENTS.md Rule 2.

## Sequencing & risk

```
P0 guardrails ──► P1 bugs ──► P2 splits ──► P3 debt ──► P4 packaging ──► P5 verify
   (no behavior)   (tests)    (behavior-neutral,   (independent)   (release-facing)
                                fixture-covered)
```

- Biggest risk: Phase 2 macos_scanner extraction (untestable-on-Linux paths).
  Mitigation: parser fixtures captured BEFORE touching code; facade keeps API stable.
- Second risk: packaging extras break existing installs. Mitigation: keep `all` extra
  equivalent to today's default; document migration in README.
- Bus factor 1: every phase lands as self-contained reviewed-by-tests commits; no
  cross-phase coupling, so any phase can be abandoned without orphaning others.
