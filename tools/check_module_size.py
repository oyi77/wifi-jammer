#!/usr/bin/env python3
"""Module-size ratchet gate.

Project constraint: no Python source file may exceed 1000 lines (god-file ban),
working target <= 900. Files already over the limit when this gate was introduced
are listed in ``KNOWN_OFFENDERS`` with their size frozen as an allowance — they
may not grow. Shrinking an offender below the limit means deleting its entry,
which tightens the gate automatically. Any *new* offender fails immediately.
"""

import argparse
import sys
from pathlib import Path

HARD_LIMIT = 900

# rel-path -> frozen maximum while split debt is pending (delete entry once fixed)
KNOWN_OFFENDERS: dict = {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Module-size ratchet gate")
    parser.add_argument(
        "paths",
        nargs="*",
        default=["wifi_jammer"],
        help="directories to check (default: wifi_jammer)",
    )
    parser.add_argument(
        "--limit", type=int, default=HARD_LIMIT, help="max lines per module"
    )
    args = parser.parse_args()

    offenders = []
    for root in args.paths:
        base = Path(root)
        if not base.is_dir():
            print(f"error: not a directory: {root}")
            return 2
        for path in sorted(base.rglob("*.py")):
            rel = path.as_posix()
            lines = len(path.read_text(encoding="utf-8").splitlines())
            allowance = KNOWN_OFFENDERS.get(rel, args.limit)
            if lines > allowance:
                offenders.append((rel, lines))

    for rel, lines in offenders:
        print(f"FAIL {rel}: {lines} lines (limit {args.limit})")

    for rel in sorted(KNOWN_OFFENDERS):
        path = Path(rel)
        if path.exists():
            n = len(path.read_text(encoding="utf-8").splitlines())
            marker = "OK" if n <= args.limit else "DEBT"
            print(f"{marker} {rel}: {n} lines (tracked debt, frozen at "
                  f"{KNOWN_OFFENDERS[rel]})")
        else:
            del KNOWN_OFFENDERS[rel]
            print(f"CLEANUP {rel}: no longer exists — remove from KNOWN_OFFENDERS")

    if offenders:
        return 1
    print(f"OK: all modules within {args.limit}-line limit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
