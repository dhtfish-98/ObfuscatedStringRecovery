"""Command-line entry point for the static scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import BudgetExceeded, InputRejected, Limits, scan_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover bounded stack strings from ELF64 x86-64 objects")
    parser.add_argument("object", type=Path, help="ELF64 x86-64 relocatable object to inspect")
    parser.add_argument("--max-instructions", type=int, default=4096)
    parser.add_argument("--max-wall-ms", type=int, default=500)
    args = parser.parse_args()
    try:
        limits = Limits(max_instructions=args.max_instructions, max_wall_ms=args.max_wall_ms)
        result = scan_path(args.object, limits)
    except BudgetExceeded as exc:
        print(json.dumps({"status": "BUDGET_EXCEEDED", "reason": str(exc)}, sort_keys=True))
        return 3
    except (InputRejected, ValueError, OSError) as exc:
        print(json.dumps({"status": "REJECTED_INPUT", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
