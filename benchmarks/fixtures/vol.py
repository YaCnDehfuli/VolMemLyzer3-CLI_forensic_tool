#!/usr/bin/env python3
"""Volatility 3 stand-in for CI. Writes a one-row JSON list and sleeps.

Used only by `benchmarks/run_benchmark.py --ci`. Not a substitute for vol.
"""
from __future__ import annotations

import json
import os
import sys
import time

# Names VolRunner.list_plugins() accepts (lines starting with windows.).
# Keep in sync with PINNED_PLUGINS in benchmarks/run_benchmark.py.
CATALOGUE = [
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.dlllist.DllList",
    "windows.cmdline.CmdLine",
    "windows.registry.hivelist.HiveList",
    "windows.modules.Modules",
    "windows.svcscan.SvcScan",
    "windows.getsids.GetSIDs",
    "windows.privileges.Privs",
    "windows.envars.Envars",
]


def _help() -> int:
    print("Volatility 3 Framework 0.0.0-ci-stub")
    print()
    for name in CATALOGUE:
        print(f"    {name}")
    return 0


def _plugin_arg(argv: list[str]) -> str:
    for tok in reversed(argv):
        if tok.startswith("-"):
            continue
        if tok in ("-f", "-r", "-s", "-o", "-p", "-c", "-e", "-l", "-u"):
            continue
        return tok
    return "windows.info.Info"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        return _help()
    delay = float(os.environ.get("VOL_STUB_SLEEP", "0.12"))
    time.sleep(max(0.0, delay))
    print("Volatility 3 Framework 0.0.0-ci-stub", file=sys.stderr)
    json.dump([{"plugin": _plugin_arg(argv), "ok": True}], sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
