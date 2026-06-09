"""Command-line interface for loxeye.

Usage:
    python -m loxeye list
    python -m loxeye help <tool>
    python -m loxeye run <tool> [args...] [--rpc URL] [--json]

Examples:
    python -m loxeye run selector "transfer(address,uint256)"
    python -m loxeye run checksum 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed
    python -m loxeye run scan examples/Vulnerable.sol --json
    python -m loxeye run detect-proxy 0xADDR --rpc https://rpc.example
"""
from __future__ import annotations

import json
import sys

from .registry import REGISTRY, groups, tool_count


def _print_list():
    print(f"loxeye — {tool_count()} tools\n")
    for g, names in groups().items():
        print(f"[{g}]")
        for n in names:
            t = REGISTRY[n]
            tag = " (needs --rpc)" if t.needs_rpc else ""
            print(f"  {n:24} {t.help}{tag}")
        print()


def _print_help(name):
    t = REGISTRY.get(name)
    if not t:
        print(f"unknown tool: {name}", file=sys.stderr)
        return 1
    print(f"{t.name}  [{t.group}]")
    print(f"  {t.help}")
    if t.needs_rpc:
        print("  requires: --rpc <URL> (passed as first argument)")
    return 0


def _emit(result, as_json):
    if as_json:
        print(json.dumps(result, indent=2, default=str))
    elif isinstance(result, list):
        for item in result:
            print(json.dumps(item, default=str) if isinstance(item, (dict, list)) else item)
    elif isinstance(result, dict):
        for k, v in result.items():
            print(f"{k}: {v}")
    else:
        print(result)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") and len(argv) == 1:
        _print_list()
        return 0
    cmd = argv[0]

    if cmd == "list":
        _print_list()
        return 0
    if cmd == "help":
        if len(argv) < 2:
            _print_list()
            return 0
        return _print_help(argv[1])
    if cmd != "run":
        print(f"unknown command: {cmd!r} (use list | help | run)", file=sys.stderr)
        return 2

    if len(argv) < 2:
        print("usage: run <tool> [args...]", file=sys.stderr)
        return 2

    name = argv[1]
    rest = argv[2:]

    as_json = "--json" in rest
    rest = [a for a in rest if a != "--json"]

    rpc = None
    if "--rpc" in rest:
        i = rest.index("--rpc")
        try:
            rpc = rest[i + 1]
        except IndexError:
            print("--rpc requires a URL", file=sys.stderr)
            return 2
        rest = rest[:i] + rest[i + 2:]

    tool = REGISTRY.get(name)
    if not tool:
        print(f"unknown tool: {name!r} (try `list`)", file=sys.stderr)
        return 2

    args = list(rest)
    if tool.needs_rpc:
        if not rpc:
            print(f"tool {name!r} needs --rpc <URL>", file=sys.stderr)
            return 2
        args = [rpc] + args

    try:
        result = tool(*args)
    except TypeError as e:
        print(f"argument error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    _emit(result, as_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
