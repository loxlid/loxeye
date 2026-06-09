"""Heuristic static analysis for Solidity source.

This is a regex/line based linter for common smart-contract vulnerability
patterns. It is NOT a substitute for a full AST analyzer (slither) or formal
verification, but it catches the most common foot-guns fast and with zero
external dependencies.

Each detector returns a list of Finding objects with severity + line number.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    detector: str
    severity: str
    title: str
    line: int
    snippet: str
    advice: str

    def as_dict(self):
        return asdict(self)


def _strip_comments(src: str) -> list[str]:
    """Return source lines with // and /* */ comments blanked (line count kept)."""
    out = []
    in_block = False
    for line in src.splitlines():
        res = []
        i = 0
        while i < len(line):
            two = line[i:i + 2]
            if in_block:
                if two == "*/":
                    in_block = False
                    i += 2
                    continue
                i += 1
                continue
            if two == "//":
                break
            if two == "/*":
                in_block = True
                i += 2
                continue
            res.append(line[i])
            i += 1
        out.append("".join(res))
    return out


def _iter(lines):
    for idx, line in enumerate(lines, 1):
        yield idx, line


# ---- individual detectors ---------------------------------------------------
def d_pragma_unlocked(lines):
    f = []
    for i, l in _iter(lines):
        m = re.search(r"pragma\s+solidity\s+([^;]+);", l)
        if m and ("^" in m.group(1) or ">" in m.group(1)):
            f.append(Finding("pragma-unlocked", "low", "Floating/unlocked pragma",
                             i, l.strip(), "Pin an exact compiler version (e.g. pragma solidity 0.8.24;)."))
    return f


def d_tx_origin(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\btx\.origin\b", l):
            f.append(Finding("tx-origin-auth", "high", "Use of tx.origin",
                             i, l.strip(), "tx.origin enables phishing; use msg.sender for auth."))
    return f


def d_reentrancy(lines):
    """External call followed by a state write in the same function => possible reentrancy."""
    f = []
    call_re = re.compile(r"\.(call|delegatecall)\s*[\({]|\.call\{value")
    transfer_value = re.compile(r"\.(call)\{value\s*:")
    state_write = re.compile(r"^\s*[\w\.\[\]]+\s*[-+]?=(?!=)")
    depth = 0
    pending_call = None
    for i, l in _iter(lines):
        depth += l.count("{") - l.count("}")
        if call_re.search(l) or transfer_value.search(l):
            pending_call = i
        elif pending_call and state_write.search(l):
            f.append(Finding("reentrancy", "high", "State write after external call",
                             i, l.strip(),
                             "Apply checks-effects-interactions or a nonReentrant guard. "
                             f"External call at line {pending_call}."))
            pending_call = None
        if depth <= 0:
            pending_call = None
    return f


def d_low_level_call_unchecked(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\.call\s*\{?.*\}?\s*\(", l) and "=" not in l and "require" not in l:
            f.append(Finding("unchecked-call", "medium", "Unchecked low-level call return",
                             i, l.strip(), "Check the boolean success return of .call()."))
    return f


def d_selfdestruct(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\b(selfdestruct|suicide)\s*\(", l):
            f.append(Finding("selfdestruct", "high", "selfdestruct present",
                             i, l.strip(), "selfdestruct can forcibly remove the contract; gate it tightly."))
    return f


def d_delegatecall(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\.delegatecall\s*\(", l):
            f.append(Finding("delegatecall", "high", "delegatecall to external input",
                             i, l.strip(), "delegatecall runs foreign code in this context; validate target."))
    return f


def d_block_timestamp(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\b(block\.timestamp|now)\b", l):
            f.append(Finding("timestamp-dep", "low", "Block timestamp dependence",
                             i, l.strip(), "Miners can nudge block.timestamp; avoid for randomness/critical logic."))
    return f


def d_weak_randomness(lines):
    f = []
    pat = re.compile(r"(blockhash|block\.(difficulty|prevrandao|timestamp|number|coinbase|gaslimit))")
    for i, l in _iter(lines):
        if "random" in l.lower() and pat.search(l) or (pat.search(l) and "keccak256" in l):
            f.append(Finding("weak-randomness", "high", "On-chain randomness from block fields",
                             i, l.strip(), "Predictable; use a VRF (e.g. Chainlink VRF) for randomness."))
    return f


def d_unchecked_transfer(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\.(transfer|transferFrom)\s*\(", l) and "require" not in l and "=" not in l \
                and "safeTransfer" not in l and "payable" not in l:
            f.append(Finding("unchecked-erc20", "medium", "Unchecked ERC20 transfer return",
                             i, l.strip(), "Some tokens return false; use SafeERC20 or check the return value."))
    return f


def d_public_default_visibility(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\bfunction\s+\w+\s*\([^)]*\)\s*(\{|$)", l) and \
           not re.search(r"\b(public|private|internal|external)\b", l):
            f.append(Finding("missing-visibility", "medium", "Function missing explicit visibility",
                             i, l.strip(), "Declare visibility explicitly (external/public/internal/private)."))
    return f


def d_arbitrary_send(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\.(transfer|send)\s*\(", l) and re.search(r"(msg\.sender|to|recipient|dest)", l):
            f.append(Finding("ether-send", "info", "Ether send to a variable destination",
                             i, l.strip(), "Confirm destination is access-controlled and trusted."))
    return f


def d_assembly(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\bassembly\b", l):
            f.append(Finding("inline-assembly", "low", "Inline assembly block",
                             i, l.strip(), "Assembly bypasses Solidity safety checks; review carefully."))
    return f


def d_deprecated(lines):
    f = []
    pats = {"sha3": "use keccak256", "suicide": "use selfdestruct",
            "throw": "use revert()", "var ": "use explicit types",
            "callcode": "removed; use delegatecall", "constant": "use view/pure for functions"}
    for i, l in _iter(lines):
        for kw, adv in pats.items():
            if re.search(r"\b" + re.escape(kw.strip()) + r"\b", l):
                f.append(Finding("deprecated", "low", f"Deprecated construct: {kw.strip()}",
                                 i, l.strip(), adv))
    return f


def d_dangerous_unary(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"=\s*[\+\-]=", l) or re.search(r"[\w\]]\s*=-\s*\w", l):
            f.append(Finding("typo-unary", "medium", "Suspicious =+ / =- (typo for += / -=?)",
                             i, l.strip(), "'=-' assigns the negation; did you mean '-='?"))
    return f


def d_unprotected_init(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"function\s+initialize\s*\(", l) and "onlyOwner" not in l and "initializer" not in l:
            f.append(Finding("unprotected-init", "high", "Unprotected initialize()",
                             i, l.strip(), "Add the 'initializer' modifier; an open init can be hijacked."))
    return f


def d_missing_zero_check(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"function\s+\w*[Oo]wner\w*\s*\(\s*address", l) or \
           re.search(r"function\s+set\w*\s*\(\s*address\s+\w+\s*\)", l):
            f.append(Finding("zero-address", "low", "Setter takes address without obvious zero-check",
                             i, l.strip(), "Add require(addr != address(0)) where appropriate."))
    return f


def d_hardcoded_gas(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"\.gas\s*\(\s*\d+\s*\)", l) or re.search(r"\{\s*gas\s*:\s*\d+", l):
            f.append(Finding("hardcoded-gas", "low", "Hardcoded gas amount",
                             i, l.strip(), "Hardcoded gas breaks after opcode repricing; avoid."))
    return f


def d_strict_balance_eq(lines):
    f = []
    for i, l in _iter(lines):
        if re.search(r"(address\(this\)\.balance|\.balance)\s*==", l) or \
           re.search(r"==\s*address\(this\)\.balance", l):
            f.append(Finding("strict-balance", "medium", "Strict equality on contract balance",
                             i, l.strip(), "Forced ether (selfdestruct) breaks '== balance'; use >=."))
    return f


DETECTORS = [
    d_pragma_unlocked, d_tx_origin, d_reentrancy, d_low_level_call_unchecked,
    d_selfdestruct, d_delegatecall, d_block_timestamp, d_weak_randomness,
    d_unchecked_transfer, d_public_default_visibility, d_arbitrary_send,
    d_assembly, d_deprecated, d_dangerous_unary, d_unprotected_init,
    d_missing_zero_check, d_hardcoded_gas, d_strict_balance_eq,
]


def analyze_source(src: str, min_severity: str = "info") -> list[Finding]:
    lines = _strip_comments(src)
    findings: list[Finding] = []
    for det in DETECTORS:
        findings.extend(det(lines))
    threshold = SEVERITY_ORDER[min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))
    return findings


def analyze_file(path: str, min_severity: str = "info") -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return analyze_source(fh.read(), min_severity)


def summarize(findings: list[Finding]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts
