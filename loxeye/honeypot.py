"""Scam / rugpull / honeypot heuristics over Solidity source.

Pattern-based risk scoring for tokens. Flags the classic rug mechanics:
unlimited owner mint, blacklist/whitelist gating, trading on/off switches,
modifiable fees, hidden transfer restrictions, and ownership that is never
renounced. Heuristic only — high score == investigate, not proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

from .static_analysis import _strip_comments


@dataclass
class RiskFlag:
    name: str
    weight: int
    line: int
    evidence: str

    def as_dict(self):
        return asdict(self)


_RULES = [
    ("owner_can_mint", 25,
     re.compile(r"function\s+\w*[Mm]int\w*\s*\([^)]*\)[^{}]*\b(onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner)")),
    ("unbounded_mint", 20,
     re.compile(r"_mint\s*\(\s*\w+\s*,\s*\w+\s*\)")),
    ("blacklist", 20,
     re.compile(r"\b(blacklist|_blacklisted|isBlacklisted|denyList|_isBlocked)\b", re.I)),
    ("trading_switch", 18,
     re.compile(r"\b(tradingEnabled|tradingActive|tradingOpen|enableTrading|canTrade)\b", re.I)),
    ("mutable_fee", 15,
     re.compile(r"function\s+set\w*(Fee|Tax)\w*\s*\(", re.I)),
    ("high_fee_constant", 15,
     re.compile(r"\b(fee|tax)\w*\s*=\s*([2-9]\d|\d{3,})\b", re.I)),
    ("max_tx_limit", 12,
     re.compile(r"\b(maxTx|maxTransaction|maxWallet|_maxTxAmount)\b", re.I)),
    ("pausable_transfer", 12,
     re.compile(r"\b(whenNotPaused|_paused|pause\s*\()\b", re.I)),
    ("owner_withdraw_all", 18,
     re.compile(r"function\s+\w*([Ww]ithdraw|[Rr]escue|[Ss]weep)\w*\s*\([^)]*\)[^{}]*onlyOwner")),
    ("hidden_transfer_block", 22,
     re.compile(r"_(transfer|beforeTokenTransfer)\b[^{}]*require\s*\([^)]*(allow|trading|whitelist|black)", re.I)),
    ("self_destruct", 25,
     re.compile(r"\bselfdestruct\s*\(")),
    ("proxy_upgradeable", 10,
     re.compile(r"\b(upgradeTo|_authorizeUpgrade|UUPSUpgradeable|delegatecall)\b")),
    ("modifiable_router", 12,
     re.compile(r"function\s+set\w*(Router|Pair|Pool)\w*\s*\(", re.I)),
    ("balance_manipulation", 20,
     re.compile(r"_balances\s*\[\s*\w+\s*\]\s*=\s*(?!_balances)", )),
]


def scan_token(src: str) -> dict:
    lines = _strip_comments(src)
    flags: list[RiskFlag] = []
    for i, line in enumerate(lines, 1):
        for name, weight, pat in _RULES:
            if pat.search(line):
                flags.append(RiskFlag(name, weight, i, line.strip()[:120]))
    # ownership renounced?
    full = "\n".join(lines)
    renounced = bool(re.search(r"renounceOwnership", full))
    if not renounced and re.search(r"\bonlyOwner\b", full):
        flags.append(RiskFlag("owner_never_renounced", 10, 0,
                              "onlyOwner present, no renounceOwnership found"))

    score = min(100, sum(f.weight for f in flags))
    level = ("CRITICAL" if score >= 70 else "HIGH" if score >= 45
             else "MEDIUM" if score >= 20 else "LOW")
    return {
        "risk_score": score,
        "risk_level": level,
        "flag_count": len(flags),
        "flags": [f.as_dict() for f in flags],
    }


def scan_token_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return scan_token(fh.read())
