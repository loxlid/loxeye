"""Calldata decoding + a small built-in 4-byte selector dictionary.

Decodes a raw calldata hex blob into selector + 32-byte words, and—when the
selector or an explicit signature is known—into typed arguments for the
common static head types (address, uint*, int*, bool, bytes32).
"""
from __future__ import annotations

from .crypto_utils import function_selector, to_checksum_address

# Common selectors so decoding works offline without a 4byte API.
KNOWN_SELECTORS = {}
for _sig in [
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
    "approve(address,uint256)",
    "balanceOf(address)",
    "allowance(address,address)",
    "totalSupply()",
    "name()", "symbol()", "decimals()",
    "owner()", "transferOwnership(address)", "renounceOwnership()",
    "mint(address,uint256)", "burn(uint256)",
    "deposit()", "withdraw(uint256)",
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "safeTransferFrom(address,address,uint256)",
    "setApprovalForAll(address,bool)",
    "multicall(bytes[])",
    "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)",
    "initialize(address)",
    "execute(address,uint256,bytes)",
]:
    KNOWN_SELECTORS[function_selector(_sig)] = _sig


def _split_words(body: bytes) -> list[bytes]:
    return [body[i:i + 32] for i in range(0, len(body), 32)]


def _decode_word(word: bytes, typ: str):
    if typ == "address":
        return to_checksum_address("0x" + word[-20:].hex())
    if typ == "bool":
        return int.from_bytes(word, "big") != 0
    if typ.startswith("uint"):
        return int.from_bytes(word, "big")
    if typ.startswith("int"):
        v = int.from_bytes(word, "big")
        return v - (1 << 256) if v >= (1 << 255) else v
    if typ.startswith("bytes"):
        return "0x" + word.hex()
    return "0x" + word.hex()


def decode_calldata(calldata, signature: str | None = None) -> dict:
    s = calldata[2:] if calldata.startswith(("0x", "0X")) else calldata
    raw = bytes.fromhex(s)
    if len(raw) < 4:
        return {"selector": "0x" + raw.hex(), "known": None, "words": [], "args": None}
    selector = "0x" + raw[:4].hex()
    body = raw[4:]
    words = ["0x" + w.hex() for w in _split_words(body)]
    sig = signature or KNOWN_SELECTORS.get(selector)
    out = {"selector": selector, "known": sig, "word_count": len(words), "words": words}
    if sig and "(" in sig:
        inner = sig[sig.index("(") + 1: sig.rindex(")")]
        types = [t for t in inner.split(",") if t]
        # only decode if all types are static head types we understand
        decodable = all(
            t == "address" or t == "bool" or t.startswith(("uint", "int", "bytes32"))
            for t in types
        )
        if decodable and len(types) <= len(_split_words(body)):
            wlist = _split_words(body)
            out["args"] = [
                {"type": t, "value": _decode_word(wlist[i], t)}
                for i, t in enumerate(types)
            ]
    return out


def identify_selector(selector: str) -> str | None:
    sel = selector if selector.startswith("0x") else "0x" + selector
    return KNOWN_SELECTORS.get(sel.lower())
