"""Crypto / encoding utilities built on the validated keccak256."""
from __future__ import annotations

from .keccak import keccak256, keccak256_hex


def is_hex_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr[2:] if addr.startswith(("0x", "0X")) else addr
    return len(a) == 40 and all(c in "0123456789abcdefABCDEF" for c in a)


def to_checksum_address(addr: str) -> str:
    """EIP-55 checksummed address."""
    if not is_hex_address(addr):
        raise ValueError(f"not a valid 20-byte hex address: {addr!r}")
    a = addr[2:].lower() if addr.startswith(("0x", "0X")) else addr.lower()
    h = keccak256_hex(a.encode())
    out = "0x"
    for i, ch in enumerate(a):
        if ch in "0123456789":
            out += ch
        else:
            out += ch.upper() if int(h[i], 16) >= 8 else ch
    return out


def check_address_checksum(addr: str) -> bool:
    """True if *addr* is already correctly EIP-55 checksummed."""
    if not is_hex_address(addr):
        return False
    body = addr[2:] if addr.startswith(("0x", "0X")) else addr
    if body == body.lower() or body == body.upper():
        return False  # not mixed-case => not a checksum address
    return to_checksum_address(addr) == ("0x" + body)


def function_selector(signature: str) -> str:
    """4-byte selector for a function signature, e.g. 'transfer(address,uint256)'."""
    sig = signature.replace(" ", "")
    return "0x" + keccak256_hex(sig.encode())[:8]


def event_topic(signature: str) -> str:
    """32-byte topic0 for an event signature."""
    sig = signature.replace(" ", "")
    return "0x" + keccak256_hex(sig.encode())


# ---- unit conversion --------------------------------------------------------
_UNITS = {
    "wei": 0, "kwei": 3, "mwei": 6, "gwei": 9,
    "szabo": 12, "finney": 15, "ether": 18,
}


def to_wei(amount, unit: str = "ether") -> int:
    unit = unit.lower()
    if unit not in _UNITS:
        raise ValueError(f"unknown unit {unit!r}")
    factor = 10 ** _UNITS[unit]
    if isinstance(amount, str):
        if "." in amount:
            whole, frac = amount.split(".", 1)
        else:
            whole, frac = amount, ""
        frac = (frac + "0" * _UNITS[unit])[: _UNITS[unit]]
        return int(whole or "0") * factor + (int(frac) if frac else 0)
    return int(amount * factor)


def from_wei(wei: int, unit: str = "ether") -> str:
    unit = unit.lower()
    if unit not in _UNITS:
        raise ValueError(f"unknown unit {unit!r}")
    factor = 10 ** _UNITS[unit]
    whole, frac = divmod(int(wei), factor)
    if _UNITS[unit] == 0:
        return str(whole)
    s = f"{frac:0{_UNITS[unit]}d}".rstrip("0")
    return f"{whole}.{s}" if s else str(whole)


# ---- minimal ABI encoding (static head types) ------------------------------
def encode_uint256(value: int) -> bytes:
    if value < 0:
        value &= (1 << 256) - 1
    return value.to_bytes(32, "big")


def encode_address(addr: str) -> bytes:
    if not is_hex_address(addr):
        raise ValueError(f"bad address {addr!r}")
    body = addr[2:] if addr.startswith(("0x", "0X")) else addr
    return bytes(12) + bytes.fromhex(body.lower())


def encode_call(signature: str, *args) -> str:
    """Encode a calldata string for simple (address/uint) signatures.

    Supports static head types address and uint*/int*; enough for the most
    common ERC-20/721 read calls (balanceOf, allowance, ownerOf, ...).
    """
    sel = function_selector(signature)
    inner = signature[signature.index("(") + 1: signature.rindex(")")]
    types = [t for t in inner.split(",") if t] if inner else []
    if len(types) != len(args):
        raise ValueError(f"signature expects {len(types)} args, got {len(args)}")
    body = b""
    for t, a in zip(types, args):
        if t == "address":
            body += encode_address(a)
        elif t.startswith(("uint", "int")) or t == "bool":
            body += encode_uint256(int(a))
        else:
            raise ValueError(f"unsupported abi type for encode_call: {t}")
    return sel + body.hex()


def keccak_text(text: str) -> str:
    return "0x" + keccak256_hex(text.encode())
