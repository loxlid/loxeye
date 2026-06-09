"""Message-hashing + signature utilities (EIP-191 / EIP-712 / EIP-2098).

Computes the hashes you need before ecrecover, splits/normalizes signatures,
and flags malleable (high-s) signatures. Pure hashing — no secp256k1 signing,
so there are zero crypto dependencies. Validated against known vectors.
"""
from __future__ import annotations

from .keccak import keccak256
from .crypto_utils import is_hex_address

# secp256k1 curve order
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = SECP256K1_N // 2


def _to_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        if data.startswith(("0x", "0X")):
            return bytes.fromhex(data[2:])
        return data.encode()
    raise TypeError(type(data))


def eth_message_hash(message) -> str:
    """EIP-191 personal_sign hash: keccak('\\x19Ethereum Signed Message:\\n' + len + msg)."""
    msg = _to_bytes(message)
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode()
    return "0x" + keccak256(prefix + msg).hex()


def eip712_domain_separator(name: str, version: str, chain_id: int,
                            verifying_contract: str) -> str:
    """EIP-712 domainSeparator for the standard EIP712Domain type."""
    if not is_hex_address(verifying_contract):
        raise ValueError("verifying_contract must be an address")
    type_hash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    enc = (
        type_hash
        + keccak256(name.encode())
        + keccak256(version.encode())
        + chain_id.to_bytes(32, "big")
        + bytes.fromhex(verifying_contract[2:].lower()).rjust(32, b"\x00")
    )
    return "0x" + keccak256(enc).hex()


def eip712_typed_data_hash(domain_separator: str, struct_hash: str) -> str:
    """Final EIP-712 digest: keccak('\\x19\\x01' + domainSeparator + structHash)."""
    ds = _to_bytes(domain_separator)
    sh = _to_bytes(struct_hash)
    return "0x" + keccak256(b"\x19\x01" + ds + sh).hex()


def type_hash(type_string: str) -> str:
    """keccak of an EIP-712 type string e.g. 'Permit(address owner,...)'. """
    return "0x" + keccak256(type_string.encode()).hex()


def split_signature(sig) -> dict:
    """Split a 65-byte signature into r, s, v. Accepts 64-byte EIP-2098 compact too."""
    b = _to_bytes(sig)
    if len(b) == 65:
        r, s, v = b[:32], b[32:64], b[64]
    elif len(b) == 64:  # EIP-2098 compact
        r = b[:32]
        vs = b[32:64]
        s_int = int.from_bytes(vs, "big") & ((1 << 255) - 1)
        v = 27 + (vs[0] >> 7)
        s = s_int.to_bytes(32, "big")
        return {"r": "0x" + r.hex(), "s": "0x" + s.hex(), "v": v, "compact": True}
    else:
        raise ValueError(f"signature must be 64 or 65 bytes, got {len(b)}")
    if v < 27:
        v += 27
    return {"r": "0x" + r.hex(), "s": "0x" + s.hex(), "v": v, "compact": False}


def is_malleable(sig) -> dict:
    """True if signature s-value is in the upper half (high-s) => malleable.

    EIP-2 requires low-s; high-s lets an attacker forge a second valid sig
    for the same message (replay / double-spend foot-gun).
    """
    parts = split_signature(sig)
    s = int(parts["s"], 16)
    high = s > HALF_N
    return {
        "s": parts["s"],
        "high_s": high,
        "malleable": high,
        "advice": ("reject high-s signatures (enforce s <= N/2, EIP-2)"
                   if high else "low-s, ok"),
    }
