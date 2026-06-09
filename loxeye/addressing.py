"""Contract address prediction + vanity scoring.

CREATE  : address = keccak(rlp([sender, nonce]))[12:]
CREATE2 : address = keccak(0xff ++ sender ++ salt ++ keccak(init_code))[12:]

Includes a minimal RLP encoder (enough for [address, nonce]) so there are
no external dependencies. Validated against known vectors in the tests.
"""
from __future__ import annotations

from .keccak import keccak256
from .crypto_utils import is_hex_address, to_checksum_address


def _addr_bytes(addr: str) -> bytes:
    if not is_hex_address(addr):
        raise ValueError(f"bad address {addr!r}")
    h = addr[2:] if addr.startswith(("0x", "0X")) else addr
    return bytes.fromhex(h.lower())


def _int_to_minimal_bytes(n: int) -> bytes:
    if n == 0:
        return b""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _rlp_encode_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    length_bytes = _int_to_minimal_bytes(len(b))
    return bytes([0xB7 + len(length_bytes)]) + length_bytes + b


def _rlp_encode_list(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    length_bytes = _int_to_minimal_bytes(len(payload))
    return bytes([0xF7 + len(length_bytes)]) + length_bytes + payload


def create_address(deployer: str, nonce: int) -> str:
    """Address a contract deployed via CREATE from `deployer` at `nonce`."""
    enc = _rlp_encode_list([
        _rlp_encode_bytes(_addr_bytes(deployer)),
        _rlp_encode_bytes(_int_to_minimal_bytes(int(nonce))),
    ])
    digest = keccak256(enc)
    return to_checksum_address("0x" + digest[12:].hex())


def create2_address(deployer: str, salt, init_code) -> str:
    """Address a contract deployed via CREATE2.

    `salt` may be int or 0x-hex (32 bytes). `init_code` is the deployment
    bytecode (hex string or bytes).
    """
    if isinstance(salt, int):
        salt_b = salt.to_bytes(32, "big")
    else:
        s = salt[2:] if str(salt).startswith("0x") else str(salt)
        salt_b = bytes.fromhex(s).rjust(32, b"\x00")
    if isinstance(init_code, bytes):
        code_b = init_code
    else:
        c = init_code[2:] if init_code.startswith("0x") else init_code
        code_b = bytes.fromhex(c)
    code_hash = keccak256(code_b)
    pre = b"\xff" + _addr_bytes(deployer) + salt_b + code_hash
    return to_checksum_address("0x" + keccak256(pre)[12:].hex())


def vanity_score(addr: str) -> dict:
    """Score how 'vanity' an address looks: leading/trailing zero nibbles & repeats."""
    h = (addr[2:] if addr.startswith(("0x", "0X")) else addr).lower()
    lead_zero = len(h) - len(h.lstrip("0"))
    trail_zero = len(h) - len(h.rstrip("0"))
    # longest leading repeat of any single nibble
    lead_repeat = 1
    for c in h[1:]:
        if c == h[0]:
            lead_repeat += 1
        else:
            break
    return {
        "address": to_checksum_address(addr),
        "leading_zero_nibbles": lead_zero,
        "trailing_zero_nibbles": trail_zero,
        "leading_repeat": lead_repeat,
        "gas_saving_zero_bytes": lead_zero // 2,  # cheaper to store/call
    }
