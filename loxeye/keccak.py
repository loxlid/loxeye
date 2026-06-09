"""Pure-Python Keccak-256 (Ethereum variant).

No third-party deps. Implements the Keccak-f[1600] permutation with the
original Keccak padding (0x01 ... 0x80), which is what Ethereum uses
(NOT the NIST SHA3 0x06 padding).

Validated against known test vectors in tests/test_keccak.py.
"""
from __future__ import annotations

_RHO = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
]
_PI = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
]
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_MASK = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state: list[int]) -> None:
    for rnd in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                state[x + y] ^= d[x]
        # Rho + Pi
        t = state[1]
        for i in range(24):
            j = _PI[i]
            state[j], t = _rol(t, _RHO[i]), state[j]
        # Chi
        for y in range(0, 25, 5):
            row = state[y:y + 5]
            for x in range(5):
                state[y + x] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        # Iota
        state[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of *data*."""
    rate = 136  # 1088 bits for 256-bit output
    state = [0] * 25
    # Absorb
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i] ^= lane
        _keccak_f(state)
    # Squeeze (one block is enough for 32 bytes)
    out = bytearray()
    for i in range(rate // 8):
        out += state[i].to_bytes(8, "little")
        if len(out) >= 32:
            break
    return bytes(out[:32])


def keccak256_hex(data: bytes) -> str:
    return keccak256(data).hex()
