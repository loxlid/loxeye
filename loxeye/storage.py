"""Storage-slot math + gas heuristics.

Solidity storage layout helpers (mappings, dynamic arrays), plus a rough
bytecode gas-cost estimator and a proxy storage-collision checker. The slot
math matches the Solidity spec and is validated in the tests.
"""
from __future__ import annotations

from .keccak import keccak256
from .crypto_utils import is_hex_address


def _to_32(value) -> bytes:
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    s = str(value)
    if s.startswith(("0x", "0X")):
        h = s[2:]
        if is_hex_address(s):  # left-pad address to 32 bytes
            return bytes.fromhex(h.lower()).rjust(32, b"\x00")
        return bytes.fromhex(h).rjust(32, b"\x00")
    return int(s).to_bytes(32, "big")


def mapping_slot(key, slot: int) -> str:
    """Storage slot of mapping[key] declared at base `slot`.

    slot = keccak256(pad(key) ++ pad(slot))
    """
    pre = _to_32(key) + slot.to_bytes(32, "big")
    return "0x" + keccak256(pre).hex()


def nested_mapping_slot(keys: list, slot: int) -> str:
    """Slot for nested mapping[k1][k2]...; applies mapping_slot iteratively."""
    cur = slot
    for k in keys:
        h = mapping_slot(k, cur) if isinstance(cur, int) else _hash_at(k, cur)
        cur = int(h, 16)
    return "0x" + format(cur, "064x")


def _hash_at(key, slot_int: int) -> str:
    pre = _to_32(key) + slot_int.to_bytes(32, "big")
    return "0x" + keccak256(pre).hex()


def dynamic_array_slot(slot: int, index: int) -> str:
    """Storage slot of array[index] for a dynamic array declared at `slot`.

    base = keccak256(pad(slot)); element = base + index
    """
    base = int.from_bytes(keccak256(slot.to_bytes(32, "big")), "big")
    return "0x" + format(base + index, "064x")


def string_bytes_slot(slot: int) -> str:
    """Data slot for long string/bytes stored at `slot`."""
    base = int.from_bytes(keccak256(slot.to_bytes(32, "big")), "big")
    return "0x" + format(base, "064x")


# ---- gas heuristics ---------------------------------------------------------
# rough static gas per opcode (London-era), enough for relative comparison
_GAS = {
    "SSTORE": 20000, "SLOAD": 2100, "CALL": 2600, "DELEGATECALL": 2600,
    "STATICCALL": 2600, "CREATE": 32000, "CREATE2": 32000, "KECCAK256": 30,
    "BALANCE": 2600, "EXTCODESIZE": 2600, "EXTCODECOPY": 2600,
    "LOG0": 375, "LOG1": 750, "LOG2": 1125, "LOG3": 1500, "LOG4": 1875,
    "EXP": 50, "JUMPDEST": 1, "JUMP": 8, "JUMPI": 10,
}
_DEFAULT_GAS = 3


def estimate_bytecode_gas(code) -> dict:
    from .bytecode import disassemble
    total = 0
    hot = {}
    for ins in disassemble(code):
        g = _GAS.get(ins.name, _DEFAULT_GAS)
        total += g
        if ins.name in _GAS:
            hot[ins.name] = hot.get(ins.name, 0) + 1
    return {"static_gas_estimate": total, "expensive_ops": hot}


def calldata_gas(calldata) -> dict:
    """EIP-2028 calldata gas: 4 gas per zero byte, 16 per non-zero byte."""
    s = calldata[2:] if calldata.startswith(("0x", "0X")) else calldata
    raw = bytes.fromhex(s)
    zeros = sum(1 for b in raw if b == 0)
    nonzeros = len(raw) - zeros
    return {
        "bytes": len(raw),
        "zero_bytes": zeros,
        "nonzero_bytes": nonzeros,
        "calldata_gas": zeros * 4 + nonzeros * 16,
    }


def storage_collision_check(layout_a: list[str], layout_b: list[str]) -> list[dict]:
    """Compare two ordered storage layouts (proxy vs implementation).

    Each layout is a list of 'type name' strings in declaration order. Returns
    slots where the variable type differs — a classic proxy upgrade footgun.
    """
    issues = []
    for i in range(min(len(layout_a), len(layout_b))):
        ta = layout_a[i].split()[0] if layout_a[i] else ""
        tb = layout_b[i].split()[0] if layout_b[i] else ""
        if ta != tb:
            issues.append({
                "slot": i, "proxy": layout_a[i], "impl": layout_b[i],
                "issue": "type mismatch at same slot — storage collision risk",
            })
    if len(layout_a) != len(layout_b):
        issues.append({
            "slot": min(len(layout_a), len(layout_b)),
            "issue": f"layout length differs ({len(layout_a)} vs {len(layout_b)})",
        })
    return issues
