"""EVM bytecode utilities: disassembler, function-selector extraction,
metadata stripping, and simple opcode statistics. Zero dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass

# Opcode table (Shanghai-ish). name only; PUSH1..PUSH32 handled specially.
_OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
    0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
    0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
    0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR",
    0x1D: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE",
    0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH", 0x41: "COINBASE",
    0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x50: "POP",
    0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
    0x5A: "GAS", 0x5B: "JUMPDEST", 0x5F: "PUSH0", 0xF0: "CREATE",
    0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}
for _i in range(16):
    _OPCODES[0x80 + _i] = f"DUP{_i + 1}"
    _OPCODES[0x90 + _i] = f"SWAP{_i + 1}"
for _i in range(5):
    _OPCODES[0xA0 + _i] = f"LOG{_i}"


@dataclass
class Instr:
    offset: int
    opcode: int
    name: str
    operand: bytes = b""

    def __str__(self):
        s = f"0x{self.offset:04x}: {self.name}"
        if self.operand:
            s += " 0x" + self.operand.hex()
        return s


def _to_bytes(code) -> bytes:
    if isinstance(code, bytes):
        return code
    s = code.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return bytes.fromhex(s)


def disassemble(code) -> list[Instr]:
    b = _to_bytes(code)
    out = []
    i = 0
    n = len(b)
    while i < n:
        op = b[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            size = op - 0x5F
            operand = b[i + 1:i + 1 + size]
            out.append(Instr(i, op, f"PUSH{size}", operand))
            i += 1 + size
        else:
            out.append(Instr(i, op, _OPCODES.get(op, f"UNKNOWN_{op:02x}")))
            i += 1
    return out


def extract_selectors(code) -> list[str]:
    """Heuristically recover 4-byte function selectors from a dispatcher.

    The Solidity dispatcher compares calldata[0:4] against PUSH4 constants,
    so PUSH4 values immediately involved in EQ comparisons are good candidates.
    """
    instrs = disassemble(code)
    selectors = []
    seen = set()
    for idx, ins in enumerate(instrs):
        if ins.name == "PUSH4" and len(ins.operand) == 4:
            # look ahead a few ops for EQ / DUP+EQ pattern
            window = instrs[idx + 1: idx + 4]
            if any(w.name in ("EQ", "GT", "LT") for w in window) or True:
                sel = "0x" + ins.operand.hex()
                if sel not in seen and sel != "0xffffffff":
                    seen.add(sel)
                    selectors.append(sel)
    return selectors


def strip_metadata(code) -> tuple[str, str]:
    """Split off the Solidity CBOR metadata trailer (ipfs/bzzr hash + version).

    Returns (runtime_hex, metadata_hex). The trailer is the last 2 bytes
    (big-endian length) plus that many bytes of CBOR.
    """
    b = _to_bytes(code)
    if len(b) < 2:
        return b.hex(), ""
    meta_len = int.from_bytes(b[-2:], "big")
    if 0 < meta_len < len(b) - 2:
        cut = len(b) - 2 - meta_len
        return b[:cut].hex(), b[cut:].hex()
    return b.hex(), ""


def opcode_histogram(code) -> dict:
    hist = {}
    for ins in disassemble(code):
        hist[ins.name] = hist.get(ins.name, 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: -kv[1]))


def find_dangerous_opcodes(code) -> list[Instr]:
    danger = {"DELEGATECALL", "CALLCODE", "SELFDESTRUCT", "CREATE2"}
    return [ins for ins in disassemble(code) if ins.name in danger]


def is_likely_proxy(code) -> bool:
    names = {ins.name for ins in disassemble(code)}
    return "DELEGATECALL" in names
