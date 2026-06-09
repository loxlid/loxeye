"""Tool registry: every callable loxeye feature, grouped, with metadata.

A "tool" is a small function with a stable name, a help string, and a group.
The CLI dispatches by name. Keeping them in one registry makes it trivial to
list everything and to keep the count honest.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import crypto_utils as C
from . import static_analysis as S
from . import bytecode as B
from . import onchain as O


@dataclass
class Tool:
    name: str
    group: str
    help: str
    needs_rpc: bool
    fn: Callable

    def __call__(self, *a, **k):
        return self.fn(*a, **k)


REGISTRY: dict[str, Tool] = {}


def tool(name, group, help, needs_rpc=False):
    def deco(fn):
        REGISTRY[name] = Tool(name, group, help, needs_rpc, fn)
        return fn
    return deco


# ── group: crypto / encoding ────────────────────────────────────────────────
@tool("keccak", "crypto", "Keccak-256 of a UTF-8 string")
def t_keccak(text): return C.keccak_text(text)


@tool("selector", "crypto", "4-byte function selector from a signature")
def t_selector(sig): return C.function_selector(sig)


@tool("topic", "crypto", "Event topic0 hash from an event signature")
def t_topic(sig): return C.event_topic(sig)


@tool("checksum", "crypto", "EIP-55 checksum an address")
def t_checksum(addr): return C.to_checksum_address(addr)


@tool("verify-checksum", "crypto", "Verify an address is correctly EIP-55 checksummed")
def t_verify_checksum(addr): return C.check_address_checksum(addr)


@tool("is-address", "crypto", "Validate a 20-byte hex address")
def t_is_address(addr): return C.is_hex_address(addr)


@tool("to-wei", "crypto", "Convert an amount in <unit> to wei")
def t_to_wei(amount, unit="ether"): return C.to_wei(amount, unit)


@tool("from-wei", "crypto", "Convert wei to <unit>")
def t_from_wei(wei, unit="ether"): return C.from_wei(int(wei), unit)


@tool("encode-call", "crypto", "ABI-encode calldata for a simple signature + args")
def t_encode_call(sig, *args): return C.encode_call(sig, *args)


# ── group: static analysis ──────────────────────────────────────────────────
@tool("scan", "static", "Run all Solidity vulnerability detectors on a file")
def t_scan(path, min_severity="info"):
    return [f.as_dict() for f in S.analyze_file(path, min_severity)]


@tool("scan-src", "static", "Run detectors on a Solidity source string")
def t_scan_src(src, min_severity="info"):
    return [f.as_dict() for f in S.analyze_source(src, min_severity)]


@tool("scan-summary", "static", "Severity counts for a Solidity file")
def t_scan_summary(path):
    return S.summarize(S.analyze_file(path))


@tool("list-detectors", "static", "List every vulnerability detector available")
def t_list_detectors():
    return [d.__name__.replace("d_", "") for d in S.DETECTORS]


def _single_detector(name):
    def runner(path):
        target = "d_" + name.replace("-", "_")
        det = next((d for d in S.DETECTORS if d.__name__ == target), None)
        if det is None:
            raise ValueError(f"no detector {name!r}")
        lines = S._strip_comments(open(path, encoding="utf-8", errors="replace").read())
        return [f.as_dict() for f in det(lines)]
    return runner


# expose a few high-value detectors as standalone tools
for _det, _grp_help in [
    ("reentrancy", "Detect state-write-after-external-call reentrancy"),
    ("tx-origin-auth", "Detect tx.origin used for authorization"),
    ("delegatecall", "Detect delegatecall to external input"),
    ("selfdestruct", "Detect selfdestruct usage"),
    ("weak-randomness", "Detect on-chain randomness from block fields"),
    ("unchecked-call", "Detect unchecked low-level call returns"),
]:
    REGISTRY[f"check-{_det}"] = Tool(
        f"check-{_det}", "static", _grp_help, False, _single_detector(_det))


# ── group: bytecode ─────────────────────────────────────────────────────────
@tool("disasm", "bytecode", "Disassemble EVM bytecode (hex) to opcodes")
def t_disasm(code): return [str(i) for i in B.disassemble(code)]


@tool("selectors-from-code", "bytecode", "Recover function selectors from bytecode")
def t_selectors_code(code): return B.extract_selectors(code)


@tool("strip-metadata", "bytecode", "Split runtime code from CBOR metadata trailer")
def t_strip_meta(code):
    rt, meta = B.strip_metadata(code)
    return {"runtime": "0x" + rt, "metadata": "0x" + meta}


@tool("opcode-histogram", "bytecode", "Opcode frequency histogram for bytecode")
def t_hist(code): return B.opcode_histogram(code)


@tool("dangerous-opcodes", "bytecode", "List DELEGATECALL/SELFDESTRUCT/CREATE2 in bytecode")
def t_danger(code): return [str(i) for i in B.find_dangerous_opcodes(code)]


@tool("is-proxy-code", "bytecode", "Heuristic: does bytecode use delegatecall (proxy)?")
def t_is_proxy_code(code): return B.is_likely_proxy(code)


# ── group: on-chain (need --rpc) ────────────────────────────────────────────
@tool("chain-id", "onchain", "Get the chain id from an RPC", needs_rpc=True)
def t_chain_id(rpc): return O.RpcClient(rpc).chain_id()


@tool("block-number", "onchain", "Latest block number", needs_rpc=True)
def t_block_number(rpc): return O.RpcClient(rpc).block_number()


@tool("get-code", "onchain", "Fetch deployed bytecode of an address", needs_rpc=True)
def t_get_code(rpc, addr): return O.RpcClient(rpc).get_code(addr)


@tool("get-balance", "onchain", "ETH balance (wei) of an address", needs_rpc=True)
def t_get_balance(rpc, addr): return O.RpcClient(rpc).get_balance(addr)


@tool("is-contract", "onchain", "Is the address a contract?", needs_rpc=True)
def t_is_contract(rpc, addr): return O.RpcClient(rpc).is_contract(addr)


@tool("detect-proxy", "onchain", "Read EIP-1967 slots to detect proxy + impl", needs_rpc=True)
def t_detect_proxy(rpc, addr): return O.RpcClient(rpc).detect_proxy(addr)


@tool("read-owner", "onchain", "Probe owner()/admin() ownership getters", needs_rpc=True)
def t_read_owner(rpc, addr): return O.RpcClient(rpc).read_owner(addr)


@tool("token-standard", "onchain", "Detect ERC-721/1155 via ERC-165", needs_rpc=True)
def t_token_standard(rpc, addr): return O.RpcClient(rpc).detect_token_standard(addr)


@tool("read-storage", "onchain", "Read a raw storage slot", needs_rpc=True)
def t_read_storage(rpc, addr, slot): return O.RpcClient(rpc).get_storage_at(addr, slot)


@tool("allowance", "onchain", "ERC-20 allowance + risk classification", needs_rpc=True)
def t_allowance(rpc, token, owner, spender):
    v = O.RpcClient(rpc).erc20_allowance(token, owner, spender)
    return {"allowance": v, "class": O.classify_allowance(v)}


def groups() -> dict:
    g = {}
    for t in REGISTRY.values():
        g.setdefault(t.group, []).append(t.name)
    return g


def tool_count() -> int:
    return len(REGISTRY)
