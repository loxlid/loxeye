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
from . import addressing as A
from . import calldata as CD
from . import storage as ST
from . import honeypot as H
from . import signatures as SIG


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


def _single_detector(func_name):
    def runner(path):
        det = next((d for d in S.DETECTORS if d.__name__ == func_name), None)
        if det is None:
            raise ValueError(f"no detector {func_name!r}")
        lines = S._strip_comments(open(path, encoding="utf-8", errors="replace").read())
        return [f.as_dict() for f in det(lines)]
    return runner


# expose a few high-value detectors as standalone tools.
# tuple = (cli-suffix, detector-function-name, help)
for _det, _fn, _grp_help in [
    ("reentrancy", "d_reentrancy", "Detect state-write-after-external-call reentrancy"),
    ("tx-origin-auth", "d_tx_origin", "Detect tx.origin used for authorization"),
    ("delegatecall", "d_delegatecall", "Detect delegatecall to external input"),
    ("selfdestruct", "d_selfdestruct", "Detect selfdestruct usage"),
    ("weak-randomness", "d_weak_randomness", "Detect on-chain randomness from block fields"),
    ("unchecked-call", "d_low_level_call_unchecked", "Detect unchecked low-level call returns"),
]:
    REGISTRY[f"check-{_det}"] = Tool(
        f"check-{_det}", "static", _grp_help, False, _single_detector(_fn))


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


# ── group: addressing (CREATE / CREATE2 prediction) ─────────────────────────
@tool("create-address", "addressing", "Predict CREATE deploy address from deployer+nonce")
def t_create_addr(deployer, nonce): return A.create_address(deployer, int(nonce))


@tool("create2-address", "addressing", "Predict CREATE2 address from deployer+salt+initcode")
def t_create2_addr(deployer, salt, init_code): return A.create2_address(deployer, salt, init_code)


@tool("vanity-score", "addressing", "Score how 'vanity' (zero-prefixed/repeating) an address is")
def t_vanity(addr): return A.vanity_score(addr)


# ── group: calldata decoding ────────────────────────────────────────────────
@tool("decode-calldata", "calldata", "Decode raw calldata into selector + typed args")
def t_decode_cd(calldata, signature=None): return CD.decode_calldata(calldata, signature)


@tool("identify-selector", "calldata", "Look up a 4-byte selector in the built-in signature DB")
def t_id_sel(selector): return CD.identify_selector(selector)


@tool("known-selectors", "calldata", "List the built-in selector dictionary")
def t_known_sel(): return CD.KNOWN_SELECTORS


# ── group: storage / gas ────────────────────────────────────────────────────
@tool("mapping-slot", "storage", "Storage slot of mapping[key] at base slot")
def t_map_slot(key, slot): return ST.mapping_slot(key, int(slot))


@tool("array-slot", "storage", "Storage slot of dynamic array[index] at base slot")
def t_arr_slot(slot, index): return ST.dynamic_array_slot(int(slot), int(index))


@tool("string-slot", "storage", "Data slot for long string/bytes at a base slot")
def t_str_slot(slot): return ST.string_bytes_slot(int(slot))


@tool("calldata-gas", "storage", "EIP-2028 calldata gas cost (4/zero byte, 16/nonzero)")
def t_cd_gas(calldata): return ST.calldata_gas(calldata)


@tool("estimate-gas", "storage", "Rough static gas estimate from bytecode opcodes")
def t_est_gas(code): return ST.estimate_bytecode_gas(code)


@tool("storage-collision", "storage", "Compare two storage layouts for proxy collision (a|b pipe-separated)")
def t_collision(layout_a, layout_b):
    return ST.storage_collision_check(layout_a.split("|"), layout_b.split("|"))


# ── group: honeypot / rug analysis ──────────────────────────────────────────
@tool("scan-token", "honeypot", "Score a token contract for rug/honeypot red flags")
def t_scan_token(path): return H.scan_token_file(path)


@tool("scan-token-src", "honeypot", "Score token source string for rug/honeypot red flags")
def t_scan_token_src(src): return H.scan_token(src)


# ── group: signatures (EIP-191 / 712 / 2098) ────────────────────────────────
@tool("eth-message-hash", "signatures", "EIP-191 personal_sign hash of a message")
def t_eth_msg(message): return SIG.eth_message_hash(message)


@tool("eip712-domain", "signatures", "EIP-712 domainSeparator (name version chainId contract)")
def t_domain(name, version, chain_id, contract):
    return SIG.eip712_domain_separator(name, version, int(chain_id), contract)


@tool("eip712-digest", "signatures", "Final EIP-712 digest from domainSeparator + structHash")
def t_digest(domain_separator, struct_hash):
    return SIG.eip712_typed_data_hash(domain_separator, struct_hash)


@tool("type-hash", "signatures", "keccak of an EIP-712 type string")
def t_type_hash(type_string): return SIG.type_hash(type_string)


@tool("split-sig", "signatures", "Split a 65-byte (or EIP-2098 compact) signature into r,s,v")
def t_split_sig(sig): return SIG.split_signature(sig)


@tool("check-malleability", "signatures", "Detect high-s (malleable) signatures (EIP-2)")
def t_malleable(sig): return SIG.is_malleable(sig)


def groups() -> dict:
    g = {}
    for t in REGISTRY.values():
        g.setdefault(t.group, []).append(t.name)
    return g


def tool_count() -> int:
    return len(REGISTRY)
