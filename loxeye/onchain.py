"""On-chain inspection over JSON-RPC. Standard library only (urllib).

Works against any Ethereum-compatible HTTP RPC endpoint. All network calls
go through one helper so the rest of the toolkit stays testable/offline.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from .crypto_utils import encode_call, function_selector, is_hex_address, to_checksum_address

# EIP-1967 storage slots
SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

ERC165_SELECTOR = function_selector("supportsInterface(bytes4)")
INTERFACE_IDS = {
    "0x80ac58cd": "ERC-721",
    "0xd9b67a26": "ERC-1155",
    "0x5b5e139f": "ERC-721Metadata",
    "0x01ffc9a7": "ERC-165",
}


class RpcError(Exception):
    pass


class RpcClient:
    def __init__(self, url: str, timeout: int = 20):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list):
        self._id += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": self._id,
                              "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                doc = json.loads(r.read())
        except urllib.error.URLError as e:
            raise RpcError(f"RPC transport error: {e}") from e
        if "error" in doc:
            raise RpcError(f"RPC error: {doc['error']}")
        return doc.get("result")

    # convenience wrappers ----------------------------------------------------
    def chain_id(self) -> int:
        return int(self.call("eth_chainId", []), 16)

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def get_code(self, address: str, block="latest") -> str:
        return self.call("eth_getCode", [to_checksum_address(address), block])

    def get_balance(self, address: str, block="latest") -> int:
        return int(self.call("eth_getBalance", [to_checksum_address(address), block]), 16)

    def get_storage_at(self, address: str, slot, block="latest") -> str:
        if isinstance(slot, int):
            slot = hex(slot)
        return self.call("eth_getStorageAt", [to_checksum_address(address), slot, block])

    def eth_call(self, to: str, data: str, block="latest") -> str:
        return self.call("eth_call", [{"to": to_checksum_address(to), "data": data}, block])

    # higher-level detectors --------------------------------------------------
    def is_contract(self, address: str) -> bool:
        code = self.get_code(address)
        return code not in (None, "0x", "0x0")

    def detect_proxy(self, address: str) -> dict:
        """Read EIP-1967 slots to detect a transparent/UUPS proxy."""
        out = {"is_proxy": False, "implementation": None, "admin": None, "beacon": None}
        impl = self.get_storage_at(address, SLOT_IMPL)
        if impl and int(impl, 16) != 0:
            out["is_proxy"] = True
            out["implementation"] = _slot_to_address(impl)
        admin = self.get_storage_at(address, SLOT_ADMIN)
        if admin and int(admin, 16) != 0:
            out["admin"] = _slot_to_address(admin)
        beacon = self.get_storage_at(address, SLOT_BEACON)
        if beacon and int(beacon, 16) != 0:
            out["is_proxy"] = True
            out["beacon"] = _slot_to_address(beacon)
        return out

    def read_owner(self, address: str):
        """Try common ownership getters."""
        for sig in ("owner()", "getOwner()", "admin()"):
            try:
                res = self.eth_call(address, function_selector(sig))
                if res and int(res, 16) != 0:
                    return {"method": sig, "owner": _slot_to_address(res)}
            except RpcError:
                continue
        return None

    def supports_interface(self, address: str, interface_id: str) -> bool:
        data = encode_call("supportsInterface(bytes4)", 0) # placeholder, build manually below
        # build calldata: selector + bytes4 left-padded to 32
        iid = interface_id[2:] if interface_id.startswith("0x") else interface_id
        data = ERC165_SELECTOR + iid.ljust(64, "0")
        try:
            res = self.eth_call(address, data)
            return bool(res) and int(res, 16) == 1
        except RpcError:
            return False

    def detect_token_standard(self, address: str) -> list[str]:
        found = []
        for iid, name in INTERFACE_IDS.items():
            if self.supports_interface(address, iid):
                found.append(name)
        return found

    def erc20_allowance(self, token: str, owner: str, spender: str) -> int:
        data = encode_call("allowance(address,address)", owner, spender)
        res = self.eth_call(token, data)
        return int(res, 16) if res and res != "0x" else 0


def _slot_to_address(slot_hex: str) -> str:
    h = slot_hex[2:] if slot_hex.startswith("0x") else slot_hex
    h = h.rjust(64, "0")
    return to_checksum_address("0x" + h[-40:])


UNLIMITED = (1 << 256) - 1


def classify_allowance(value: int) -> str:
    if value == 0:
        return "none"
    if value >= UNLIMITED - (1 << 200):
        return "UNLIMITED (risky)"
    return "limited"
