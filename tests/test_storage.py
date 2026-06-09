from loxeye import storage as ST
from loxeye.keccak import keccak256


def test_mapping_slot_matches_spec():
    addr = "0x" + "be" * 20
    got = ST.mapping_slot(addr, 0)
    expect = "0x" + keccak256(bytes.fromhex("be" * 20).rjust(32, b"\x00")
                              + (0).to_bytes(32, "big")).hex()
    assert got == expect


def test_array_slot():
    base = ST.dynamic_array_slot(1, 0)
    expect = "0x" + keccak256((1).to_bytes(32, "big")).hex()
    assert base == expect
    # index N == base + N
    assert int(ST.dynamic_array_slot(1, 5), 16) - int(base, 16) == 5


def test_calldata_gas_eip2028():
    g = ST.calldata_gas("0xa9059cbb" + "00" * 32)
    # 4 nonzero bytes (selector) *16 + 32 zero *4
    assert g["calldata_gas"] == 4 * 16 + 32 * 4
    assert g["zero_bytes"] == 32


def test_storage_collision_detect():
    a = ["address owner", "uint256 total"]
    b = ["address owner", "address admin"]
    issues = ST.storage_collision_check(a, b)
    assert any(i.get("slot") == 1 for i in issues)


def test_storage_no_collision():
    a = ["address owner", "uint256 total"]
    assert ST.storage_collision_check(a, a) == []


def test_estimate_gas():
    est = ST.estimate_bytecode_gas("60016000556001")  # has SSTORE
    assert est["static_gas_estimate"] > 20000
    assert "SSTORE" in est["expensive_ops"]
