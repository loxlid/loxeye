import pytest
from loxeye import crypto_utils as C


@pytest.mark.parametrize("addr", [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
])
def test_eip55_roundtrip(addr):
    assert C.to_checksum_address(addr.lower()) == addr
    assert C.check_address_checksum(addr) is True


def test_bad_checksum_rejected():
    # all-lowercase is not a checksum address
    assert C.check_address_checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") is False


def test_is_address():
    assert C.is_hex_address("0x" + "a" * 40)
    assert not C.is_hex_address("0x" + "a" * 39)
    assert not C.is_hex_address("nope")


def test_selectors():
    assert C.function_selector("transfer(address,uint256)") == "0xa9059cbb"
    assert C.function_selector("balanceOf(address)") == "0x70a08231"


def test_event_topic():
    t = C.event_topic("Transfer(address,address,uint256)")
    assert t.startswith("0xddf252ad")
    assert len(t) == 66


def test_units():
    assert C.to_wei("1.5", "ether") == 1_500_000_000_000_000_000
    assert C.to_wei("20", "gwei") == 20_000_000_000
    assert C.to_wei(3, "ether") == 3_000_000_000_000_000_000
    assert C.from_wei(1_500_000_000_000_000_000) == "1.5"
    assert C.from_wei(20_000_000_000, "gwei") == "20"


def test_encode_call():
    cd = C.encode_call("balanceOf(address)", "0x" + "ab" * 20)
    assert cd.startswith("0x70a08231")
    assert len(cd) == 2 + 8 + 64


def test_encode_call_arity():
    with pytest.raises(ValueError):
        C.encode_call("balanceOf(address)")
