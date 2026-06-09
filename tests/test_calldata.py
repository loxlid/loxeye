from loxeye import calldata as CD


def test_decode_transfer():
    cd = "0xa9059cbb" + "00" * 12 + "be" * 20 + format(1_000_000, "064x")
    d = CD.decode_calldata(cd)
    assert d["selector"] == "0xa9059cbb"
    assert d["known"] == "transfer(address,uint256)"
    assert d["args"][0]["type"] == "address"
    assert d["args"][1]["value"] == 1_000_000


def test_identify_selector():
    assert CD.identify_selector("0xa9059cbb") == "transfer(address,uint256)"
    assert CD.identify_selector("0x70a08231") == "balanceOf(address)"
    assert CD.identify_selector("0xdeadbeef") is None


def test_explicit_signature():
    cd = "0x70a08231" + "00" * 12 + "ab" * 20
    d = CD.decode_calldata(cd, "balanceOf(address)")
    assert d["args"][0]["type"] == "address"


def test_short_calldata():
    d = CD.decode_calldata("0xab")
    assert d["args"] is None


def test_known_db_nonempty():
    assert len(CD.KNOWN_SELECTORS) >= 20
