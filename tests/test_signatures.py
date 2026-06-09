from loxeye import signatures as SIG


def test_eth_message_hash_known():
    # canonical personal_sign hash of "hello world"
    assert SIG.eth_message_hash("hello world") == \
        "0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"


def test_split_signature_65():
    sig = "0x" + "11" * 32 + "22" * 32 + "1b"
    p = SIG.split_signature(sig)
    assert p["r"] == "0x" + "11" * 32
    assert p["s"] == "0x" + "22" * 32
    assert p["v"] == 27
    assert p["compact"] is False


def test_split_signature_v_normalized():
    sig = "0x" + "11" * 32 + "22" * 32 + "00"  # v=0 -> 27
    assert SIG.split_signature(sig)["v"] == 27


def test_malleability():
    high_s = (SIG.HALF_N + 1).to_bytes(32, "big").hex()
    low_s = (SIG.HALF_N - 1).to_bytes(32, "big").hex()
    assert SIG.is_malleable("0x" + "11" * 32 + high_s + "1b")["malleable"] is True
    assert SIG.is_malleable("0x" + "11" * 32 + low_s + "1b")["malleable"] is False


def test_eip712_domain_deterministic():
    a = SIG.eip712_domain_separator("App", "1", 1, "0x" + "ab" * 20)
    b = SIG.eip712_domain_separator("App", "1", 1, "0x" + "ab" * 20)
    assert a == b and len(a) == 66


def test_eip712_digest():
    ds = "0x" + "11" * 32
    sh = "0x" + "22" * 32
    d = SIG.eip712_typed_data_hash(ds, sh)
    assert d.startswith("0x") and len(d) == 66


def test_type_hash():
    th = SIG.type_hash("Permit(address owner,address spender,uint256 value)")
    assert th.startswith("0x") and len(th) == 66
