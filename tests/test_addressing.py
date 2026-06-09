from loxeye import addressing as A


def test_create_known_vector():
    # well-known: deployer 0x6ac7..dbf0 nonce 0
    addr = A.create_address("0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 0)
    assert addr.lower() == "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"


def test_create2_eip1014_vectors():
    a = A.create2_address("0x0000000000000000000000000000000000000000",
                          "0x" + "00" * 32, "0x00")
    assert a.lower() == "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"
    b = A.create2_address("0xdeadbeef00000000000000000000000000000000",
                          "0x" + "00" * 32, "0x00")
    assert b.lower() == "0xb928f69bb1d91cd65274e3c79d8986362984fda3"


def test_create2_int_salt():
    a = A.create2_address("0x0000000000000000000000000000000000000000", 0, "0x00")
    assert a.lower() == "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"


def test_vanity_score():
    v = A.vanity_score("0x0000000000c9b3e3a0d0e0b0a0000000000000000"[:42])
    assert v["leading_zero_nibbles"] >= 8
    assert "gas_saving_zero_bytes" in v
