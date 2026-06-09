from loxeye.keccak import keccak256_hex


def test_empty():
    assert keccak256_hex(b"") == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_abc():
    assert keccak256_hex(b"abc") == \
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_selector_transfer():
    assert keccak256_hex(b"transfer(address,uint256)")[:8] == "a9059cbb"


def test_longer_than_rate():
    # > 136 bytes forces multiple absorb blocks
    data = b"x" * 200
    out = keccak256_hex(data)
    assert len(out) == 64
