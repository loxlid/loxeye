from loxeye import onchain as O
from loxeye.keccak import keccak256


def test_eip1967_slot_constant():
    # impl slot == keccak256("eip1967.proxy.implementation") - 1
    calc = int.from_bytes(keccak256(b"eip1967.proxy.implementation"), "big") - 1
    assert "0x" + format(calc, "064x") == O.SLOT_IMPL


def test_slot_to_address():
    slot = "0x000000000000000000000000" + "be" * 20
    assert O._slot_to_address(slot).lower() == "0x" + "be" * 20


def test_classify_allowance():
    assert O.classify_allowance(0) == "none"
    assert O.classify_allowance(1000) == "limited"
    assert "UNLIMITED" in O.classify_allowance(O.UNLIMITED)
    assert "UNLIMITED" in O.classify_allowance(2 ** 256 - 1)


def test_rpc_client_offline_construct():
    # Constructing a client must not perform any network IO.
    c = O.RpcClient("http://127.0.0.1:1")
    assert c.url == "http://127.0.0.1:1"
    assert c._id == 0


def test_interface_ids_present():
    assert "0x80ac58cd" in O.INTERFACE_IDS  # ERC-721
    assert "0xd9b67a26" in O.INTERFACE_IDS  # ERC-1155
