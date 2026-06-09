from loxeye import bytecode as B

# EIP-1167 minimal proxy runtime (uses DELEGATECALL)
PROXY = ("363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe"
         "5af43d82803e903d91602b57fd5bf3")


def test_disassemble_proxy():
    ins = B.disassemble(PROXY)
    names = [i.name for i in ins]
    assert "DELEGATECALL" in names
    assert "RETURN" in names


def test_is_proxy():
    assert B.is_likely_proxy(PROXY) is True
    assert B.is_likely_proxy("6001600101") is False  # PUSH1 1 PUSH1 1 ADD


def test_dangerous_opcodes():
    d = B.find_dangerous_opcodes(PROXY)
    assert any(i.name == "DELEGATECALL" for i in d)


def test_extract_selectors():
    # PUSH4 0x70a08231 EQ ; PUSH4 0xa9059cbb EQ
    code = "6370a0823114" + "63a9059cbb14"
    sels = B.extract_selectors(code)
    assert "0x70a08231" in sels
    assert "0xa9059cbb" in sels


def test_push_operand_parsing():
    ins = B.disassemble("60ff")  # PUSH1 0xff
    assert ins[0].name == "PUSH1"
    assert ins[0].operand == b"\xff"


def test_strip_metadata_roundtrip():
    # construct: runtime + cbor + 2-byte length
    runtime = "6080604052"
    cbor = "a164736f6c63430008180033"[:-4]  # arbitrary body
    body = "a164736f6c6343000818"
    length = format(len(bytes.fromhex(body)), "04x")
    full = runtime + body + length
    rt, meta = B.strip_metadata(full)
    assert rt == runtime
    assert meta == body + length


def test_histogram():
    h = B.opcode_histogram("6001600101")  # PUSH1,PUSH1,ADD
    assert h.get("PUSH1") == 2
    assert h.get("ADD") == 1
