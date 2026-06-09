from loxeye import static_analysis as S

VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract V {
    address owner;
    function initialize(address o) public { owner = o; }
    function a() public view returns (bool) { return tx.origin == owner; }
    function w(uint256 x) public {
        (bool ok,) = msg.sender.call{value: x}("");
        bal[msg.sender] -= x;
    }
    function rng() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp)));
    }
    function nuke() public { selfdestruct(payable(owner)); }
    function ex(address t, bytes memory d) public { t.delegatecall(d); }
    mapping(address=>uint256) bal;
}
"""


def _detectors(findings):
    return {f.detector for f in findings}


def test_finds_core_bugs():
    f = S.analyze_source(VULN)
    d = _detectors(f)
    for expected in ["tx-origin-auth", "reentrancy", "selfdestruct",
                     "delegatecall", "weak-randomness", "unprotected-init",
                     "pragma-unlocked"]:
        assert expected in d, f"missing {expected}"


def test_severity_filter():
    high = S.analyze_source(VULN, min_severity="high")
    assert all(x.severity == "high" for x in high)
    assert len(high) >= 4


def test_comments_ignored():
    src = "// tx.origin == owner\n/* selfdestruct(x); */\ncontract C {}"
    f = S.analyze_source(src)
    assert "tx-origin-auth" not in _detectors(f)
    assert "selfdestruct" not in _detectors(f)


def test_clean_contract_low_noise():
    clean = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Safe {
    address private owner;
    constructor() { owner = msg.sender; }
    function setOwner(address n) external {
        require(msg.sender == owner);
        require(n != address(0));
        owner = n;
    }
}
"""
    f = S.analyze_source(clean, min_severity="high")
    assert len(f) == 0


def test_detector_count():
    assert len(S.DETECTORS) >= 15


def test_findings_have_lines():
    f = S.analyze_source(VULN)
    assert all(x.line > 0 for x in f)
