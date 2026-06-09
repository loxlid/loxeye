from loxeye import honeypot as H

RUG = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Rug {
    address owner;
    bool tradingEnabled;
    uint256 sellTax = 35;
    mapping(address=>bool) isBlacklisted;
    mapping(address=>uint256) _balances;
    modifier onlyOwner(){require(msg.sender==owner);_;}
    function mint(address to,uint256 a) public onlyOwner { _mint(to,a); }
    function setSellTax(uint256 t) public onlyOwner { sellTax=t; }
    function enableTrading() public onlyOwner { tradingEnabled=true; }
    function blacklist(address a) public onlyOwner { isBlacklisted[a]=true; }
    function rescueTokens(address t) public onlyOwner {}
    function _mint(address to,uint256 a) internal { _balances[to]+=a; }
}
"""

CLEAN = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Token {
    mapping(address=>uint256) private _bal;
    function transfer(address to,uint256 v) external returns(bool){
        _bal[msg.sender]-=v; _bal[to]+=v; return true;
    }
}
"""


def test_rug_is_critical():
    r = H.scan_token(RUG)
    assert r["risk_score"] >= 70
    assert r["risk_level"] == "CRITICAL"
    names = {f["name"] for f in r["flags"]}
    assert "blacklist" in names
    assert "trading_switch" in names


def test_clean_is_low():
    r = H.scan_token(CLEAN)
    assert r["risk_score"] < 20
    assert r["risk_level"] == "LOW"


def test_flags_have_lines():
    r = H.scan_token(RUG)
    assert all("line" in f for f in r["flags"])
