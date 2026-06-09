// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Intentionally rug-shaped token to exercise the honeypot scanner.
// DO NOT use as a template. Every red flag here is on purpose.
contract RugToken {
    address public owner;
    bool public tradingEnabled;
    uint256 public sellTax = 35;
    mapping(address => bool) public isBlacklisted;
    mapping(address => uint256) private _balances;

    modifier onlyOwner() { require(msg.sender == owner); _; }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function setSellTax(uint256 t) public onlyOwner { sellTax = t; }

    function enableTrading() public onlyOwner { tradingEnabled = true; }

    function blacklist(address a) public onlyOwner { isBlacklisted[a] = true; }

    function _transfer(address from, address to, uint256 v) internal {
        require(tradingEnabled || from == owner, "trading off");
        require(!isBlacklisted[from], "blocked");
        _balances[from] -= v;
        _balances[to] += v;
    }

    function rescueTokens(address t) public onlyOwner {
        // owner can sweep everything
    }

    function _mint(address to, uint256 a) internal { _balances[to] += a; }
}
