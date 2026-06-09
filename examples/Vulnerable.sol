// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Intentionally vulnerable contract used to exercise the static analyzer.
// DO NOT deploy this. Every "bug" here is on purpose.
contract Vulnerable {
    address owner;
    mapping(address => uint256) public balances;

    function initialize(address _owner) public {
        owner = _owner;
    }

    function auth() public view returns (bool) {
        return tx.origin == owner;
    }

    // reentrancy: external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function rng() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }

    function nuke() public {
        selfdestruct(payable(owner));
    }

    function exec(address target, bytes memory data) public {
        target.delegatecall(data);
    }

    function payout(address to, uint256 v) public {
        to.call{value: v}("");
    }

    function checkExact() public view returns (bool) {
        return address(this).balance == 1 ether;
    }

    function setManager(address m) public {
        owner = m;
    }
}
