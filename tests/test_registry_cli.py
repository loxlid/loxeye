from loxeye import registry as R
from loxeye.cli import main


def test_minimum_tool_count():
    assert R.tool_count() >= 30


def test_groups_present():
    g = R.groups()
    for grp in ("crypto", "static", "bytecode", "onchain"):
        assert grp in g and len(g[grp]) > 0


def test_every_tool_callable():
    for t in R.REGISTRY.values():
        assert callable(t.fn)
        assert t.help
        assert t.group


def test_cli_list(capsys):
    rc = main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "tools" in out
    assert "[crypto]" in out


def test_cli_run_selector(capsys):
    rc = main(["run", "selector", "transfer(address,uint256)"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == "0xa9059cbb"


def test_cli_run_checksum(capsys):
    rc = main(["run", "checksum", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def test_cli_unknown_tool():
    assert main(["run", "does-not-exist"]) == 2


def test_cli_rpc_required():
    # onchain tool without --rpc must fail with code 2
    assert main(["run", "chain-id"]) == 2


def test_cli_help_tool(capsys):
    rc = main(["help", "scan"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "scan" in out


def test_all_check_detectors_resolve(tmp_path):
    # every check-* tool must map to a real detector and run without error
    sol = tmp_path / "v.sol"
    sol.write_text(
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function f() public { require(tx.origin == msg.sender); }\n"
        "  function g(address t, bytes memory d) public { t.delegatecall(d); }\n"
        "}\n"
    )
    check_tools = [n for n, t in R.REGISTRY.items()
                   if n.startswith("check-") and t.group == "static"]
    assert len(check_tools) >= 6
    for name in check_tools:
        result = R.REGISTRY[name](str(sol))  # must not raise
        assert isinstance(result, list)


def test_every_offline_tool_invokable():
    # smoke: non-rpc tools that take no args or simple args resolve cleanly
    assert R.REGISTRY["known-selectors"]()
    assert R.REGISTRY["list-detectors"]()
