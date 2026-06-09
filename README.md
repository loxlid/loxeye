# loxeye

[![CI](https://github.com/loxlid/loxeye/actions/workflows/ci.yml/badge.svg)](https://github.com/loxlid/loxeye/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Tools](https://img.shields.io/badge/tools-55-orange)

A dependency-free **web3 / smart-contract security toolkit**. 55 tools for
auditing Solidity source, dissecting EVM bytecode, predicting deploy
addresses, decoding calldata, and inspecting live contracts over JSON-RPC —
all in pure Python, no `pip install` needed.

Built for the boring-but-critical parts of a security workflow: hashing
selectors, checksumming addresses, flagging reentrancy and `tx.origin` auth,
recovering function selectors from bytecode, and reading EIP-1967 proxy slots.

> The Keccak-256 implementation, EIP-55 checksums, and EIP-1967 slot constants
> are validated against official test vectors in the test suite (42 tests).

## Why

Most quick checks pull in `web3.py`, `eth-utils`, `slither`, and a Solidity
compiler. That's a heavy stack for "what's the selector for this signature" or
"does this bytecode use delegatecall". This toolkit does the common 80% with
the standard library only, so it runs anywhere Python runs.

It is **not** a replacement for a full auditor or a formal verifier. The static
analyzer is heuristic (regex/line based); treat it as a fast first pass, not a
proof of safety.

## Install

```bash
git clone https://github.com/loxlid/loxeye.git
cd loxeye
# no dependencies; optionally install as a package:
pip install -e .
```

## Usage

```bash
# list every tool
python -m loxeye list

# crypto / encoding
python -m loxeye run selector "transfer(address,uint256)"     # 0xa9059cbb
python -m loxeye run checksum 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed
python -m loxeye run to-wei 1.5 ether                          # 1500000000000000000
python -m loxeye run topic "Transfer(address,address,uint256)"

# static analysis
python -m loxeye run scan examples/Vulnerable.sol --json
python -m loxeye run scan-summary examples/Vulnerable.sol
python -m loxeye run check-reentrancy examples/Vulnerable.sol

# bytecode
python -m loxeye run disasm 0x6080604052
python -m loxeye run selectors-from-code 0x...
python -m loxeye run is-proxy-code 0x363d3d37...

# on-chain (needs an RPC endpoint)
python -m loxeye run detect-proxy 0xADDR --rpc https://eth.llamarpc.com
python -m loxeye run read-owner  0xADDR --rpc https://eth.llamarpc.com
python -m loxeye run allowance 0xTOKEN 0xOWNER 0xSPENDER --rpc https://eth.llamarpc.com

# deploy-address prediction (CREATE / CREATE2)
python -m loxeye run create-address 0xDEPLOYER 0          # CREATE at nonce 0
python -m loxeye run create2-address 0xFACTORY 0xSALT 0xINITCODE

# decode a raw transaction's calldata
python -m loxeye run decode-calldata 0xa9059cbb000...

# storage-layout math (find where a mapping value lives)
python -m loxeye run mapping-slot 0xHOLDER 0             # balances[holder] @ slot 0
python -m loxeye run storage-collision "address owner|uint256 x" "address owner|address y"

# rug / honeypot risk score
python -m loxeye run scan-token examples/RugToken.sol

# signature hashing + malleability
python -m loxeye run eth-message-hash "hello world"
python -m loxeye run check-malleability 0xSIGNATURE
```

As a library:

```python
from loxeye import crypto_utils, static_analysis, bytecode

crypto_utils.function_selector("transfer(address,uint256)")   # '0xa9059cbb'
findings = static_analysis.analyze_file("examples/Vulnerable.sol")
bytecode.is_likely_proxy("0x363d3d37...")
```

## Tool groups

- **crypto (9)** — keccak, selector, topic, checksum, verify-checksum,
  is-address, to-wei, from-wei, encode-call
- **static (10)** — scan, scan-src, scan-summary, list-detectors, plus
  standalone `check-*` detectors (reentrancy, tx-origin, delegatecall,
  selfdestruct, weak-randomness, unchecked-call)
- **bytecode (6)** — disasm, selectors-from-code, strip-metadata,
  opcode-histogram, dangerous-opcodes, is-proxy-code
- **onchain (10)** — chain-id, block-number, get-code, get-balance,
  is-contract, detect-proxy, read-owner, token-standard, read-storage,
  allowance
- **addressing (3)** — create-address, create2-address, vanity-score
  (predict CREATE/CREATE2 deploy addresses, validated against EIP-1014)
- **calldata (3)** — decode-calldata, identify-selector, known-selectors
  (decode raw tx input into typed args via a built-in selector DB)
- **storage (6)** — mapping-slot, array-slot, string-slot, calldata-gas,
  estimate-gas, storage-collision (Solidity storage-layout math + proxy
  collision detection)
- **honeypot (2)** — scan-token, scan-token-src (rug/honeypot risk scoring:
  hidden mints, blacklists, trading switches, mutable fees)
- **signatures (6)** — eth-message-hash, eip712-domain, eip712-digest,
  type-hash, split-sig, check-malleability (EIP-191/712/2098 hashing +
  high-s malleability detection)

## Vulnerability detectors

The static analyzer ships 18 detectors: floating pragma, `tx.origin` auth,
reentrancy (state write after external call), unchecked low-level call,
selfdestruct, delegatecall, timestamp dependence, weak randomness, unchecked
ERC-20 transfer, missing visibility, ether-send to variable, inline assembly,
deprecated constructs, `=-`/`=+` typos, unprotected `initialize()`, missing
zero-address checks, hardcoded gas, and strict balance equality.

```bash
python -m loxeye run list-detectors
```

## Limitations

- The static analyzer is line/regex based — it has false positives and false
  negatives. It does not parse an AST or resolve types.
- Selector recovery from bytecode is heuristic and may miss selectors behind
  unusual dispatchers.
- On-chain tools require a trusted RPC endpoint; results are only as honest as
  the node you point them at.

## Testing

```bash
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
