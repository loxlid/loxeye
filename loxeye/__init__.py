"""loxeye — a dependency-free web3 / smart-contract security toolkit."""
from .registry import REGISTRY, groups, tool_count
from . import crypto_utils, static_analysis, bytecode, onchain

__version__ = "0.1.0"
__all__ = ["REGISTRY", "groups", "tool_count",
           "crypto_utils", "static_analysis", "bytecode", "onchain"]
