"""Stable import path for the CLI entry point.

`python -m loxeye` uses __main__.py; library/test code imports loxeye.cli.
Both share this single main().
"""
from .__main__ import main

__all__ = ["main"]
