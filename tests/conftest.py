"""Pytest configuration for supply_chain probe tests.

Sets garak._config to safe defaults before any probe/detector is imported,
preventing AttributeError from the base-class __init__ print guards.
"""
import garak._config as _config

# garak's base Probe/Detector __init__ guards on `if not args` before printing.
# args=None is already the default, so no mock is needed — this file exists to
# document that assumption and provide a single place to add future fixtures.
assert _config.args is None
assert _config.reportfile is None
