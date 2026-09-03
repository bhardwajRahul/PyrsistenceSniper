"""Tests for the BootVerificationProgram plugin in T1547/boot_verification.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1547.boot_verification import BootVerificationProgram

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    """A hijacked ImagePath value produces a finding with the planted program."""
    node = make_node(values={"ImagePath": r"C:\evil_bootverify.exe"})
    plugin = make_plugin(BootVerificationProgram, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SYSTEM")
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil_bootverify.exe" in findings[0].value
    assert findings[0].check_id == "boot_verification_program"
