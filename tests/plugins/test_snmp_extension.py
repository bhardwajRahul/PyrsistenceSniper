"""Tests for the SnmpExtensionAgent plugin in T1574/snmp_extension.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1574.snmp_extension import SnmpExtensionAgent

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_extension_agent_detected(tmp_path: Path) -> None:
    """A non-default ExtensionAgents value pointing at an agent key fires."""
    node = make_node(values={"1": r"SOFTWARE\EvilCorp\EvilAgent\CurrentVersion"})
    plugin = make_plugin(SnmpExtensionAgent, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SYSTEM")
    findings = plugin.run()
    assert len(findings) == 1
    assert "EvilAgent" in findings[0].value
    assert findings[0].check_id == "snmp_extension_agent"
    assert findings[0].access_gained == AccessLevel.SYSTEM
