"""Tests for the DsrmAdminLogonBehavior backdoor check (T1547.001)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.dsrm_backdoor import DsrmBackdoor

from .conftest import make_node, make_plugin


def _plugin_reading(tmp_path: Path, logon_behavior: int) -> object:
    """Answer the Lsa key with the given DsrmAdminLogonBehavior and nothing after."""
    plugin = make_plugin(DsrmBackdoor, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.side_effect = [
        make_node(values={"DsrmAdminLogonBehavior": logon_behavior}),
        None,
        None,
    ]
    return plugin


def test_dsrm_value_2_produces_finding(tmp_path: Path) -> None:
    """Value 2 grants network logon with the DSRM password, a SYSTEM backdoor."""
    findings = _plugin_reading(tmp_path, 2).run()

    assert len(findings) == 1
    assert findings[0].value == "2"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "T1547" in findings[0].mitre_id


def test_dsrm_value_not_2_returns_empty(tmp_path: Path) -> None:
    """Only the value 2 is the backdoor; the key's presence alone is not."""
    assert _plugin_reading(tmp_path, 0).run() == []
