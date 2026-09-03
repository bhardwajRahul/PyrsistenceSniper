"""Tests for the ShellExecuteHooks and SharedTaskScheduler plugins (T1546)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.plugins.T1546.shell_execute_hooks import (
    SharedTaskScheduler,
    ShellExecuteHooks,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_HAPPY_CASES: list[tuple[type, str, str]] = [
    (ShellExecuteHooks, "{evil-clsid}", "EvilHook"),
    (SharedTaskScheduler, "{evil-clsid}", "EvilScheduler"),
]


@pytest.mark.parametrize(
    ("plugin_cls", "value_key", "value_data"),
    _HAPPY_CASES,
    ids=[case[0].__name__ for case in _HAPPY_CASES],
)
def test_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    value_key: str,
    value_data: str,
) -> None:
    """Each declarative plugin produces a finding when its registry value is present."""
    node = make_node(values={value_key: value_data})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) >= 1
    assert any(value_data in finding.value for finding in findings)
    assert all("T1546" in finding.mitre_id for finding in findings)
