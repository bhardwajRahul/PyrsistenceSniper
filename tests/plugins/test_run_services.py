"""Tests for the RunServices and RunServicesOnce plugins (T1547.001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.plugins.T1547.run_services import (
    RunServices,
    RunServicesOnce,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_HAPPY_CASES: list[tuple[type, str, str]] = [
    (RunServices, "EvilSvc", r"C:\evil_svc.exe"),
    (RunServicesOnce, "EvilOnce", r"C:\evil_once.exe"),
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
    """Each plugin produces a finding when its registry value is present."""
    node = make_node(values={value_key: value_data})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) >= 1
    assert any(value_data in finding.value for finding in findings)
