"""Tests for the ShellLauncher declarative plugin (T1547.001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1547.shell_launcher import ShellLauncher

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SOFTWARE_HIVE = "/fake/SOFTWARE"


def test_shell_launcher_happy_path(tmp_path: Path) -> None:
    """A Shell override replaces explorer.exe for every logon on the host."""
    node = make_node(values={"Shell": r"C:\evil.exe"})
    plugin = make_plugin(ShellLauncher, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    assert findings, "a Shell value other than the default must be reported"
    hklm_findings = [finding for finding in findings if finding.path.startswith("HKLM")]
    assert any(finding.value == r"C:\evil.exe" for finding in hklm_findings), (
        "the machine Shell value must be reported under HKLM"
    )
