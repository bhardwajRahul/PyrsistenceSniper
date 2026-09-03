"""Tests for the DotNetStartupHooks plugin (T1574.012)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1574.dotnet_startup_hooks import DotNetStartupHooks

from .conftest import make_deps, make_node


def _make_plugin(
    tmp_path: Path,
    user_profiles: list[UserProfile] | None = None,
) -> DotNetStartupHooks:
    """Build a DotNetStartupHooks; without profiles it sees no user hives at all."""
    context, _registry, _filesystem = make_deps(tmp_path, user_profiles=user_profiles)
    return DotNetStartupHooks(context=context)


def _plugin_reading(tmp_path: Path, environment_key: object) -> DotNetStartupHooks:
    """Answer the machine Environment key with the node given, or None for absent."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = environment_key
    return plugin


def _profile(tmp_path: Path, username: str) -> list[UserProfile]:
    """Return one profile whose NTUSER.DAT the check will open."""
    return [
        UserProfile(username, tmp_path / "Users" / username, tmp_path / "NTUSER.DAT")
    ]


def test_system_hive_detected(tmp_path: Path) -> None:
    """DOTNET_STARTUP_HOOKS in the machine environment loads into every CLR process."""
    node = make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\evil.dll"})

    findings = _plugin_reading(tmp_path, node).run()

    system_findings = [
        finding for finding in findings if finding.access_gained == AccessLevel.SYSTEM
    ]
    assert len(system_findings) == 1
    assert system_findings[0].value == r"C:\evil.dll"
    assert "DOTNET_STARTUP_HOOKS" in system_findings[0].path


def test_system_hive_missing(tmp_path: Path) -> None:
    """An image with no SYSTEM hive is a clean absence, not a scan failure."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None

    assert plugin.run() == []


def test_system_env_key_missing(tmp_path: Path) -> None:
    """A SYSTEM hive without an Environment key sets no variable to report."""
    assert _plugin_reading(tmp_path, None).run() == []


def test_system_env_no_hooks_value(tmp_path: Path) -> None:
    """An Environment key holding other variables sets no startup hook."""
    node = make_node(values={"OTHER_VAR": "something"})

    assert _plugin_reading(tmp_path, node).run() == []


def test_user_hive_detected(tmp_path: Path) -> None:
    """The HKCU copy needs no administrative rights, so it is checked too."""
    plugin = _make_plugin(tmp_path, user_profiles=_profile(tmp_path, "victim"))
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.side_effect = [MagicMock(), MagicMock()]
    plugin.registry.load_subtree.side_effect = [
        None,
        make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\user_evil.dll"}),
    ]

    findings = plugin.run()

    user_findings = [
        finding for finding in findings if finding.access_gained == AccessLevel.USER
    ]
    assert len(user_findings) == 1
    assert user_findings[0].value == r"C:\user_evil.dll"
    assert "victim" in user_findings[0].path


def test_both_system_and_user(tmp_path: Path) -> None:
    """A hook set in both scopes is two separate settings, so two findings."""
    plugin = _make_plugin(tmp_path, user_profiles=_profile(tmp_path, "alice"))
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.side_effect = [MagicMock(), MagicMock()]
    plugin.registry.load_subtree.side_effect = [
        make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\sys.dll"}),
        make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\user.dll"}),
    ]

    findings = plugin.run()

    assert len(findings) == 2
    assert {finding.access_gained for finding in findings} == {
        AccessLevel.SYSTEM,
        AccessLevel.USER,
    }
