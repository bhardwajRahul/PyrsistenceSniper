"""Tests for the PowerAutomate plugin (T1546)."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.power_automate import PowerAutomate

from .conftest import make_deps


def _flows_dir(tmp_path: Path, username: str) -> Path:
    """Return the Flows directory Power Automate Desktop runs from."""
    return (
        tmp_path
        / "Users"
        / username
        / "AppData"
        / "Local"
        / "Microsoft"
        / "Power Automate Desktop"
        / "Flows"
    )


def _make_plugin(
    tmp_path: Path,
    user_profiles: list[UserProfile] | None = None,
) -> PowerAutomate:
    """Build a PowerAutomate plugin that sees only the given user profiles."""
    context, _registry, _filesystem = make_deps(tmp_path, user_profiles=user_profiles)
    return PowerAutomate(context=context)


def test_flow_directory_detected(tmp_path: Path) -> None:
    """Each subdirectory under Flows is a flow the desktop agent can run."""
    flows = _flows_dir(tmp_path, "victim")
    (flows / "MaliciousFlow").mkdir(parents=True)

    profiles = [UserProfile("victim", tmp_path / "Users" / "victim")]
    plugin = _make_plugin(tmp_path, user_profiles=profiles)

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "MaliciousFlow"
    assert findings[0].access_gained == AccessLevel.USER


def test_no_flows_directory(tmp_path: Path) -> None:
    """A profile that never installed Power Automate has no Flows folder."""
    profiles = [UserProfile("clean", tmp_path / "Users" / "clean")]
    plugin = _make_plugin(tmp_path, user_profiles=profiles)

    findings = plugin.run()
    assert findings == []


def test_files_in_flows_ignored(tmp_path: Path) -> None:
    """Regular files inside Flows are not flagged, only subdirectories."""
    flows = _flows_dir(tmp_path, "victim")
    flows.mkdir(parents=True)
    (flows / "readme.txt").write_text("not a flow")

    profiles = [UserProfile("victim", tmp_path / "Users" / "victim")]
    plugin = _make_plugin(tmp_path, user_profiles=profiles)

    findings = plugin.run()
    assert findings == []


def test_multiple_users_multiple_flows(tmp_path: Path) -> None:
    """Each profile carries its own flows, so every profile is scanned."""
    for username, flow_name in [("alice", "FlowA"), ("bob", "FlowB")]:
        ((_flows_dir(tmp_path, username)) / flow_name).mkdir(parents=True)

    profiles = [
        UserProfile("alice", tmp_path / "Users" / "alice"),
        UserProfile("bob", tmp_path / "Users" / "bob"),
    ]
    plugin = _make_plugin(tmp_path, user_profiles=profiles)

    findings = plugin.run()
    assert len(findings) == 2
    values = {finding.value for finding in findings}
    assert values == {"FlowA", "FlowB"}


def test_no_user_profiles(tmp_path: Path) -> None:
    """An image with no collected profiles has no flow directory to walk."""
    plugin = _make_plugin(tmp_path, user_profiles=[])

    findings = plugin.run()
    assert findings == []
