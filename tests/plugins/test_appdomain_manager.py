"""Tests for the AppDomainManagerInjection plugin in T1574/appdomain_manager.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1574.appdomain_manager import AppDomainManagerInjection

from .conftest import make_node, make_plugin, setup_hklm


def test_system_environment_detected(tmp_path: Path) -> None:
    """Both APPDOMAIN_MANAGER_* variables in the system Environment key fire."""
    env_node = make_node(
        values={
            "APPDOMAIN_MANAGER_ASM": "EvilAssembly, Version=1.0.0.0",
            "APPDOMAIN_MANAGER_TYPE": "Evil.Manager",
        }
    )
    plugin = make_plugin(AppDomainManagerInjection, tmp_path)
    setup_hklm(plugin, env_node, hive_path="/fake/SYSTEM")
    findings = plugin.run()
    assert len(findings) == 2
    assert any("EvilAssembly" in finding.value for finding in findings)
    assert any("Evil.Manager" in finding.value for finding in findings)
    assert all(finding.check_id == "appdomain_manager" for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_user_environment_detected(tmp_path: Path) -> None:
    """APPDOMAIN_MANAGER_ASM in a user Environment key fires with USER access."""
    profile = UserProfile(
        username="testuser",
        profile_path=Path("/fake/Users/testuser"),
        ntuser_path=Path("/fake/ntuser.dat"),
    )
    env_node = make_node(values={"APPDOMAIN_MANAGER_ASM": "EvilAssembly"})
    plugin = make_plugin(AppDomainManagerInjection, tmp_path, user_profiles=[profile])
    plugin.context.hive_path.return_value = None
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = env_node
    findings = plugin.run()
    assert len(findings) == 1
    assert "EvilAssembly" in findings[0].value
    assert findings[0].check_id == "appdomain_manager"
    assert findings[0].access_gained == AccessLevel.USER
