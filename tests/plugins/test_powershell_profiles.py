"""Tests for PowerShellProfiles: system-wide and per-user scripts (T1546.013)."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.powershell_profiles import PowerShellProfiles

from .conftest import (
    make_node,
    make_plugin,
    make_user_profiles,
    setup_filesystem,
    setup_keys,
)

_USER_SHELL_FOLDERS_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)
_SHELL_FOLDERS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"


def test_system_profile_found(tmp_path: Path) -> None:
    """The $PSHOME profile runs for every user, so it is a SYSTEM-level hit."""
    plugin = make_plugin(PowerShellProfiles, tmp_path)
    setup_filesystem(
        plugin,
        {r"Windows\System32\WindowsPowerShell\v1.0\profile.ps1": ("evil-code")},
    )

    findings = plugin.run()

    assert len(findings) >= 1
    assert any("profile.ps1" in finding.value for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_user_profile_found(tmp_path: Path) -> None:
    """A profile under a user Documents folder runs only for that user."""
    profiles = [
        UserProfile(
            username="victim",
            profile_path=Path("/Users/victim"),
            ntuser_path=Path("/Users/victim/NTUSER.DAT"),
        ),
    ]
    plugin = make_plugin(PowerShellProfiles, tmp_path, user_profiles=profiles)
    setup_filesystem(
        plugin,
        {r"Users\victim\Documents\WindowsPowerShell\profile.ps1": "evil-code"},
    )

    findings = plugin.run()

    assert len(findings) >= 1
    assert any(finding.access_gained == AccessLevel.USER for finding in findings)


def test_multiple_system_profiles(tmp_path: Path) -> None:
    """$PSHOME holds an all-hosts and a host-specific profile, both executed."""
    plugin = make_plugin(PowerShellProfiles, tmp_path)
    setup_filesystem(
        plugin,
        {
            r"Windows\System32\WindowsPowerShell\v1.0\profile.ps1": "x",
            r"Windows\System32\WindowsPowerShell\v1.0"
            r"\Microsoft.PowerShell_profile.ps1": "y",
        },
    )

    findings = plugin.run()

    assert len(findings) == 2
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_powershell_core_system_profile_found(tmp_path: Path) -> None:
    """A profile beside pwsh.exe in $PSHOME runs for every user and is reported."""
    plugin = make_plugin(PowerShellProfiles, tmp_path)
    setup_filesystem(
        plugin,
        {
            r"Program Files\PowerShell\7\pwsh.exe": b"MZ",
            r"Program Files\PowerShell\7\profile.ps1": "downloader",
        },
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"Program Files\PowerShell\7\profile.ps1"
    ]
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert findings[0].resolve_target == findings[0].path


def test_powershell_core_version_directories_are_enumerated(tmp_path: Path) -> None:
    """$PSHOME is versioned, so the install root is walked instead of named."""
    plugin = make_plugin(PowerShellProfiles, tmp_path)
    setup_filesystem(
        plugin,
        {
            r"Program Files\PowerShell\7-preview\profile.ps1": "preview payload",
            r"Program Files (x86)\PowerShell\7\Microsoft.PowerShell_profile.ps1": "x86",
        },
    )

    findings = plugin.run()

    assert sorted(finding.path for finding in findings) == [
        r"Program Files (x86)\PowerShell\7\Microsoft.PowerShell_profile.ps1",
        r"Program Files\PowerShell\7-preview\profile.ps1",
    ]


def test_populated_pshome_without_a_profile_stays_quiet(tmp_path: Path) -> None:
    """A stock $PSHOME ships no profile script, so a real install reports nothing."""
    plugin = make_plugin(PowerShellProfiles, tmp_path)
    setup_filesystem(
        plugin,
        {
            r"Windows\System32\WindowsPowerShell\v1.0\powershell.exe": b"MZ",
            r"Windows\System32\WindowsPowerShell\v1.0\types.ps1xml": "<Types/>",
            r"Windows\System32\WindowsPowerShell\v1.0\Modules\Foo\Foo.psm1": "module",
            r"Program Files\PowerShell\7\pwsh.exe": b"MZ",
            r"Program Files\PowerShell\7\pwsh.dll": b"MZ",
        },
    )

    assert plugin.run() == []


def test_host_specific_profiles_found(tmp_path: Path) -> None:
    """The ISE and VSCode host profiles auto-execute too and must be reported."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_filesystem(
        plugin,
        {
            r"Users\testuser\Documents\WindowsPowerShell"
            r"\Microsoft.PowerShellISE_profile.ps1": "ise payload",
            r"Users\testuser\Documents\PowerShell\Microsoft.VSCode_profile.ps1": "vsc",
        },
    )

    findings = plugin.run()

    assert sorted(finding.path for finding in findings) == [
        r"Users\testuser\Documents\PowerShell\Microsoft.VSCode_profile.ps1",
        r"Users\testuser\Documents\WindowsPowerShell"
        r"\Microsoft.PowerShellISE_profile.ps1",
    ]
    assert all(finding.access_gained == AccessLevel.USER for finding in findings)


def test_module_and_script_files_stay_quiet(tmp_path: Path) -> None:
    """A stocked profile directory holds modules and scripts that never auto-execute."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_filesystem(
        plugin,
        {
            r"Users\testuser\Documents\WindowsPowerShell\Modules\Foo\Foo.psm1": "mod",
            r"Users\testuser\Documents\WindowsPowerShell\Scripts\helper.ps1": "helper",
            r"Users\testuser\Documents\PowerShell\PSReadLine\history.txt": "h",
        },
    )

    assert plugin.run() == []


def test_onedrive_documents_profile_found_without_a_hive(tmp_path: Path) -> None:
    """A OneDrive sync root on disk keeps a redirected profile reachable hive-less."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_filesystem(
        plugin,
        {
            r"Users\testuser\OneDrive - Contoso\Documents\WindowsPowerShell"
            r"\Microsoft.PowerShell_profile.ps1": "kfm payload",
        },
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"Users\testuser\OneDrive - Contoso\Documents\WindowsPowerShell"
        r"\Microsoft.PowerShell_profile.ps1"
    ]
    assert findings[0].resolve_target == findings[0].path


def test_redirected_documents_read_from_user_shell_folders(tmp_path: Path) -> None:
    """$PROFILE follows the recorded MyDocuments location, so the check must too."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_keys(
        plugin,
        {
            _USER_SHELL_FOLDERS_KEY: make_node(
                values={"Personal": r"%USERPROFILE%\Redirected\Docs"}
            )
        },
    )
    setup_filesystem(
        plugin,
        {
            r"Users\testuser\Redirected\Docs\PowerShell\profile.ps1": "redirected",
        },
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"Users\testuser\Redirected\Docs\PowerShell\profile.ps1"
    ]


def test_redirection_falls_back_to_shell_folders(tmp_path: Path) -> None:
    """User Shell Folders can be absent while Shell Folders still records the path."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_keys(
        plugin,
        {
            _SHELL_FOLDERS_KEY: make_node(
                values={"Personal": r"C:\Users\testuser\Redirected\Docs"}
            )
        },
    )
    setup_filesystem(
        plugin,
        {
            r"Users\testuser\Redirected\Docs\PowerShell\profile.ps1": "redirected",
        },
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"Users\testuser\Redirected\Docs\PowerShell\profile.ps1"
    ]


def test_redirection_ignores_an_undeclared_key(tmp_path: Path) -> None:
    """A hive answering only a key the check never names must not steer the scan."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_keys(
        plugin,
        {
            r"Software\Decoy\Never\Read": make_node(
                values={"Personal": r"%USERPROFILE%\Redirected\Docs"}
            )
        },
    )
    setup_filesystem(
        plugin,
        {
            r"Users\testuser\Redirected\Docs\PowerShell\profile.ps1": "redirected",
        },
    )

    assert plugin.run() == []


def test_one_script_reached_by_two_routes_is_reported_once(tmp_path: Path) -> None:
    """Redirection that points back at the default folder must not double-report."""
    plugin = make_plugin(
        PowerShellProfiles, tmp_path, user_profiles=make_user_profiles()
    )
    setup_keys(
        plugin,
        {
            _USER_SHELL_FOLDERS_KEY: make_node(
                values={"Personal": r"%USERPROFILE%\Documents"}
            )
        },
    )
    setup_filesystem(
        plugin,
        {r"Users\testuser\Documents\WindowsPowerShell\profile.ps1": "payload"},
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"Users\testuser\Documents\WindowsPowerShell\profile.ps1"
    ]
