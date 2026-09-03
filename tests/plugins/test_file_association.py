"""Tests for the file association hijack plugin (T1546)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel, Finding, Severity, UserProfile
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1546.file_association import (
    FileAssociationHijack,
)

from .conftest import make_node, make_plugin, setup_keys, setup_usrclass

if TYPE_CHECKING:
    from pathlib import Path

_DROPPED_HANDLER = r'"C:\Users\victim\AppData\Roaming\updater.exe" "%1"'


def _victim(tmp_path: Path) -> UserProfile:
    """Return a profile whose UsrClass.dat was collected."""
    return UserProfile(
        username="victim",
        profile_path=tmp_path / "Users" / "victim",
        ntuser_path=tmp_path / "NTUSER.DAT",
        usrclass_path=tmp_path / "UsrClass.dat",
    )


def _classify(finding: Finding) -> Severity:
    """Classify a finding with the shipped profile, as a real scan would."""
    policy = DetectionProfile.load(None).policy_for("file_association_hijack")
    return policy.classify(finding)


def test_script_interpreter_flagged(tmp_path: Path) -> None:
    """An open command routed through cmd.exe is a hijack, not a real handler."""
    plugin = make_plugin(FileAssociationHijack, tmp_path)
    setup_keys(
        plugin,
        {
            r"Classes\.txt\shell\open\command": make_node(
                values={"(Default)": r'"C:\Windows\System32\cmd.exe" /c evil.bat'}
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == r"HKLM\SOFTWARE\Classes\.txt\shell\open\command"
    assert "cmd.exe" in findings[0].value


def test_plain_executable_handler_flagged(tmp_path: Path) -> None:
    """A handler repointed at a dropped EXE is the commonest hijack and must fire."""
    plugin = make_plugin(FileAssociationHijack, tmp_path)
    setup_keys(
        plugin,
        {
            r"Classes\.txt\shell\open\command": make_node(
                values={"(Default)": _DROPPED_HANDLER}
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == _DROPPED_HANDLER
    assert findings[0].access_gained is AccessLevel.SYSTEM


def test_unquoted_handler_with_spaces_reported_whole(tmp_path: Path) -> None:
    """The handler is reported verbatim, not truncated at the first space."""
    plugin = make_plugin(FileAssociationHijack, tmp_path)
    command = r"C:\Users\victim\My Tools\viewer.exe %1"
    setup_keys(
        plugin,
        {r"Classes\.pdf\shell\open\command": make_node(values={"(Default)": command})},
    )

    findings = plugin.run()

    assert [finding.value for finding in findings] == [command]


def test_signed_default_handler_stays_quiet_in_the_profile() -> None:
    """A Microsoft-signed non-LOLBin handler is suppressed by the profile, not run()."""
    finding = Finding(
        path=r"HKLM\SOFTWARE\Classes\htmlfile\shell\open\command",
        value=r'"C:\Program Files\Internet Explorer\iexplore.exe" %1',
        check_id="file_association_hijack",
        signer="Microsoft Windows",
        is_lolbin=False,
    )

    assert _classify(finding) < Severity.MEDIUM


def test_dropped_handler_is_recoverable_from_the_command_line() -> None:
    """The dropped-EXE hijack survives run(), so --min-severity can still reach it."""
    finding = Finding(
        path=r"HKU\victim\Software\Classes\txtfile\shell\open\command",
        value=_DROPPED_HANDLER,
        check_id="file_association_hijack",
        signer="",
        is_lolbin=False,
    )

    assert _classify(finding) > Severity.INFO


def test_progid_handler_reported_once_for_both_extensions(tmp_path: Path) -> None:
    """.htm and .html share one progid key, which must not be reported twice."""
    plugin = make_plugin(FileAssociationHijack, tmp_path)
    setup_keys(
        plugin,
        {
            r"Classes\.htm": make_node(values={"(Default)": "htmlfile"}),
            r"Classes\.html": make_node(values={"(Default)": "htmlfile"}),
            r"Classes\htmlfile\shell\open\command": make_node(
                values={"(Default)": r"C:\evil\hijack.exe %1"}
            ),
        },
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"HKLM\SOFTWARE\Classes\htmlfile\shell\open\command"
    ]


def test_no_hive_returns_empty(tmp_path: Path) -> None:
    """A missing hive is a clean absence, not a scan failure."""
    plugin = make_plugin(FileAssociationHijack, tmp_path)
    plugin.context.hive_path.return_value = None
    plugin.registry.open_hive.return_value = None
    assert plugin.run() == []


def test_per_user_handler_read_from_the_hive_root(tmp_path: Path) -> None:
    """The per-user lookup addresses the hive at its root, with no classes prefix."""
    plugin = make_plugin(
        FileAssociationHijack, tmp_path, user_profiles=[_victim(tmp_path)]
    )
    command = make_node(values={"(Default)": r"mshta.exe evil.hta"})
    setup_usrclass(plugin, {r".txt\shell\open\command": command})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (r"HKU\victim\Software\Classes\.txt\shell\open\command")
    assert findings[0].access_gained is AccessLevel.USER


def test_per_user_handler_not_read_from_a_prefixed_path(tmp_path: Path) -> None:
    """A hive answering only the prefixed path yields nothing, as on real images."""
    plugin = make_plugin(
        FileAssociationHijack, tmp_path, user_profiles=[_victim(tmp_path)]
    )
    command = make_node(values={"(Default)": r"mshta.exe evil.hta"})
    setup_usrclass(plugin, {r"Software\Classes\.txt\shell\open\command": command})

    assert plugin.run() == []


def test_per_user_progid_indirection(tmp_path: Path) -> None:
    """A progid redirect is followed at the hive root as well."""
    plugin = make_plugin(
        FileAssociationHijack, tmp_path, user_profiles=[_victim(tmp_path)]
    )
    setup_usrclass(
        plugin,
        {
            ".txt": make_node(values={"(Default)": "evilfile"}),
            r"evilfile\shell\open\command": make_node(
                values={"(Default)": r"wscript.exe evil.vbs"}
            ),
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKU\victim\Software\Classes\evilfile\shell\open\command"
    )
