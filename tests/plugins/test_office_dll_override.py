"""Tests for the OfficeDllOverride plugin (T1137)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1137.office_dll_override import OfficeDllOverride

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

if TYPE_CHECKING:
    from pathlib import Path


def test_word_override_dll_produces_finding(tmp_path: Path) -> None:
    """A WwlibtDll value on the machine Word key loads that DLL for every user."""
    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_keys(
        plugin,
        {
            r"Microsoft\Office\16.0\Word": make_node(
                name="Word", values={"WwlibtDll": r"C:\evil.dll"}
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.value == r"C:\evil.dll"
    assert finding.access_gained == AccessLevel.SYSTEM
    assert finding.path == r"HKLM\SOFTWARE\Microsoft\Office\16.0\Word\WwlibtDll"


def test_per_user_word_override_dll_produces_finding(tmp_path: Path) -> None:
    """The per-user key needs no admin rights, which is the point of the technique."""
    plugin = make_plugin(
        OfficeDllOverride, tmp_path, user_profiles=make_user_profiles("alice")
    )
    setup_keys(
        plugin,
        {
            r"Software\Microsoft\Office\16.0\Word": make_node(
                name="Word",
                values={"WwlibtDll": r"C:\Users\alice\AppData\Local\wwlib.dll"},
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.value == r"C:\Users\alice\AppData\Local\wwlib.dll"
    assert finding.access_gained == AccessLevel.USER
    assert finding.path == r"HKU\alice\Software\Microsoft\Office\16.0\Word\WwlibtDll"


def test_powerpoint_override_dll_produces_finding(tmp_path: Path) -> None:
    """Each Office app names its override differently, so every value is checked."""
    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_keys(
        plugin,
        {
            r"Microsoft\Office\15.0\PowerPoint": make_node(
                name="PowerPoint", values={"PPCoreTDLL": r"C:\evil_ppt.dll"}
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == r"C:\evil_ppt.dll"
    assert findings[0].path.endswith(r"15.0\PowerPoint\PPCoreTDLL")


def test_click_to_run_mirror_is_covered(tmp_path: Path) -> None:
    """A ClickToRun install mirrors the machine registry, and Office reads it there."""
    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_keys(
        plugin,
        {
            r"Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software"
            r"\Microsoft\Office\16.0\Word": make_node(
                name="Word", values={"WwlibtDll": r"C:\evil_c2r.dll"}
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == r"C:\evil_c2r.dll"


def test_office_subtree_alone_is_never_read(tmp_path: Path) -> None:
    """The check reads the application keys, not the Office subtree that holds them."""
    word_node = make_node(name="Word", values={"WwlibtDll": r"C:\evil.dll"})
    version_node = make_node(name="16.0", children={"Word": word_node})
    office_tree = make_node(name="Office", children={"16.0": version_node})

    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_keys(plugin, {r"Microsoft\Office": office_tree})

    assert plugin.run() == []


def test_application_key_without_override_stays_quiet(tmp_path: Path) -> None:
    """An Office application key on its own is a normal install, not an override."""
    plugin = make_plugin(
        OfficeDllOverride, tmp_path, user_profiles=make_user_profiles("alice")
    )
    settings_node = make_node(name="Word", values={"NoReReg": 1})
    setup_keys(
        plugin,
        {
            r"Microsoft\Office\16.0\Word": settings_node,
            r"Software\Microsoft\Office\16.0\Word": settings_node,
        },
    )

    assert plugin.run() == []
