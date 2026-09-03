"""Tests for the Outlook Home Page WebView URL plugin (T1137.004)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1137.outlook_home_page import OutlookHomePage

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_WEBVIEW_KEY = r"Software\Microsoft\Office\16.0\Outlook\WebView"


def test_happy_path(tmp_path: Path) -> None:
    """A WebView URL runs in the mailbox owner's context, so it is USER access."""
    plugin = make_plugin(
        OutlookHomePage, tmp_path, user_profiles=make_user_profiles("victim")
    )
    setup_keys(
        plugin,
        {
            _WEBVIEW_KEY: make_node(
                name="WebView",
                children={
                    "Inbox": make_node(
                        name="Inbox",
                        values={"URL": "http://evil.example.com/payload.html"},
                    )
                },
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.value == "http://evil.example.com/payload.html"
    assert finding.access_gained == AccessLevel.USER
    assert finding.path == rf"HKU\victim\{_WEBVIEW_KEY}\Inbox\URL"


def test_user_created_folder_is_covered(tmp_path: Path) -> None:
    """A home page can be set on any folder, so the subkeys are enumerated."""
    plugin = make_plugin(
        OutlookHomePage, tmp_path, user_profiles=make_user_profiles("victim")
    )
    setup_keys(
        plugin,
        {
            _WEBVIEW_KEY: make_node(
                name="WebView",
                children={
                    "Archive": make_node(
                        name="Archive", values={"URL": "http://198.51.100.7/p.html"}
                    )
                },
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == rf"HKU\victim\{_WEBVIEW_KEY}\Archive\URL"


def test_localized_folder_name_is_covered(tmp_path: Path) -> None:
    """A non-English Outlook names its folders in that language, and it still fires."""
    plugin = make_plugin(
        OutlookHomePage, tmp_path, user_profiles=make_user_profiles("victim")
    )
    setup_keys(
        plugin,
        {
            _WEBVIEW_KEY: make_node(
                name="WebView",
                children={
                    "Posteingang": make_node(
                        name="Posteingang",
                        values={"URL": "http://198.51.100.7/p.html"},
                    )
                },
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == rf"HKU\victim\{_WEBVIEW_KEY}\Posteingang\URL"


def test_no_users_returns_empty(tmp_path: Path) -> None:
    """With no collected user hives there is nothing to scan, and that is no error."""
    assert make_plugin(OutlookHomePage, tmp_path).run() == []


def test_no_url_value_skipped(tmp_path: Path) -> None:
    """A WebView folder key without a URL loads nothing and is not persistence."""
    plugin = make_plugin(
        OutlookHomePage, tmp_path, user_profiles=make_user_profiles("victim")
    )
    setup_keys(
        plugin,
        {
            _WEBVIEW_KEY: make_node(
                name="WebView",
                children={
                    "Inbox": make_node(name="Inbox", values={"Flags": 1}),
                    "Calendar": make_node(name="Calendar", values={"URL": "   "}),
                },
            )
        },
    )

    assert plugin.run() == []


def test_webview_key_without_folders_stays_quiet(tmp_path: Path) -> None:
    """An Outlook profile that never set a home page carries no folder subkey."""
    plugin = make_plugin(
        OutlookHomePage, tmp_path, user_profiles=make_user_profiles("victim")
    )
    setup_keys(plugin, {_WEBVIEW_KEY: make_node(name="WebView")})

    assert plugin.run() == []
