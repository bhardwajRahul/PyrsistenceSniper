"""Tests for the protocol handler hijack plugins (T1546)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pyrsistencesniper.core.models import (
    AccessLevel,
    FilterRule,
    Finding,
    MatchResult,
)
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1546.protocol_handlers import (
    ProtocolHandlerHijack,
    SearchProtocolHandler,
)

from .conftest import (
    make_node,
    make_plugin,
    make_user_profiles,
    setup_hklm,
    setup_keys,
    setup_usrclass,
)


class TestProtocolHandlerHijack:
    """Cases for the machine-wide and per-user protocol handler command scan."""

    def test_no_hive_returns_empty(self, tmp_path: Path) -> None:
        """An uncollected SOFTWARE hive is a clean absence, not a scan failure."""
        plugin = make_plugin(ProtocolHandlerHijack, tmp_path)
        plugin.context.hive_path.return_value = None
        assert plugin.run() == []

    def test_hklm_happy_path(self, tmp_path: Path) -> None:
        """A machine-wide handler is reported with the executable its command names."""
        node = make_node(values={"(Default)": r"C:\evil.exe %1"})
        plugin = make_plugin(ProtocolHandlerHijack, tmp_path)
        setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
        findings = plugin.run()
        assert len(findings) >= 1
        assert any("evil.exe" in finding.value for finding in findings)

    def test_hku_happy_path(self, tmp_path: Path) -> None:
        """A per-user handler is reported under the profile that owns it."""
        # Without usrclass_path the per-user hive is unreachable and only the
        # machine hive is scanned, so this case would never touch HKU.
        plugin = make_plugin(
            ProtocolHandlerHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        plugin.context.hive_path.return_value = None
        hive_mock = MagicMock()
        hive_mock.get_key_by_path.return_value.get_number_of_sub_keys.return_value = 0
        plugin.registry.open_hive.return_value = hive_mock

        node = make_node(values={"(Default)": r"C:\evil.exe %1"})
        plugin.registry.load_subtree.return_value = node

        findings = plugin.run()
        assert findings
        assert all(finding.path.startswith("HKU\\victim\\") for finding in findings)
        assert any("evil.exe" in finding.value for finding in findings)

    def test_no_value_skipped(self, tmp_path: Path) -> None:
        """A handler key carrying no command subtree contributes nothing."""
        plugin = make_plugin(ProtocolHandlerHijack, tmp_path)
        plugin.context.hive_path.return_value = None
        plugin.registry.open_hive.return_value = None
        plugin.registry.load_subtree.return_value = None
        assert plugin.run() == []


class _FakeValue:
    """pyregf value stub; get_name() is None for the unnamed default value."""

    def __init__(self, name: str | None) -> None:
        """Record the value name, or None for the unnamed default."""
        self._name = name

    def get_name(self) -> str | None:
        """None is how pyregf spells the unnamed default value."""
        return self._name


class _FakeKey:
    """pyregf key stub exposing the enumeration surface the plugin walks."""

    def __init__(
        self,
        name: str,
        values: list[_FakeValue] | None = None,
        sub_keys: list[_FakeKey] | None = None,
    ) -> None:
        """Record the key name and the values and subkeys it enumerates."""
        self._name = name
        self._values = values or []
        self._sub_keys = sub_keys or []

    def get_name(self) -> str:
        """The subkey name the scan matches against the known-protocol list."""
        return self._name

    def get_number_of_sub_keys(self) -> int:
        """Bound for the custom-protocol enumeration."""
        return len(self._sub_keys)

    def get_sub_key(self, index: int) -> _FakeKey:
        """Subkeys are addressed by index, as libregf exposes them."""
        return self._sub_keys[index]

    def get_number_of_values(self) -> int:
        """Bound for the URL Protocol marker search."""
        return len(self._values)

    def get_value(self, index: int) -> _FakeValue:
        """Values are addressed by index, as libregf exposes them."""
        return self._values[index]


class _FakeHive:
    """pyregf file stub answering every path with the one Classes key it holds."""

    def __init__(self, classes_key: _FakeKey) -> None:
        """Record the single Classes key this hive answers every path with."""
        self._classes_key = classes_key

    def get_key_by_path(self, path: str) -> _FakeKey:
        """Path spelling is ignored, so these cases turn only on the enumeration."""
        return self._classes_key


def _make_custom_protocol_plugin(
    tmp_path: Path, protocol_key: _FakeKey
) -> ProtocolHandlerHijack:
    """Wire a plugin whose Classes key holds the given protocol key."""
    plugin = make_plugin(ProtocolHandlerHijack, tmp_path)
    classes_key = _FakeKey("Classes", sub_keys=[protocol_key])
    plugin.registry.open_hive.return_value = _FakeHive(classes_key)
    evil_node = make_node(values={"(Default)": r"C:\evil.exe %1"})
    plugin.registry.load_subtree.side_effect = lambda hive, path: (
        evil_node if protocol_key.get_name().lower() in path.lower() else None
    )
    return plugin


class TestCustomProtocolScan:
    """Cases for finding handlers by their URL Protocol marker value."""

    def test_url_protocol_found_after_unnamed_default_value(
        self, tmp_path: Path
    ) -> None:
        """pyregf reports the unnamed default as None, which must not end the walk."""
        key = _FakeKey(
            "evilproto", values=[_FakeValue(None), _FakeValue("URL Protocol")]
        )
        plugin = _make_custom_protocol_plugin(tmp_path, key)
        findings = plugin.run()
        assert len(findings) == 1
        assert "evil.exe" in findings[0].value
        assert "evilproto" in findings[0].path

    def test_key_with_only_default_value_is_skipped(self, tmp_path: Path) -> None:
        """A key without a URL Protocol value is not a protocol handler."""
        key = _FakeKey("plainclass", values=[_FakeValue(None)])
        plugin = _make_custom_protocol_plugin(tmp_path, key)
        assert plugin.run() == []


def _msdt_rule() -> FilterRule:
    """Locate the msdt allow rule for protocol_handler_hijack by content."""
    allow = DetectionProfile.load(None).policy_for("protocol_handler_hijack").allow
    matched = [rule for rule in allow if "msdt" in rule.value_matches]
    assert len(matched) == 1
    return matched[0]


class TestProtocolHandlerMsdtFilterRule:
    """Cases for the profile rule that allows a signed msdt and nothing else."""

    @pytest.mark.parametrize(
        ("value", "signer", "expected"),
        [
            (
                r"C:\Windows\system32\msdt.exe -id",
                "Microsoft Windows",
                MatchResult.FULL,
            ),
            (r"C:\Windows\system32\msdt.exe -id", "", MatchResult.PARTIAL),
            (r"C:\evil.exe %1", "Microsoft Windows", MatchResult.NONE),
        ],
        ids=["msdt-signed-full", "msdt-unsigned-partial", "evil-exe-none"],
    )
    def test_match_result(self, value: str, signer: str, expected: MatchResult) -> None:
        """Only the signer separates a full allow from a partial one."""
        finding = Finding(value=value, signer=signer)
        assert _msdt_rule().match_result(finding) == expected


class TestSearchProtocolHandler:
    """Cases for search-ms, the Follina-era handler checked on its own."""

    def test_hklm_happy_path(self, tmp_path: Path) -> None:
        """A hijacked search-ms command is reported like any other handler."""
        node = make_node(values={"(Default)": r"C:\evil.exe %1"})
        plugin = make_plugin(SearchProtocolHandler, tmp_path)
        setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
        findings = plugin.run()
        assert len(findings) >= 1
        assert any("evil.exe" in finding.value for finding in findings)


class TestPerUserProtocolHandlers:
    """The per-user scan addresses UsrClass.dat at its root."""

    @staticmethod
    def _empty_classes_key() -> MagicMock:
        """Return a classes key with no custom protocol subkeys to enumerate."""
        classes_key = MagicMock()
        classes_key.get_number_of_sub_keys.return_value = 0
        return classes_key

    def test_known_protocol_read_from_the_hive_root(self, tmp_path: Path) -> None:
        """The lookup drops the classes prefix the hive root already supplies."""
        plugin = make_plugin(
            ProtocolHandlerHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_usrclass(
            plugin,
            {
                r"http\shell\open\command": make_node(
                    values={"(Default)": r"C:\evil.exe %1"}
                )
            },
        )
        plugin.registry.open_hive.return_value.get_key_by_path.return_value = (
            self._empty_classes_key()
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\victim\Software\Classes\http\shell\open\command"
        )

    def test_known_protocol_not_read_from_a_prefixed_path(self, tmp_path: Path) -> None:
        """A hive answering only the prefixed path yields nothing."""
        plugin = make_plugin(
            ProtocolHandlerHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_usrclass(
            plugin,
            {
                r"Software\Classes\http\shell\open\command": make_node(
                    values={"(Default)": r"C:\evil.exe %1"}
                )
            },
        )
        plugin.registry.open_hive.return_value.get_key_by_path.return_value = (
            self._empty_classes_key()
        )

        assert plugin.run() == []


class _NamedHive(_FakeHive):
    """A classes hive tagged with the hive file it stands for."""

    def __init__(self, name: str, classes_key: _FakeKey) -> None:
        """Tag the hive with the file name load_subtree discriminates on."""
        super().__init__(classes_key)
        self.name = name


def _wire_two_hives(
    plugin: ProtocolHandlerHijack,
    machine_classes: _FakeKey,
    user_classes: _FakeKey,
    subtrees: dict[tuple[str, str], object],
) -> None:
    """Answer open_hive and load_subtree separately for SOFTWARE and UsrClass.dat."""
    machine_hive = _NamedHive("software", machine_classes)
    user_hive = _NamedHive("usrclass.dat", user_classes)

    def _open_hive(path: Path) -> _NamedHive:
        """Pick the hive the caller asked for by its file name."""
        return machine_hive if Path(path).name.lower() == "software" else user_hive

    def _load_subtree(hive: _NamedHive, key_path: str) -> object | None:
        """Answer only the (hive, key path) pairs the case wired."""
        return subtrees.get((hive.name, key_path.lower().strip("\\")))

    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    plugin.registry.open_hive.side_effect = _open_hive
    plugin.registry.load_subtree.side_effect = _load_subtree


class TestShadowedProtocolHandlers:
    """A per-user class key shadows HKLM without carrying a URL Protocol value."""

    _COMMAND_KEY = r"ms-settings\shell\open\command"
    _PAYLOAD = r"C:\Users\victim\payload.exe"

    def test_per_user_shadow_of_a_machine_protocol_is_reported(
        self, tmp_path: Path
    ) -> None:
        """The fodhelper key carries no marker, so only the HKLM one identifies it."""
        plugin = make_plugin(
            ProtocolHandlerHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        _wire_two_hives(
            plugin,
            _FakeKey(
                "Classes",
                sub_keys=[_FakeKey("ms-settings", values=[_FakeValue("URL Protocol")])],
            ),
            _FakeKey("", sub_keys=[_FakeKey("ms-settings", values=[_FakeValue(None)])]),
            {
                ("usrclass.dat", self._COMMAND_KEY): make_node(
                    values={"(Default)": self._PAYLOAD}
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\victim\Software\Classes\ms-settings\shell\open\command"
        )
        assert findings[0].value == self._PAYLOAD
        assert findings[0].access_gained is AccessLevel.USER

    def test_per_user_class_shadowing_nothing_stays_quiet(self, tmp_path: Path) -> None:
        """Most per-user classes are ordinary file associations and must stay quiet."""
        plugin = make_plugin(
            ProtocolHandlerHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        _wire_two_hives(
            plugin,
            _FakeKey("Classes", sub_keys=[]),
            _FakeKey("", sub_keys=[_FakeKey("ms-settings", values=[_FakeValue(None)])]),
            {
                ("usrclass.dat", self._COMMAND_KEY): make_node(
                    values={"(Default)": self._PAYLOAD}
                )
            },
        )

        assert plugin.run() == []

    def test_machine_class_without_a_marker_stays_quiet(self, tmp_path: Path) -> None:
        """The shadow allowance is per-user only; HKLM is the store being shadowed."""
        plugin = make_plugin(ProtocolHandlerHijack, tmp_path)
        _wire_two_hives(
            plugin,
            _FakeKey(
                "Classes", sub_keys=[_FakeKey("ms-settings", values=[_FakeValue(None)])]
            ),
            _FakeKey("", sub_keys=[]),
            {
                ("software", r"classes\ms-settings\shell\open\command"): make_node(
                    values={"(Default)": self._PAYLOAD}
                )
            },
        )

        assert plugin.run() == []


class TestPerUserSearchProtocolHandler:
    """search-ms is registered per user in UsrClass.dat, never in NTUSER.DAT."""

    _PAYLOAD = r"C:\Users\victim\AppData\Local\Temp\a.exe %1"

    def test_per_user_search_ms_read_from_the_hive_root(self, tmp_path: Path) -> None:
        """The lookup drops the classes prefix the UsrClass.dat root supplies."""
        plugin = make_plugin(
            SearchProtocolHandler, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin,
            {
                r"search-ms\shell\open\command": make_node(
                    values={"(Default)": self._PAYLOAD}
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\victim\Software\Classes\search-ms\shell\open\command"
        )
        assert findings[0].access_gained is AccessLevel.USER

    def test_per_user_search_ms_not_read_from_a_prefixed_path(
        self, tmp_path: Path
    ) -> None:
        """A UsrClass.dat answering only the prefixed path yields nothing."""
        plugin = make_plugin(
            SearchProtocolHandler, tmp_path, user_profiles=make_user_profiles("victim")
        )
        wiring = {
            r"software\classes\search-ms\shell\open\command": make_node(
                values={"(Default)": self._PAYLOAD}
            )
        }

        def _open_hive(path: Path) -> str:
            """Name the hive file being opened so load_subtree can discriminate."""
            return Path(path).name.lower()

        def _load_subtree(hive: str, key_path: str) -> object | None:
            """Answer out of UsrClass.dat only, so an NTUSER.DAT read finds nothing."""
            if hive != "usrclass.dat":
                return None
            return wiring.get(key_path.lower().strip("\\"))

        plugin.context.hive_path.return_value = None
        plugin.registry.open_hive.side_effect = _open_hive
        plugin.registry.load_subtree.side_effect = _load_subtree

        assert plugin.run() == []

    def test_undeclared_per_user_protocol_stays_quiet(self, tmp_path: Path) -> None:
        """A per-user protocol this check never declares is not read by it."""
        plugin = make_plugin(
            SearchProtocolHandler, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin,
            {
                r"search\shell\open\command": make_node(
                    values={"(Default)": self._PAYLOAD}
                )
            },
        )

        assert plugin.run() == []
