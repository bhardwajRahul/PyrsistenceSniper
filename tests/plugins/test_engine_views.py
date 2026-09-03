"""The declarative engine's 32-bit registry view and per-user class registrations."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    HiveScope,
    RegistryTarget,
    UserProfile,
)
from pyrsistencesniper.plugins.base import PersistencePlugin

from .conftest import make_node, make_plugin

_USERNAME = "alice"
_PAYLOAD = r"C:\Users\alice\AppData\Roaming\payload.exe"
_OTHER_PAYLOAD = r"C:\Users\alice\AppData\Roaming\other.exe"


class MachineRunWow64Check(PersistencePlugin):
    """Machine Run key opting into the 32-bit registry view."""

    definition = CheckDefinition(
        id="engine_machine_run_wow64",
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.HKLM,
                include_wow64=True,
            ),
        ),
    )


class MachineRunNativeCheck(PersistencePlugin):
    """Machine Run key that never opted into the 32-bit registry view."""

    definition = CheckDefinition(
        id="engine_machine_run_native",
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.HKLM,
            ),
        ),
    )


class MachineClassesWow64Check(PersistencePlugin):
    """Machine COM class registration opting into the 32-bit registry view."""

    definition = CheckDefinition(
        id="engine_machine_classes_wow64",
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{0006F03A-0000-0000-C000-000000000046}"
                r"\InprocServer32",
                values="(Default)",
                scope=HiveScope.HKLM,
                include_wow64=True,
            ),
        ),
    )


class SystemHiveWow64Check(PersistencePlugin):
    """A SYSTEM-hive target, which WOW64 redirection never applies to."""

    definition = CheckDefinition(
        id="engine_system_hive_wow64",
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\Example",
                scope=HiveScope.HKLM,
                include_wow64=True,
            ),
        ),
    )


class UserClassesCheck(PersistencePlugin):
    """A per-user COM class registration under the classes subtree."""

    definition = CheckDefinition(
        id="engine_user_classes",
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
        ),
    )


class UserClassesWow64Check(PersistencePlugin):
    """A per-user class registration opting into the 32-bit registry view."""

    definition = CheckDefinition(
        id="engine_user_classes_wow64",
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
                include_wow64=True,
            ),
        ),
    )


class UserNonClassesCheck(PersistencePlugin):
    """A per-user target outside the classes subtree, which UsrClass.dat never holds."""

    definition = CheckDefinition(
        id="engine_user_non_classes",
        targets=(
            RegistryTarget(
                path=r"Software\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.HKU,
                include_wow64=True,
            ),
        ),
    )


def _profiles(*, with_usrclass: bool = True) -> list[UserProfile]:
    """Return one user profile carrying the per-user hives discovery would find."""
    usrclass = Path(f"/img/Users/{_USERNAME}/UsrClass.dat") if with_usrclass else None
    return [
        UserProfile(
            username=_USERNAME,
            profile_path=Path(f"/img/Users/{_USERNAME}"),
            ntuser_path=Path(f"/img/Users/{_USERNAME}/NTUSER.DAT"),
            usrclass_path=usrclass,
        )
    ]


def setup_hive_keys(plugin: object, hives: dict[str, dict[str, object]]) -> None:
    """Wire each named hive file to answer only the key paths listed under it."""
    lookup = {
        (hive_name.lower(), key_path.lower().strip("\\")): node
        for hive_name, keys in hives.items()
        for key_path, node in keys.items()
    }

    def _open_hive(path: Path) -> str:
        """Return a handle naming the hive file, which the engine passes onward."""
        return Path(path).name.lower()

    def _load_subtree(hive: str, key_path: str) -> object | None:
        """Answer only the key paths wired for the hive file being read."""
        return lookup.get((hive, key_path.lower().strip("\\")))

    def _hive_path(hive_name: str, username: str = "") -> Path:
        """Name a machine hive file the way discovery would, so open_hive sees it."""
        return Path(f"/img/{hive_name}")

    plugin.context.hive_path.side_effect = _hive_path  # type: ignore[attr-defined]
    plugin.registry.open_hive.side_effect = _open_hive  # type: ignore[attr-defined]
    plugin.registry.load_subtree.side_effect = _load_subtree  # type: ignore[attr-defined]


def _payload_node(value_name: str = "(Default)", value: str = _PAYLOAD) -> object:
    """Build a registry node holding one payload value."""
    return make_node(values={value_name: value})


def test_wow64_opt_in_reads_the_redirected_machine_key(tmp_path: Path) -> None:
    """A target opting in is read from Wow6432Node inserted after SOFTWARE."""
    plugin = make_plugin(MachineRunWow64Check, tmp_path)
    setup_hive_keys(
        plugin,
        {
            "software": {
                r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run": _payload_node(
                    "Evil"
                )
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\Evil"
    )
    assert findings[0].value == _PAYLOAD
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_wow64_opt_out_leaves_the_redirected_machine_key_unread(
    tmp_path: Path,
) -> None:
    """A target that did not opt in never reads the 32-bit view, so nothing fires."""
    plugin = make_plugin(MachineRunNativeCheck, tmp_path)
    setup_hive_keys(
        plugin,
        {
            "software": {
                r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run": _payload_node(
                    "Evil"
                )
            }
        },
    )

    assert plugin.run() == []


def test_wow64_opt_in_still_reads_the_native_key_exactly_once(tmp_path: Path) -> None:
    """Opting into the 32-bit view leaves the native view reported once, not twice."""
    plugin = make_plugin(MachineRunWow64Check, tmp_path)
    setup_hive_keys(
        plugin,
        {
            "software": {
                r"Microsoft\Windows\CurrentVersion\Run": _payload_node("Evil"),
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil"
    )


def test_wow64_inserts_the_node_after_classes_for_class_registrations(
    tmp_path: Path,
) -> None:
    """Under SOFTWARE\\Classes the redirection node goes after Classes, not before."""
    plugin = make_plugin(MachineClassesWow64Check, tmp_path)
    setup_hive_keys(
        plugin,
        {
            "software": {
                r"Classes\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}"
                r"\InprocServer32": _payload_node()
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Classes\Wow6432Node"
        r"\CLSID\{0006F03A-0000-0000-C000-000000000046}\InprocServer32"
    )


def test_wow64_does_not_put_the_node_before_classes(tmp_path: Path) -> None:
    """The hive-root redirection never applies to a classes path, so it stays quiet."""
    plugin = make_plugin(MachineClassesWow64Check, tmp_path)
    setup_hive_keys(
        plugin,
        {
            "software": {
                r"Wow6432Node\Classes\CLSID\{0006F03A-0000-0000-C000-000000000046}"
                r"\InprocServer32": _payload_node()
            }
        },
    )

    assert plugin.run() == []


def test_wow64_leaves_hives_other_than_software_unredirected(tmp_path: Path) -> None:
    """Only the SOFTWARE hive is redirected, so a SYSTEM target gains no second view."""
    plugin = make_plugin(SystemHiveWow64Check, tmp_path)
    setup_hive_keys(
        plugin,
        {
            "system": {
                r"Wow6432Node\ControlSet001\Services\Example": _payload_node("Evil")
            }
        },
    )

    assert plugin.run() == []


def test_system_hive_target_still_reads_its_native_key(tmp_path: Path) -> None:
    """Opting into the 32-bit view does not disturb the SYSTEM hive's native read."""
    plugin = make_plugin(SystemHiveWow64Check, tmp_path)
    setup_hive_keys(
        plugin,
        {"system": {r"ControlSet001\Services\Example": _payload_node("Evil")}},
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == r"HKLM\SYSTEM\ControlSet001\Services\Example\Evil"


def test_per_user_class_registration_is_read_from_usrclass(tmp_path: Path) -> None:
    """A hijack stored only in UsrClass.dat, at the stripped path, is reported."""
    plugin = make_plugin(UserClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "usrclass.dat": {
                r"CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command": (
                    _payload_node()
                )
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKU\alice\SOFTWARE\Classes"
        r"\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command"
    )
    assert findings[0].value == _PAYLOAD
    assert findings[0].access_gained == AccessLevel.USER


def test_per_user_class_registration_is_quiet_when_neither_hive_holds_it(
    tmp_path: Path,
) -> None:
    """The unstripped path inside UsrClass.dat is not where class data lives."""
    plugin = make_plugin(UserClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "usrclass.dat": {
                r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command": _payload_node()
            }
        },
    )

    assert plugin.run() == []


def test_per_user_class_path_is_identical_whichever_hive_supplied_it(
    tmp_path: Path,
) -> None:
    """An analyst cannot tell the two per-user hives apart by the reported path."""
    from_ntuser = make_plugin(UserClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        from_ntuser,
        {
            "ntuser.dat": {
                r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command": _payload_node()
            }
        },
    )
    from_usrclass = make_plugin(UserClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        from_usrclass,
        {
            "usrclass.dat": {
                r"CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command": (
                    _payload_node()
                )
            }
        },
    )

    ntuser_findings = from_ntuser.run()
    usrclass_findings = from_usrclass.run()

    assert len(ntuser_findings) == 1
    assert len(usrclass_findings) == 1
    assert ntuser_findings[0].path == usrclass_findings[0].path


def test_same_entry_in_both_per_user_hives_is_reported_once(tmp_path: Path) -> None:
    """A REG_LINK-shadowed entry read twice must not become two identical rows."""
    plugin = make_plugin(UserClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "ntuser.dat": {
                r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command": _payload_node()
            },
            "usrclass.dat": {
                r"CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command": (
                    _payload_node()
                )
            },
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == _PAYLOAD


def test_differing_values_in_the_two_per_user_hives_are_both_reported(
    tmp_path: Path,
) -> None:
    """Deduplication drops repeats of one entry, never a genuinely different value."""
    plugin = make_plugin(UserClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "ntuser.dat": {
                r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command": _payload_node()
            },
            "usrclass.dat": {
                r"CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command": (
                    _payload_node(value=_OTHER_PAYLOAD)
                )
            },
        },
    )

    findings = plugin.run()

    assert len(findings) == 2
    assert {finding.value for finding in findings} == {_PAYLOAD, _OTHER_PAYLOAD}


def test_per_user_target_outside_classes_never_reads_usrclass(tmp_path: Path) -> None:
    """UsrClass.dat holds class registrations only, so other targets stay quiet."""
    plugin = make_plugin(UserNonClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "usrclass.dat": {
                r"Microsoft\Windows\CurrentVersion\Run": _payload_node("Evil")
            }
        },
    )

    assert plugin.run() == []


def test_per_user_target_outside_classes_still_reads_ntuser(tmp_path: Path) -> None:
    """The per-user classes rule leaves an ordinary NTUSER.DAT target untouched."""
    plugin = make_plugin(UserNonClassesCheck, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "ntuser.dat": {
                r"Software\Microsoft\Windows\CurrentVersion\Run": _payload_node("Evil")
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKU\alice\Software\Microsoft\Windows\CurrentVersion\Run\Evil"
    )


def test_per_user_wow64_class_registration_is_read_from_usrclass(
    tmp_path: Path,
) -> None:
    """The 32-bit per-user class view sits at Wow6432Node under the UsrClass root."""
    plugin = make_plugin(UserClassesWow64Check, tmp_path, user_profiles=_profiles())
    setup_hive_keys(
        plugin,
        {
            "usrclass.dat": {
                r"Wow6432Node\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command": _payload_node()
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == (
        r"HKU\alice\SOFTWARE\Classes\Wow6432Node"
        r"\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command"
    )


def test_per_user_class_target_reads_ntuser_when_usrclass_is_absent(
    tmp_path: Path,
) -> None:
    """A profile whose UsrClass.dat was never collected still reads NTUSER.DAT."""
    plugin = make_plugin(
        UserClassesCheck, tmp_path, user_profiles=_profiles(with_usrclass=False)
    )
    setup_hive_keys(
        plugin,
        {
            "ntuser.dat": {
                r"SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                r"\shell\open\command": _payload_node()
            }
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == _PAYLOAD
