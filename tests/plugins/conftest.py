from __future__ import annotations

import inspect
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock, PropertyMock, create_autospec

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import UserProfile
from pyrsistencesniper.core.registry import RegistryHelper, RegistryNode

_USER_HIVE_ROOT = Path("/img/Users")

_PATH_BLIND_CALLERS = frozenset(
    {
        "test_active_setup.py",
        "test_app_paths.py",
        "test_appcert_dlls.py",
        "test_appdomain_manager.py",
        "test_assistive_technology.py",
        "test_boot_execute.py",
        "test_boot_verification.py",
        "test_cmd_autorun.py",
        "test_com_hijack.py",
        "test_debugger_hijacking.py",
        "test_dll_loading.py",
        "test_dotnet_profiler_registry.py",
        "test_explorer_clsid_hijack.py",
        "test_explorer_persistence.py",
        "test_file_association.py",
        "test_font_drivers.py",
        "test_ifeo.py",
        "test_known_dlls.py",
        "test_lsa_packages.py",
        "test_lsa_password_filter.py",
        "test_netsh_helper.py",
        "test_network_provider.py",
        "test_office_addins.py",
        "test_office_dll_override.py",
        "test_office_test_dll.py",
        "test_print_monitors.py",
        "test_profiler_env_vars.py",
        "test_protocol_handlers.py",
        "test_recycle_bin_com.py",
        "test_rid_hijacking.py",
        "test_run_keys.py",
        "test_run_services.py",
        "test_service_failure_actions.py",
        "test_shell_execute_hooks.py",
        "test_shell_folders.py",
        "test_shell_launcher.py",
        "test_snmp_extension.py",
        "test_terminal_services.py",
        "test_time_providers.py",
        "test_windows_services.py",
        "test_winlogon.py",
    }
)


def make_node(
    name: str = "test",
    values: dict[str, object] | None = None,
    children: dict[str, RegistryNode] | None = None,
) -> RegistryNode:
    """Build a RegistryNode stub with the given values and children."""
    value_map: dict[str, tuple[str, object]] = {}
    for value_name, value_data in (values or {}).items():
        key = value_name.lower()
        if key == "(default)":
            key = ""
        value_map[key] = (value_name, value_data)
    child_map = {
        child_name.lower(): child_node
        for child_name, child_node in (children or {}).items()
    }
    return RegistryNode(name, value_map, child_map)


def make_user_profiles(*usernames: str) -> list[UserProfile]:
    """Build profiles carrying both per-user hives, as discover_profiles sets them."""
    return [
        UserProfile(
            username=username,
            profile_path=_USER_HIVE_ROOT / username,
            ntuser_path=_USER_HIVE_ROOT / username / "NTUSER.DAT",
            usrclass_path=_USER_HIVE_ROOT / username / "UsrClass.dat",
        )
        for username in usernames or ("testuser",)
    ]


def make_deps(
    tmp_path: Path,
    user_profiles: list[UserProfile] | None = None,
) -> tuple[MagicMock, MagicMock, FilesystemHelper]:
    """Create a mock AnalysisContext and its dependencies for plugin testing."""
    registry = create_autospec(RegistryHelper, instance=True)
    filesystem = FilesystemHelper(image_root=tmp_path)

    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    type(context).active_controlset = PropertyMock(return_value="ControlSet001")
    type(context).user_profiles = PropertyMock(return_value=user_profiles or [])
    context.registry = registry
    context.filesystem = filesystem

    # Delegate the AnalysisContext hive-op methods to the mocked RegistryHelper
    # so tests can wire registry.open_hive / load_subtree and have plugin calls
    # to context.<method> follow the same path.
    def _open_hive_by_name(hive_name: str) -> object | None:
        """Resolve a hive name through the mocked hive_path, as the context does."""
        path = context.hive_path(hive_name)
        if path is None:
            return None
        return registry.open_hive(path)

    def _load_subtree(hive_name: str, key_path: str) -> object | None:
        """Read a key path from the named hive, or None when the hive is absent."""
        hive = _open_hive_by_name(hive_name)
        if hive is None:
            return None
        return registry.load_subtree(hive, key_path)

    def _iter_user_hives() -> object:
        """Yield each profile with an NTUSER hive, skipping profiles without one."""
        for user_profile in context.user_profiles:
            if user_profile.ntuser_path is None:
                continue
            hive = registry.open_hive(user_profile.ntuser_path)
            if hive is not None:
                yield user_profile, hive

    def _iter_usrclass_hives() -> object:
        """Yield each profile with a UsrClass hive, taken off the profile itself."""
        # Mirrors AnalysisContext._iter_profile_hives, which reads the path off
        # the profile rather than from hive_path.
        for user_profile in context.user_profiles:
            if user_profile.usrclass_path is None:
                continue
            hive = registry.open_hive(user_profile.usrclass_path)
            if hive is not None:
                yield user_profile, hive

    def _resolve_clsid_default(hive: object, subpath: str) -> str:
        """Return a CLSID key's default value, or empty when the key is unwired."""
        node = registry.load_subtree(hive, subpath)
        if node is None:
            return ""
        default_value = node.get("(Default)")
        return str(default_value) if default_value else ""

    def _resolve_clsid_inproc(hive: object, clsid: str) -> str:
        """Return the InprocServer32 path for a CLSID, ignoring non-CLSID strings."""
        if not clsid.startswith("{"):
            return ""
        return _resolve_clsid_default(hive, f"Classes\\CLSID\\{clsid}\\InprocServer32")

    context.open_hive_by_name.side_effect = _open_hive_by_name
    context.load_subtree.side_effect = _load_subtree
    context.iter_user_hives.side_effect = _iter_user_hives
    context.iter_usrclass_hives.side_effect = _iter_usrclass_hives
    context.resolve_clsid_default.side_effect = _resolve_clsid_default
    context.resolve_clsid_inproc.side_effect = _resolve_clsid_inproc

    # hive_path defaults to a fake path so tests that wire only
    # registry.open_hive still reach the delegation chain.
    context.hive_path.return_value = Path("/fake/hive")
    registry.open_hive.return_value = None
    registry.load_subtree.return_value = None

    return context, registry, filesystem


def make_plugin(
    cls: type,
    tmp_path: Path,
    *,
    user_profiles: list[UserProfile] | None = None,
) -> object:
    """Instantiate a plugin class with a mocked AnalysisContext."""
    context, registry, _filesystem = make_deps(tmp_path, user_profiles=user_profiles)
    context.registry = registry
    return cls(context=context)


def setup_hklm(
    plugin: object,
    tree_node: object,
    *,
    hive_path: str = "/fake/SOFTWARE",
    key_path: str | None = None,
) -> None:
    """Wire a mock HKLM hive; new callers must pass key_path, which binds the read."""
    plugin.context.hive_path.return_value = Path(hive_path)  # type: ignore[union-attr]
    if key_path is not None:
        setup_keys(plugin, {key_path: tree_node})
        return
    _refuse_new_path_blind_caller()
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = tree_node  # type: ignore[union-attr]


def _calling_module_name() -> str:
    """Return the file name of the nearest calling frame outside this conftest."""
    frame = inspect.currentframe()
    while frame is not None:
        module_name = Path(str(frame.f_globals.get("__file__", ""))).name
        if module_name and module_name != "conftest.py":
            return module_name
        frame = frame.f_back
    return ""


def _refuse_new_path_blind_caller() -> None:
    """Reject any module that was not already a path-blind caller when it was frozen."""
    module_name = _calling_module_name()
    if module_name in _PATH_BLIND_CALLERS:
        return
    raise AssertionError(
        f"setup_hklm without key_path answers every key path with the same node, so "
        f"{module_name} would not notice the plugin reading the wrong key. Pass "
        "key_path='<literal key path the plugin must read>', or use setup_keys to "
        "wire several paths. The path-blind form is frozen to the modules that "
        "already used it when test_declarative_targets.py took over location "
        "coverage, so those 41 files need no migration and no new test can be "
        "path-blind by accident."
    )


def setup_keys(plugin: object, keys: dict[str, object]) -> None:
    """Answer only these key paths, so a plugin reading the wrong one gets None."""
    lookup = {key.lower().strip("\\"): node for key, node in keys.items()}

    def _load_subtree(_hive: object, key_path: str) -> object | None:
        """Answer only the wired key paths, matched case- and slash-insensitively."""
        return lookup.get(key_path.lower().strip("\\"))

    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = _load_subtree  # type: ignore[union-attr]


def setup_usrclass_only(plugin: object, keys: dict[str, object]) -> None:
    """Answer these key paths out of UsrClass.dat, and nothing out of NTUSER.DAT."""
    lookup = {key.lower().strip("\\"): node for key, node in keys.items()}

    def _open_hive(hive_file: Path) -> str:
        """Name the hive file being opened, which the engine passes onward."""
        return Path(hive_file).name.lower()

    def _load_subtree(hive: str, key_path: str) -> object | None:
        """Answer wired key paths out of UsrClass.dat and nothing out of any other."""
        if hive != "usrclass.dat":
            return None
        return lookup.get(key_path.lower().strip("\\"))

    plugin.registry.open_hive.side_effect = _open_hive  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = _load_subtree  # type: ignore[union-attr]


def setup_usrclass(plugin: object, keys: dict[str, object]) -> None:
    """Wire a per-user classes hive; without a usrclass_path no hive is iterated."""
    setup_keys(plugin, keys)


def setup_filesystem(
    plugin: object,
    files: dict[str, bytes | str],
) -> None:
    """Create the given files, keyed by path relative to the plugin's image_root."""
    root = plugin.filesystem.image_root  # type: ignore[union-attr]
    for rel_path, content in files.items():
        target = root / PureWindowsPath(rel_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
