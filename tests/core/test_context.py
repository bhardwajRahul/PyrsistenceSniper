"""Tests for input classification, hive/profile discovery, and hive inventory."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from pyrsistencesniper.core.context import (
    AnalysisContext,
    ArtifactKind,
    UnsupportedArtifactError,
    build_context,
    build_hive_context,
    classify_input,
    discover_hives,
    discover_profiles,
)
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import HiveStatus, UserProfile
from pyrsistencesniper.core.registry import RegistryHelper


def _make_context(root: Path, *, hostname: str = "") -> AnalysisContext:
    """Build an image-root context, with no hostname override by default."""
    return build_context(root, hostname=hostname)


def test_hive_path_software(tmp_path: Path) -> None:
    """SOFTWARE is resolved from the System32 config path real images use."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"\x00" * 16)
    ctx = _make_context(tmp_path)
    path = ctx.hive_path("SOFTWARE")
    assert path is not None
    assert path.name == "SOFTWARE"
    assert path.is_file()


def test_hive_path_system(tmp_path: Path) -> None:
    """SYSTEM resolves too, since every service and boot check depends on it."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"\x00" * 16)
    ctx = _make_context(tmp_path)
    path = ctx.hive_path("SYSTEM")
    assert path is not None
    assert path.name == "SYSTEM"


def test_hive_path_ntuser_requires_username(tmp_path: Path) -> None:
    """With no username there is no profile to pick, so nothing is guessed."""
    ctx = _make_context(tmp_path)
    assert ctx.hive_path("NTUSER.DAT") is None


def test_hive_path_ntuser_with_username(tmp_path: Path) -> None:
    """A profile name containing a space still resolves, as most real ones do."""
    user_dir = tmp_path / "Users" / "John Doe"
    user_dir.mkdir(parents=True)
    (user_dir / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    ctx = _make_context(tmp_path)
    path = ctx.hive_path("NTUSER.DAT", "John Doe")
    assert path is not None
    assert path.is_file()


def test_hive_path_nonexistent(tmp_path: Path) -> None:
    """An unknown hive name is an absence, not an error."""
    ctx = _make_context(tmp_path)
    assert ctx.hive_path("BOGUS_HIVE") is None


def _setup_user_dirs(tmp_path: Path) -> AnalysisContext:
    """Create a typical Users/ layout and return the built context."""
    users = tmp_path / "Users"
    for name in ("John Doe", "Jane Doe", "Default", "Public"):
        user_dir = users / name
        user_dir.mkdir(parents=True)
        if name != "Public":
            (user_dir / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    return _make_context(tmp_path)


def test_user_profiles_discovers_users(tmp_path: Path) -> None:
    """Every directory under Users counts, including Default and Public."""
    ctx = _setup_user_dirs(tmp_path)
    usernames = [profile.username for profile in ctx.user_profiles]
    assert "John Doe" in usernames
    assert "Jane Doe" in usernames
    assert "Default" in usernames
    assert "Public" in usernames


def test_user_profiles_ntuser_presence(tmp_path: Path) -> None:
    """Public has no NTUSER.DAT, so per-user checks cannot assume one exists."""
    ctx = _setup_user_dirs(tmp_path)
    by_name = {profile.username: profile for profile in ctx.user_profiles}
    assert by_name["John Doe"].ntuser_path is not None
    assert by_name["Jane Doe"].ntuser_path is not None
    assert by_name["Default"].ntuser_path is not None
    assert by_name["Public"].ntuser_path is None


def test_hostname_missing_system_hive(tmp_path: Path) -> None:
    """Without a SYSTEM hive the hostname stays blank rather than invented."""
    ctx = _make_context(tmp_path)
    assert ctx.hostname == ""


def test_hostname_override(tmp_path: Path) -> None:
    """A caller-supplied hostname wins, naming images that cannot name themselves."""
    ctx = _make_context(tmp_path, hostname="MY-HOST")
    assert ctx.hostname == "MY-HOST"


def test_hive_path_usrclass_deep_path(tmp_path: Path) -> None:
    """On a live system UsrClass.dat sits deep under AppData, not beside NTUSER.DAT."""
    user_dir = (
        tmp_path / "Users" / "Alice" / "AppData" / "Local" / "Microsoft" / "Windows"
    )
    user_dir.mkdir(parents=True)
    hive = user_dir / "UsrClass.dat"
    hive.write_bytes(b"fake hive")

    ctx = _make_context(tmp_path)
    result = ctx.hive_path("UsrClass.dat", "Alice")
    assert result is not None
    assert result == hive


def test_hive_path_usrclass_shallow_fallback(tmp_path: Path) -> None:
    """Collectors that flatten a profile still leave UsrClass.dat findable."""
    user_dir = tmp_path / "Users" / "Bob"
    user_dir.mkdir(parents=True)
    hive = user_dir / "UsrClass.dat"
    hive.write_bytes(b"fake hive")

    ctx = _make_context(tmp_path)
    result = ctx.hive_path("UsrClass.dat", "Bob")
    assert result is not None
    assert result == hive


def test_hive_path_usrclass_requires_username(tmp_path: Path) -> None:
    """UsrClass.dat exists only per user, so an unnamed lookup has nothing to open."""
    ctx = _make_context(tmp_path)
    assert ctx.hive_path("UsrClass.dat") is None


def test_build_context_standalone_software(tmp_path: Path) -> None:
    """A single hive file is a valid target: root is its parent, with no users."""
    hive_file = tmp_path / "SOFTWARE"
    hive_file.write_bytes(b"\x00" * 16)
    ctx = build_context(hive_file)
    assert ctx.root == tmp_path
    assert ctx.hive_path("SOFTWARE") is not None
    assert ctx.user_profiles == []


def test_build_context_standalone_ntuser(tmp_path: Path) -> None:
    """A lone NTUSER.DAT gets a synthetic profile so per-user checks still run."""
    hive_file = tmp_path / "NTUSER.DAT"
    hive_file.write_bytes(b"\x00" * 16)
    ctx = build_context(hive_file)
    assert len(ctx.user_profiles) == 1
    assert ctx.user_profiles[0].username == "standalone_user"
    assert ctx.user_profiles[0].ntuser_path == hive_file


def test_build_context_rejects_unsupported_file(tmp_path: Path) -> None:
    """An unsupported artifact file is rejected instead of scanned as empty."""
    evtx_file = tmp_path / "Security.evtx"
    evtx_file.write_bytes(b"\x00" * 16)
    with pytest.raises(UnsupportedArtifactError):
        build_context(evtx_file)


def test_build_context_rejects_missing_path(tmp_path: Path) -> None:
    """A path that does not exist fails loudly rather than reporting no findings."""
    with pytest.raises(FileNotFoundError):
        build_context(tmp_path / "does-not-exist")


class TestClassifyInput:
    """Cases for deciding whether a target is an image root, a hive, or neither."""

    def test_classify_input_directory_returns_image_root(self, tmp_path: Path) -> None:
        """A directory path classifies as IMAGE_ROOT."""
        assert classify_input(tmp_path) == ArtifactKind.IMAGE_ROOT

    def test_classify_input_hive_file_returns_hive_file(self, tmp_path: Path) -> None:
        """Known hive names classify as HIVE_FILE."""
        for hive_name in ("SOFTWARE", "SYSTEM", "SAM", "NTUSER.DAT", "usrclass.dat"):
            hive_file = tmp_path / hive_name
            hive_file.write_bytes(b"regf")
            assert classify_input(hive_file) == ArtifactKind.HIVE_FILE, hive_name

    def test_classify_input_evtx_is_rejected(self, tmp_path: Path) -> None:
        """A .evtx file is rejected rather than scanned as an empty image."""
        evtx_file = tmp_path / "Security.evtx"
        evtx_file.write_bytes(b"ElfFile")
        with pytest.raises(UnsupportedArtifactError):
            classify_input(evtx_file)

    def test_classify_input_unknown_file_is_rejected(self, tmp_path: Path) -> None:
        """An unsupported file is rejected so it cannot look like a clean scan."""
        unknown = tmp_path / "readme.txt"
        unknown.write_text("just a text file")
        with pytest.raises(UnsupportedArtifactError):
            classify_input(unknown)

    def test_classify_input_rejection_names_the_file(self, tmp_path: Path) -> None:
        """The rejection message names the offending file so the fix is obvious."""
        unknown = tmp_path / "readme.txt"
        unknown.write_text("just a text file")
        with pytest.raises(UnsupportedArtifactError, match=r"readme\.txt"):
            classify_input(unknown)

    def test_classify_input_nonexistent_returns_image_root(
        self, tmp_path: Path
    ) -> None:
        """A path that does not exist yet is treated as an image root, not a file."""
        assert classify_input(tmp_path / "nonexistent") == ArtifactKind.IMAGE_ROOT


class TestBuildHiveContext:
    """Cases for a single hive file, where there is no image root to walk."""

    def test_build_hive_context_ntuser(self, tmp_path: Path) -> None:
        """NTUSER.DAT creates a UserProfile with ntuser_path set."""
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"regf")
        root, hives, profiles = build_hive_context(ntuser)
        assert root == tmp_path
        assert hives == {}
        assert len(profiles) == 1
        assert profiles[0].username == "standalone_user"
        assert profiles[0].ntuser_path == ntuser

    def test_build_hive_context_usrclass(self, tmp_path: Path) -> None:
        """usrclass.dat creates a UserProfile without ntuser_path."""
        usrclass = tmp_path / "usrclass.dat"
        usrclass.write_bytes(b"regf")
        root, hives, profiles = build_hive_context(usrclass)
        assert root == tmp_path
        assert hives == {}
        assert len(profiles) == 1
        assert profiles[0].ntuser_path is None

    def test_build_hive_context_system_hive(self, tmp_path: Path) -> None:
        """A machine hive is keyed by its lowered name and creates no profile."""
        software = tmp_path / "SOFTWARE"
        software.write_bytes(b"regf")
        root, hives, profiles = build_hive_context(software)
        assert root == tmp_path
        assert hives == {"software": software}
        assert profiles == []


class TestDiscoverHives:
    """Cases for finding hives in config/ or at the root, and which one wins."""

    def test_discover_hives_from_config_dir(self, tmp_path: Path) -> None:
        """Finds hives in Windows/System32/config/."""
        config_dir = tmp_path / "Windows" / "System32" / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "SOFTWARE").write_bytes(b"regf")
        (config_dir / "SYSTEM").write_bytes(b"regf")

        hives = discover_hives(tmp_path)
        assert hives["software"] == config_dir / "SOFTWARE"
        assert hives["system"] == config_dir / "SYSTEM"

    def test_discover_hives_root_fallback(self, tmp_path: Path) -> None:
        """Finds hives at root level when config/ is absent."""
        (tmp_path / "SAM").write_bytes(b"regf")
        hives = discover_hives(tmp_path)
        assert hives["sam"] == tmp_path / "SAM"

    def test_discover_hives_empty_when_no_matches(self, tmp_path: Path) -> None:
        """Returns empty dict when no known hive files exist."""
        (tmp_path / "readme.txt").write_text("not a hive")
        assert discover_hives(tmp_path) == {}

    def test_discover_hives_config_takes_precedence(self, tmp_path: Path) -> None:
        """Hive in config/ takes precedence over same-named hive at root."""
        config_dir = tmp_path / "Windows" / "System32" / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "SOFTWARE").write_bytes(b"config-version")
        (tmp_path / "SOFTWARE").write_bytes(b"root-version")

        hives = discover_hives(tmp_path)
        assert hives["software"] == config_dir / "SOFTWARE"


class TestDiscoverProfiles:
    """Cases for enumerating profiles under Users/ and their per-user hives."""

    def test_discover_profiles_enumerates_users(self, tmp_path: Path) -> None:
        """Finds user directories under Users/ with NTUSER.DAT."""
        users_dir = tmp_path / "Users"
        alice_dir = users_dir / "alice"
        alice_dir.mkdir(parents=True)
        (alice_dir / "NTUSER.DAT").write_bytes(b"regf")

        profiles = discover_profiles(tmp_path)
        assert len(profiles) == 1
        assert profiles[0].username == "alice"
        assert profiles[0].profile_path == alice_dir
        assert profiles[0].ntuser_path == alice_dir / "NTUSER.DAT"

    def test_discover_profiles_skips_files(self, tmp_path: Path) -> None:
        """Ignores non-directory entries in Users/."""
        users_dir = tmp_path / "Users"
        users_dir.mkdir()
        (users_dir / "desktop.ini").write_text("not a user")
        assert discover_profiles(tmp_path) == []

    def test_discover_profiles_empty_when_no_users_dir(self, tmp_path: Path) -> None:
        """An image with no Users directory yields no profiles rather than an error."""
        assert discover_profiles(tmp_path) == []

    def test_discover_profiles_handles_missing_ntuser(self, tmp_path: Path) -> None:
        """Profile created with ntuser_path=None when NTUSER.DAT absent."""
        users_dir = tmp_path / "Users"
        bob_dir = users_dir / "bob"
        bob_dir.mkdir(parents=True)

        profiles = discover_profiles(tmp_path)
        assert len(profiles) == 1
        assert profiles[0].username == "bob"
        assert profiles[0].ntuser_path is None

    def test_discover_profiles_multiple_users_sorted(self, tmp_path: Path) -> None:
        """Multiple user directories are discovered and sorted."""
        users_dir = tmp_path / "Users"
        for name in ("charlie", "alice", "bob"):
            user_dir = users_dir / name
            user_dir.mkdir(parents=True)
            (user_dir / "NTUSER.DAT").write_bytes(b"regf")

        profiles = discover_profiles(tmp_path)
        assert [profile.username for profile in profiles] == [
            "alice",
            "bob",
            "charlie",
        ]


def _make_context_with_mock_registry(
    tmp_path: Path,
    *,
    hives: dict[str, Path] | None = None,
    profiles: list[UserProfile] | None = None,
) -> tuple[AnalysisContext, MagicMock]:
    """Build a real AnalysisContext with a mocked RegistryHelper."""
    registry = create_autospec(RegistryHelper, instance=True)
    filesystem = FilesystemHelper(image_root=tmp_path)
    ctx = AnalysisContext(
        root=tmp_path,
        hives=hives or {},
        user_profiles=profiles or [],
        registry=registry,
        filesystem=filesystem,
    )
    return ctx, registry


def _mock_node(values: dict[str, object]) -> MagicMock:
    """Build a mock that supports .get(name) against a value dict."""
    node = MagicMock()
    node.get.side_effect = values.get
    return node


def test_open_hive_by_name_returns_hive(tmp_path: Path) -> None:
    """open_hive_by_name resolves the path and delegates to registry.open_hive."""
    software_path = tmp_path / "SOFTWARE"
    ctx, registry = _make_context_with_mock_registry(
        tmp_path, hives={"software": software_path}
    )
    sentinel = object()
    registry.open_hive.return_value = sentinel

    result = ctx.open_hive_by_name("SOFTWARE")

    assert result is sentinel
    registry.open_hive.assert_called_once_with(software_path)


def test_open_hive_by_name_returns_none_when_path_missing(tmp_path: Path) -> None:
    """open_hive_by_name returns None without calling registry when path is unknown."""
    ctx, registry = _make_context_with_mock_registry(tmp_path)

    result = ctx.open_hive_by_name("SOFTWARE")

    assert result is None
    registry.open_hive.assert_not_called()


def test_load_subtree_delegates_to_registry(tmp_path: Path) -> None:
    """load_subtree opens the hive then calls registry.load_subtree with it."""
    software_path = tmp_path / "SOFTWARE"
    ctx, registry = _make_context_with_mock_registry(
        tmp_path, hives={"software": software_path}
    )
    fake_hive = MagicMock(name="hive")
    fake_node = MagicMock(name="node")
    registry.open_hive.return_value = fake_hive
    registry.load_subtree.return_value = fake_node

    result = ctx.load_subtree("SOFTWARE", "Classes\\CLSID\\{abc}")

    assert result is fake_node
    registry.load_subtree.assert_called_once_with(fake_hive, "Classes\\CLSID\\{abc}")


def test_iter_user_hives_skips_missing_ntuser(tmp_path: Path) -> None:
    """iter_user_hives yields only profiles that have an NTUSER path."""
    user_with = UserProfile(
        username="alice",
        profile_path=tmp_path / "Users" / "alice",
        ntuser_path=tmp_path / "Users" / "alice" / "NTUSER.DAT",
    )
    user_without = UserProfile(
        username="public",
        profile_path=tmp_path / "Users" / "Public",
        ntuser_path=None,
    )
    ctx, registry = _make_context_with_mock_registry(
        tmp_path, profiles=[user_with, user_without]
    )
    fake_hive = MagicMock(name="hive")
    registry.open_hive.return_value = fake_hive

    yielded = list(ctx.iter_user_hives())

    assert yielded == [(user_with, fake_hive)]
    registry.open_hive.assert_called_once_with(user_with.ntuser_path)


def test_resolve_clsid_default_returns_value(tmp_path: Path) -> None:
    """A COM registration keeps its target in the unnamed default value."""
    ctx, registry = _make_context_with_mock_registry(tmp_path)
    fake_hive = MagicMock(name="hive")
    registry.load_subtree.return_value = _mock_node(
        {"(Default)": "C:\\Windows\\evil.dll", "ThreadingModel": "Both"}
    )

    result = ctx.resolve_clsid_default(
        fake_hive, "Classes\\CLSID\\{abc}\\InprocServer32"
    )

    assert result == "C:\\Windows\\evil.dll"
    registry.load_subtree.assert_called_once_with(
        fake_hive, "Classes\\CLSID\\{abc}\\InprocServer32"
    )


def test_resolve_clsid_inproc_rejects_non_brace_clsid(tmp_path: Path) -> None:
    """resolve_clsid_inproc short-circuits on CLSIDs that are not brace-wrapped."""
    ctx, registry = _make_context_with_mock_registry(tmp_path)
    fake_hive = MagicMock(name="hive")

    result = ctx.resolve_clsid_inproc(fake_hive, "not-a-clsid")

    assert result == ""
    registry.load_subtree.assert_not_called()


def test_resolve_clsid_inproc_falls_back_to_the_wow6432node_view(
    tmp_path: Path,
) -> None:
    """A COM server registered only in the 32-bit view still yields its DLL."""
    ctx, registry = _make_context_with_mock_registry(tmp_path)
    fake_hive = MagicMock(name="hive")
    registry.load_subtree.side_effect = lambda hive, key_path: (
        _mock_node({"(Default)": "C:\\Users\\Public\\evil.dll"})
        if key_path == "Classes\\Wow6432Node\\CLSID\\{abc}\\InprocServer32"
        else None
    )

    result = ctx.resolve_clsid_inproc(fake_hive, "{abc}")

    assert result == "C:\\Users\\Public\\evil.dll"


def test_resolve_clsid_inproc_prefers_the_native_view(tmp_path: Path) -> None:
    """A CLSID registered in both views resolves to its 64-bit COM server."""
    ctx, registry = _make_context_with_mock_registry(tmp_path)
    fake_hive = MagicMock(name="hive")

    def server_for(hive: object, key_path: str) -> object:
        """Register the CLSID in both machine views with a different DLL each."""
        if key_path == "Classes\\CLSID\\{abc}\\InprocServer32":
            return _mock_node({"(Default)": "C:\\Windows\\System32\\good.dll"})
        if key_path == "Classes\\Wow6432Node\\CLSID\\{abc}\\InprocServer32":
            return _mock_node({"(Default)": "C:\\Windows\\SysWOW64\\good.dll"})
        return None

    registry.load_subtree.side_effect = server_for

    result = ctx.resolve_clsid_inproc(fake_hive, "{abc}")

    assert result == "C:\\Windows\\System32\\good.dll"
    registry.load_subtree.assert_called_once_with(
        fake_hive, "Classes\\CLSID\\{abc}\\InprocServer32"
    )


def test_resolve_clsid_inproc_returns_empty_when_neither_view_registers_it(
    tmp_path: Path,
) -> None:
    """A CLSID with no COM server anywhere leaves callers nothing to report."""
    ctx, registry = _make_context_with_mock_registry(tmp_path)
    fake_hive = MagicMock(name="hive")
    registry.load_subtree.return_value = None

    result = ctx.resolve_clsid_inproc(fake_hive, "{abc}")

    assert result == ""
    consulted = [call.args[1] for call in registry.load_subtree.call_args_list]
    assert consulted == [
        "Classes\\CLSID\\{abc}\\InprocServer32",
        "Classes\\Wow6432Node\\CLSID\\{abc}\\InprocServer32",
    ]


def test_hive_inventory_reports_a_hive_that_was_read(tmp_path: Path) -> None:
    """A hive a check opened is recorded as read."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"regf")

    context = build_context(tmp_path)
    with patch("pyrsistencesniper.core.registry.pyregf") as mock_pyregf:
        mock_pyregf.file.return_value = MagicMock()
        context.open_hive_by_name("SOFTWARE")

    software = next(
        record for record in context.hive_inventory() if record.name == "SOFTWARE"
    )
    assert software.status is HiveStatus.OPENED


def test_hive_inventory_reports_a_hive_that_would_not_open(tmp_path: Path) -> None:
    """A hive that refused to open is recorded with the reason."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"regf")

    context = build_context(tmp_path)
    with patch("pyrsistencesniper.core.registry.pyregf") as mock_pyregf:
        mock_pyregf.file.return_value.open.side_effect = OSError("bad hive")
        context.open_hive_by_name("SYSTEM")

    system = next(
        record for record in context.hive_inventory() if record.name == "SYSTEM"
    )
    assert system.status is HiveStatus.OPEN_FAILED
    assert "bad hive" in system.error


def test_hive_inventory_reports_hives_the_image_never_had(tmp_path: Path) -> None:
    """Machine hives absent from the image are named rather than passed over."""
    context = build_context(tmp_path)
    statuses = {record.name: record.status for record in context.hive_inventory()}

    assert statuses["SOFTWARE"] is HiveStatus.NOT_COLLECTED
    assert statuses["SYSTEM"] is HiveStatus.NOT_COLLECTED


def test_hive_inventory_separates_collected_from_read(tmp_path: Path) -> None:
    """A hive present but never opened is not reported as missing."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SAM").write_bytes(b"regf")

    context = build_context(tmp_path)
    sam = next(record for record in context.hive_inventory() if record.name == "SAM")

    assert sam.status is HiveStatus.NOT_READ


def test_hive_inventory_names_per_user_hives(tmp_path: Path) -> None:
    """Each profile's hives are attributed to their owner."""
    profile = tmp_path / "Users" / "victim"
    profile.mkdir(parents=True)
    (profile / "NTUSER.DAT").write_bytes(b"regf")

    context = build_context(tmp_path)
    owned = [record for record in context.hive_inventory() if record.owner == "victim"]

    assert [record.name for record in owned] == ["NTUSER.DAT"]


def test_hive_inventory_omits_machine_hives_for_a_standalone_target(
    tmp_path: Path,
) -> None:
    """Scanning one hive file does not report every machine hive as missing."""
    hive_path = tmp_path / "NTUSER.DAT"
    hive_path.write_bytes(b"regf")

    context = build_context(hive_path)

    assert all(
        record.status is not HiveStatus.NOT_COLLECTED
        for record in context.hive_inventory()
    )


def _profile_list_node(entries: dict[str, object]) -> MagicMock:
    """Build a ProfileList node whose children are SIDs holding ProfileImagePath."""
    children = []
    for sid, image_path in entries.items():
        child = MagicMock(name=sid)
        child.get.side_effect = lambda name, value=image_path: (
            value if name == "ProfileImagePath" else None
        )
        children.append((sid, child))
    node = MagicMock(name="ProfileList")
    node.children.return_value = children
    return node


def test_profile_sids_maps_directory_name_to_sid(tmp_path: Path) -> None:
    """ProfileImagePath is the only link between a Users\\<name> dir and a SID."""
    software = tmp_path / "SOFTWARE"
    software.write_bytes(b"x")
    ctx, registry = _make_context_with_mock_registry(
        tmp_path, hives={"software": software}
    )
    registry.open_hive.return_value = MagicMock(name="hive")
    registry.load_subtree.return_value = _profile_list_node(
        {
            "S-1-5-21-7-8-9-1001": "C:\\Users\\jdoe",
            "S-1-5-18": "C:\\Windows\\system32\\config\\systemprofile",
        }
    )

    assert ctx.profile_sids == {
        "jdoe": "S-1-5-21-7-8-9-1001",
        "systemprofile": "S-1-5-18",
    }


def test_profile_sids_ignores_entries_without_an_image_path(tmp_path: Path) -> None:
    """An empty ProfileImagePath names no directory, so the SID cannot be keyed."""
    software = tmp_path / "SOFTWARE"
    software.write_bytes(b"x")
    ctx, registry = _make_context_with_mock_registry(
        tmp_path, hives={"software": software}
    )
    registry.open_hive.return_value = MagicMock(name="hive")
    registry.load_subtree.return_value = _profile_list_node(
        {"S-1-5-21-1": "", "S-1-5-21-2": "C:\\Users\\real"}
    )

    assert ctx.profile_sids == {"real": "S-1-5-21-2"}


def test_profile_sids_is_empty_without_a_software_hive(tmp_path: Path) -> None:
    """No SOFTWARE hive means no ProfileList, and an empty map rather than a raise."""
    ctx, _registry = _make_context_with_mock_registry(tmp_path)
    assert ctx.profile_sids == {}


def test_profile_sids_is_empty_when_profile_list_is_missing(tmp_path: Path) -> None:
    """A SOFTWARE hive without ProfileList yields no mapping, not an exception."""
    software = tmp_path / "SOFTWARE"
    software.write_bytes(b"x")
    ctx, registry = _make_context_with_mock_registry(
        tmp_path, hives={"software": software}
    )
    registry.open_hive.return_value = MagicMock(name="hive")
    registry.load_subtree.return_value = None
    assert ctx.profile_sids == {}
