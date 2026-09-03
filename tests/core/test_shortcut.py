"""Tests for the MS-SHLLINK parser that names what a shortcut actually launches."""

from __future__ import annotations

import struct
from pathlib import Path, PureWindowsPath

import pytest
from pyrsistencesniper.core.shortcut import (
    ShellLink,
    describe_shortcut_entry,
    parse_shell_link,
    read_shell_link,
    resolve_shortcut_target,
)

_HEADER_SIZE = 0x4C
_LINK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

_HAS_LINK_TARGET_ID_LIST = 0x0001
_HAS_LINK_INFO = 0x0002
_HAS_RELATIVE_PATH = 0x0008
_HAS_ARGUMENTS = 0x0020
_IS_UNICODE = 0x0080
_FORCE_NO_LINK_INFO = 0x0100

_ENVIRONMENT_BLOCK_SIGNATURE = 0xA0000001
_ENVIRONMENT_BLOCK_SIZE = 0x0314


def _link_info(local_base_path: str) -> bytes:
    """Build an ANSI LinkInfo structure carrying one local base path."""
    header_size = 0x1C
    encoded = local_base_path.encode("cp1252") + b"\x00"
    suffix_offset = header_size + len(encoded)
    total_size = suffix_offset + 1
    return (
        struct.pack(
            "<IIIIIII",
            total_size,
            header_size,
            0x0001,
            0,
            header_size,
            0,
            suffix_offset,
        )
        + encoded
        + b"\x00"
    )


def _environment_block(target: str) -> bytes:
    """Build the ExtraData environment block that carries an unexpanded target."""
    ansi = target.encode("cp1252").ljust(260, b"\x00")
    unicode_target = target.encode("utf-16-le").ljust(520, b"\x00")
    return (
        struct.pack("<II", _ENVIRONMENT_BLOCK_SIZE, _ENVIRONMENT_BLOCK_SIGNATURE)
        + ansi
        + unicode_target
    )


def build_shell_link(
    *,
    local_base_path: str = "",
    relative_path: str = "",
    arguments: str = "",
    environment_target: str = "",
    id_list: bytes = b"",
    force_no_link_info: bool = False,
) -> bytes:
    """Assemble a shell link from only the sections the caller asked for."""
    flags = _IS_UNICODE
    if id_list:
        flags |= _HAS_LINK_TARGET_ID_LIST
    if local_base_path:
        flags |= _HAS_LINK_INFO
    if relative_path:
        flags |= _HAS_RELATIVE_PATH
    if arguments:
        flags |= _HAS_ARGUMENTS
    if force_no_link_info:
        flags |= _FORCE_NO_LINK_INFO

    link = struct.pack("<I", _HEADER_SIZE) + _LINK_CLSID + struct.pack("<I", flags)
    link += b"\x00" * (_HEADER_SIZE - len(link))
    if id_list:
        link += struct.pack("<H", len(id_list)) + id_list
    if local_base_path:
        link += _link_info(local_base_path)
    for text in (relative_path, arguments):
        if text:
            link += struct.pack("<H", len(text)) + text.encode("utf-16-le")
    if environment_target:
        link += _environment_block(environment_target)
    return link + b"\x00\x00\x00\x00"


def test_link_info_base_path_is_the_target() -> None:
    """The LinkInfo local base path names the executable the shortcut launches."""
    payload = r"C:\Users\bob\AppData\Local\Temp\svchost.exe"
    link = parse_shell_link(build_shell_link(local_base_path=payload))
    assert link.local_base_path == payload
    assert link.target_path(PureWindowsPath("Startup")) == payload


def test_relative_path_resolves_against_the_shortcut_folder() -> None:
    """A link carrying only RELATIVE_PATH is meaningless until joined to its folder."""
    link = parse_shell_link(
        build_shell_link(
            relative_path=r"..\..\Windows\System32\WindowsPowerShell"
            r"\v1.0\powershell.exe",
            arguments="-ExecutionPolicy Bypass -File C:\\evil.ps1",
        )
    )
    folder = PureWindowsPath(r"ProgramData\Startup")
    assert link.target_path(folder) == (
        r"Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    assert link.arguments == "-ExecutionPolicy Bypass -File C:\\evil.ps1"


def test_relative_path_that_escapes_the_image_root_is_refused() -> None:
    """A target climbing above the image root is not a path this scan can resolve."""
    link = parse_shell_link(build_shell_link(relative_path=r"..\..\..\..\evil.exe"))
    assert link.target_path(PureWindowsPath("Startup")) == ""


def test_environment_block_target_is_used_when_link_info_is_absent() -> None:
    """A shortcut whose target hides behind %windir% still names its binary."""
    link = parse_shell_link(
        build_shell_link(environment_target=r"%windir%\system32\mstsc.exe")
    )
    assert link.target_path(PureWindowsPath("Startup")) == (
        r"%windir%\system32\mstsc.exe"
    )


def test_link_info_wins_over_the_environment_block() -> None:
    """The concrete path the link recorded outranks the unexpanded one."""
    link = parse_shell_link(
        build_shell_link(
            local_base_path=r"C:\Windows\System32\mstsc.exe",
            environment_target=r"%windir%\system32\mstsc.exe",
        )
    )
    assert link.target_path(PureWindowsPath("Startup")) == (
        r"C:\Windows\System32\mstsc.exe"
    )


def test_shortcut_to_a_virtual_folder_names_no_file() -> None:
    """Control Panel style links carry an id list only and target no file at all."""
    link = parse_shell_link(build_shell_link(id_list=b"\x04\x00\x00\x00\x00\x00"))
    assert link == ShellLink()
    assert link.target_path(PureWindowsPath("Startup")) == ""


def test_id_list_is_skipped_before_link_info_is_read() -> None:
    """A link that carries both sections must not read the id list as LinkInfo."""
    link = parse_shell_link(
        build_shell_link(
            id_list=b"\x20\x00" + b"\xab" * 30,
            local_base_path=r"C:\Program Files\Vendor\agent.exe",
        )
    )
    assert link.local_base_path == r"C:\Program Files\Vendor\agent.exe"


def test_non_shell_link_bytes_are_refused() -> None:
    """A file that only claims the .lnk name never passes for a shell link."""
    with pytest.raises(ValueError, match="header and class id"):
        parse_shell_link(b"\x00" * 128)


def test_truncated_shell_link_is_refused() -> None:
    """A link shorter than its own header cannot be read as one."""
    with pytest.raises(ValueError, match="header needs"):
        parse_shell_link(b"\x4c\x00\x00\x00")


def test_string_data_running_past_the_end_is_refused() -> None:
    """A character count larger than the file is malformed, not a silent empty read."""
    truncated = build_shell_link(relative_path="a" * 40)[:-60]
    with pytest.raises(ValueError, match="runs past end of link"):
        parse_shell_link(truncated)


def test_force_no_link_info_still_reads_past_the_link_info_structure() -> None:
    """The flag bars using LinkInfo as the target; it does not remove its bytes."""
    link = parse_shell_link(
        build_shell_link(
            local_base_path=r"C:\Windows\System32\cmd.exe",
            relative_path=r"..\..\System32\cmd.exe",
            arguments="/c calc.exe",
            force_no_link_info=True,
        )
    )
    assert link.local_base_path == ""
    assert link.relative_path == r"..\..\System32\cmd.exe"
    assert link.arguments == "/c calc.exe"
    assert link.target_path(PureWindowsPath(r"Windows\Temp\Startup")) == (
        r"Windows\System32\cmd.exe"
    )


def test_flipping_force_no_link_info_on_a_real_link_still_names_the_payload() -> None:
    """Setting one flag bit must not turn a Startup shortcut into a garbage target."""
    honest = build_shell_link(
        local_base_path=r"C:\Windows\System32\cmd.exe",
        relative_path=r"..\..\System32\cmd.exe",
        arguments="/c calc.exe",
        id_list=b"\x20\x00" + b"\xab" * 30,
    )
    flags = struct.unpack_from("<I", honest, 20)[0] | _FORCE_NO_LINK_INFO
    evasive = honest[:20] + struct.pack("<I", flags) + honest[24:]

    link = parse_shell_link(evasive)
    assert link.arguments == "/c calc.exe"
    assert link.target_path(PureWindowsPath(r"Windows\Temp\Startup")) == (
        r"Windows\System32\cmd.exe"
    )


def test_force_no_link_info_falls_back_to_the_environment_block() -> None:
    """With the concrete base path barred, the unexpanded target still names it."""
    link = parse_shell_link(
        build_shell_link(
            local_base_path=r"C:\Windows\System32\mstsc.exe",
            environment_target=r"%windir%\system32\mstsc.exe",
            force_no_link_info=True,
        )
    )
    assert link.local_base_path == ""
    assert link.target_path(PureWindowsPath("Startup")) == (
        r"%windir%\system32\mstsc.exe"
    )


def test_force_no_link_info_without_link_info_skips_nothing() -> None:
    """A link that never carried LinkInfo keeps its StringData where it is."""
    link = parse_shell_link(
        build_shell_link(
            relative_path=r"..\payload.exe",
            arguments="-NoProfile",
            force_no_link_info=True,
        )
    )
    assert link.relative_path == r"..\payload.exe"
    assert link.arguments == "-NoProfile"


def test_an_ordinary_link_info_shortcut_keeps_its_string_data() -> None:
    """The benign case is unchanged: LinkInfo is used and StringData follows it."""
    link = parse_shell_link(
        build_shell_link(
            local_base_path=r"C:\Program Files\Vendor\agent.exe",
            relative_path=r"..\..\Vendor\agent.exe",
            arguments="--service",
        )
    )
    assert link.local_base_path == r"C:\Program Files\Vendor\agent.exe"
    assert link.relative_path == r"..\..\Vendor\agent.exe"
    assert link.arguments == "--service"


def test_unreadable_link_info_under_force_no_link_info_is_refused() -> None:
    """A LinkInfo too small for its own header is an error, not a shifted read."""
    link = bytearray(
        build_shell_link(
            local_base_path=r"C:\Windows\System32\cmd.exe",
            arguments="/c calc.exe",
            force_no_link_info=True,
        )
    )
    struct.pack_into("<I", link, _HEADER_SIZE, 0)
    with pytest.raises(ValueError, match="cannot hold its own header"):
        parse_shell_link(bytes(link))


def _corrupt_link() -> bytes:
    """Build a link carrying every optional section, to corrupt one field at a time."""
    return build_shell_link(
        local_base_path=r"C:\Windows\System32\cmd.exe",
        relative_path=r"..\..\System32\cmd.exe",
        arguments="/c calc.exe",
        environment_target=r"%windir%\system32\cmd.exe",
        id_list=b"\x20\x00" + b"\xab" * 30,
    )


def _parse_allowing_only_refusal(data: bytes) -> None:
    """Parse a damaged link, letting anything but the documented ValueError escape."""
    try:
        parse_shell_link(data).target_path(PureWindowsPath("Startup"))
    except ValueError:
        return


def test_every_truncation_of_a_link_is_refused_rather_than_crashing() -> None:
    """A parser that raises anything but ValueError takes its whole check down."""
    link = _corrupt_link()
    for length in range(len(link) + 1):
        _parse_allowing_only_refusal(link[:length])


def test_single_byte_corruption_anywhere_is_refused_rather_than_crashing() -> None:
    """Damage to any offset, length or string byte must not escape as a crash."""
    link = _corrupt_link()
    for position in range(len(link)):
        for replacement_byte in (0x00, 0x01, 0x7F, 0xFF):
            corrupted = bytearray(link)
            corrupted[position] = replacement_byte
            _parse_allowing_only_refusal(bytes(corrupted))


def test_every_link_flag_combination_is_refused_rather_than_crashing() -> None:
    """No LinkFlags bit pattern, ForceNoLinkInfo included, reaches a crash path."""
    link = _corrupt_link()
    for flags in range(1 << 12):
        candidate = bytearray(link)
        struct.pack_into("<I", candidate, 20, flags)
        _parse_allowing_only_refusal(bytes(candidate))


def test_read_shell_link_refuses_an_oversized_file(tmp_path: Path) -> None:
    """A multi-megabyte file is not a shortcut and is never read whole."""
    oversized = tmp_path / "huge.lnk"
    oversized.write_bytes(build_shell_link(local_base_path="C:\\a.exe").ljust(1 << 21))
    with pytest.raises(ValueError, match="exceeds"):
        read_shell_link(oversized)


def test_read_shell_link_reads_a_file_from_disk(tmp_path: Path) -> None:
    """The file-reading entry point returns the same fields as the byte parser."""
    shortcut = tmp_path / "agent.lnk"
    shortcut.write_bytes(build_shell_link(local_base_path=r"C:\Vendor\agent.exe"))
    assert read_shell_link(shortcut).local_base_path == r"C:\Vendor\agent.exe"


def test_resolve_shortcut_target_names_the_payload_and_its_arguments(
    tmp_path: Path,
) -> None:
    """A dropped shortcut resolves to the binary it launches, not to the link file."""
    shortcut = tmp_path / "updater.lnk"
    shortcut.write_bytes(
        build_shell_link(local_base_path=r"C:\Vendor\agent.exe", arguments="-silent")
    )

    target, arguments = resolve_shortcut_target(
        "startup_folder", shortcut, r"ProgramData\Startup\updater.lnk", ""
    )

    assert target == r"Vendor\agent.exe"
    assert arguments == "-silent"


def test_resolve_shortcut_target_leaves_a_plain_file_alone(tmp_path: Path) -> None:
    """A dropped executable is its own payload, so it is never parsed as a link."""
    dropped = tmp_path / "payload.exe"
    dropped.write_bytes(b"MZ")

    assert resolve_shortcut_target(
        "startup_folder", dropped, r"ProgramData\Startup\payload.exe", ""
    ) == ("", "")


def test_describe_shortcut_entry_falls_back_to_the_file_name(tmp_path: Path) -> None:
    """An entry naming no target is still reported, under the name it carries."""
    entry = tmp_path / "updater.lnk"

    assert (
        describe_shortcut_entry(entry, r"Vendor\agent.exe", "-silent")
        == r"Vendor\agent.exe -silent"
    )
    assert describe_shortcut_entry(entry, "", "") == "updater.lnk"
