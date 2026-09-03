"""Minimal $MFT parser: FILE records, $SI and $FN timestamps, full paths."""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import IO

from pyrsistencesniper.timeline.base import from_filetime

logger = logging.getLogger(__name__)

_RECORD_SIZE = 1024
_SECTOR_SIZE = 512
_ROOT_RECORD = 5
_ATTR_END = 0xFFFFFFFF
_ATTR_STANDARD_INFORMATION = 0x10
_ATTR_FILE_NAME = 0x30
_NAMESPACE_DOS = 2
_MAX_PATH_DEPTH = 255
_MIN_ATTR_LENGTH = 24
_MIN_SI_LENGTH = 32
_MIN_FN_LENGTH = 0x42
_MIN_USA_ENTRIES = 2


@dataclass(frozen=True, slots=True)
class MftEntry:
    """Timestamps and full path recovered from one $MFT FILE record."""

    record_number: int
    path: str
    si_created: datetime | None
    si_modified: datetime | None
    fn_created: datetime | None
    fn_modified: datetime | None


@dataclass(frozen=True, slots=True)
class _RawRecord:
    """Per-record fields collected before paths can be resolved."""

    record_number: int
    parent: int
    name: str
    is_directory: bool
    si_created: datetime | None
    si_modified: datetime | None
    fn_created: datetime | None
    fn_modified: datetime | None


def parse_mft(handle: IO[bytes]) -> Iterator[MftEntry]:
    """Yield an MftEntry per resolvable FILE record in the stream."""
    # Corrupt records are skipped one by one; extension records (non-zero base
    # reference) are dropped because they never carry their own identity.
    raw: dict[int, _RawRecord] = {}
    for number, record in _iter_records(handle):
        parsed = _safe_parse_record(number, record)
        if parsed is not None:
            raw[number] = parsed

    paths: dict[int, str | None] = {_ROOT_RECORD: ""}
    for number, entry in raw.items():
        path = _resolve_path(number, raw, paths)
        if path is None:
            continue
        yield MftEntry(
            record_number=number,
            path=path,
            si_created=entry.si_created,
            si_modified=entry.si_modified,
            fn_created=entry.fn_created,
            fn_modified=entry.fn_modified,
        )


def _safe_parse_record(number: int, record: bytes) -> _RawRecord | None:
    """Parse one record, returning None instead of raising on corruption."""
    try:
        return _parse_record(number, record)
    except (struct.error, ValueError, UnicodeDecodeError, OverflowError):
        logger.debug("Skipping unparsable MFT record %d", number, exc_info=True)
        return None


def _iter_records(handle: IO[bytes]) -> Iterator[tuple[int, bytes]]:
    """Yield each fixed-size FILE record in the stream with its number."""
    number = 0
    while True:
        record = handle.read(_RECORD_SIZE)
        if len(record) < _RECORD_SIZE:
            return
        if record[:4] == b"FILE":
            yield number, record
        number += 1


def _apply_fixups(record: bytes) -> bytes:
    """Restore the per-sector bytes NTFS replaced with the update sequence."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < _MIN_USA_ENTRIES or usa_offset + usa_count * 2 > len(record):
        raise ValueError("invalid update sequence array")
    fixed = bytearray(record)
    usn = record[usa_offset : usa_offset + 2]
    for index in range(1, usa_count):
        sector_end = index * _SECTOR_SIZE
        if fixed[sector_end - 2 : sector_end] != usn:
            raise ValueError("update sequence mismatch")
        saved = usa_offset + index * 2
        fixed[sector_end - 2 : sector_end] = record[saved : saved + 2]
    return bytes(fixed)


def _parse_record(number: int, record: bytes) -> _RawRecord | None:
    """Read one base FILE record into its name, parent and timestamps."""
    fixed = _apply_fixups(record)
    base_reference = struct.unpack_from("<Q", fixed, 0x20)[0]
    if base_reference != 0:
        return None
    flags = struct.unpack_from("<H", fixed, 0x16)[0]
    attrs_offset = struct.unpack_from("<H", fixed, 0x14)[0]

    si_created = si_modified = None
    fn_created = fn_modified = None
    parent = -1
    name = ""
    name_namespace = -1

    offset = attrs_offset
    while offset + 8 <= len(fixed):
        attr_type, attr_length = struct.unpack_from("<II", fixed, offset)
        if (
            attr_type == _ATTR_END
            or attr_length < _MIN_ATTR_LENGTH
            or offset + attr_length > len(fixed)
        ):
            break
        non_resident = fixed[offset + 8]
        if non_resident == 0:
            value_length = struct.unpack_from("<I", fixed, offset + 0x10)[0]
            value_offset = struct.unpack_from("<H", fixed, offset + 0x14)[0]
            value_start = offset + value_offset
            if value_start + value_length <= offset + attr_length:
                value = fixed[value_start : value_start + value_length]
                if (
                    attr_type == _ATTR_STANDARD_INFORMATION
                    and value_length >= _MIN_SI_LENGTH
                ):
                    si_created = from_filetime(struct.unpack_from("<Q", value, 0)[0])
                    si_modified = from_filetime(struct.unpack_from("<Q", value, 8)[0])
                elif attr_type == _ATTR_FILE_NAME and value_length >= _MIN_FN_LENGTH:
                    candidate = _parse_file_name(value)
                    # First $FN wins; upgrade only an 8.3 DOS short name
                    replace = candidate is not None and (
                        name_namespace == -1
                        or (
                            name_namespace == _NAMESPACE_DOS
                            and candidate[3] != _NAMESPACE_DOS
                        )
                    )
                    if replace and candidate is not None:
                        parent, fn_created, fn_modified, name_namespace, name = (
                            candidate
                        )
        offset += attr_length

    if not name:
        return None
    return _RawRecord(
        record_number=number,
        parent=parent,
        name=name,
        is_directory=bool(flags & 0x02),
        si_created=si_created,
        si_modified=si_modified,
        fn_created=fn_created,
        fn_modified=fn_modified,
    )


def _parse_file_name(
    value: bytes,
) -> tuple[int, datetime, datetime, int, str] | None:
    """Unpack a $FN attribute into parent, timestamps, namespace and name."""
    parent = struct.unpack_from("<Q", value, 0)[0] & 0x0000FFFFFFFFFFFF
    created = from_filetime(struct.unpack_from("<Q", value, 0x08)[0])
    modified = from_filetime(struct.unpack_from("<Q", value, 0x10)[0])
    name_length = value[0x40]
    namespace = value[0x41]
    name_end = 0x42 + name_length * 2
    if name_end > len(value):
        return None
    name = value[0x42:name_end].decode("utf-16-le")
    return parent, created, modified, namespace, name


def _resolve_path(
    number: int,
    raw: dict[int, _RawRecord],
    paths: dict[int, str | None],
) -> str | None:
    """Walk parent references to a full path, memoizing every record on the way."""
    chain: list[int] = []
    current = number
    while current not in paths:
        entry = raw.get(current)
        if entry is None or len(chain) > _MAX_PATH_DEPTH or current in chain:
            for orphan in chain:
                paths[orphan] = None
            paths[current] = None
            return None
        chain.append(current)
        current = entry.parent

    for record in reversed(chain):
        parent_path = paths[current]
        if parent_path is None:
            paths[record] = None
        else:
            entry = raw[record]
            paths[record] = (
                f"{parent_path}\\{entry.name}" if parent_path else entry.name
            )
        current = record
    return paths[number]
