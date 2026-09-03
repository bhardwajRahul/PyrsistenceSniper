"""Tests for the BITS job notification-command check (T1197)."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.core.resolver import ResolutionPipeline
from pyrsistencesniper.plugins.T1197.bits_jobs import (
    _WINDOW_BYTES,
    BitsNotifyCommand,
)

from .conftest import make_plugin, setup_filesystem

if TYPE_CHECKING:
    from pathlib import Path

_QMGR_FILE = r"ProgramData\Microsoft\Network\Downloader\qmgr.db"
_LEGACY_FILE = r"ProgramData\Microsoft\Network\Downloader\qmgr0.dat"
_JOB_ID = "{8EC53D81-27B3-4AD2-98C2-842F0026396E}"
_USER_SID = "S-1-5-21-3576990506-1140035765-2682855383-1001"
_FILLER = b"\xab" * 64


def _job_id_bytes() -> bytes:
    """Build the 16 raw bytes the queue manager writes ahead of a job record."""
    return struct.pack("<IHH", 0x8EC53D81, 0x27B3, 0x4AD2) + bytes.fromhex(
        "98C2842F0026396E"
    )


def _counted(text: str) -> bytes:
    """Encode one counted, NUL-terminated UTF-16 string as the queue stores it."""
    return struct.pack("<I", len(text) + 1) + (text + "\x00").encode("utf-16-le")


def _job_record(
    *,
    display_name: str = "updater",
    description: str = "",
    program: str = "",
    parameters: str = "",
    owner: str = _USER_SID,
) -> bytes:
    """Build one serialised BITS job record."""
    return (
        _job_id_bytes()
        + _counted(display_name)
        + _counted(description)
        + _counted(program)
        + _counted(parameters)
        + _counted(owner)
    )


def _queue(*records: bytes) -> bytes:
    """Embed job records in filler, as they sit inside a real state file."""
    return _FILLER + _FILLER.join(records) + _FILLER


def test_job_with_notification_command_is_reported(tmp_path: Path) -> None:
    """A job carrying a notification command line is persistence and is reported."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin,
        {
            _QMGR_FILE: _queue(
                _job_record(
                    display_name="pssniper_notify_test",
                    program=r"C:\Temp\payload.exe",
                    parameters=r"C:\Temp\payload.exe -stage2",
                )
            )
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == rf"{_QMGR_FILE}\{_JOB_ID}"
    assert findings[0].value == r"C:\Temp\payload.exe -stage2"
    assert findings[0].access_gained is AccessLevel.USER


def test_ordinary_transfer_job_stays_quiet(tmp_path: Path) -> None:
    """A job with no notification command is a plain download, not persistence."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin,
        {_QMGR_FILE: _queue(_job_record(display_name="Edge Component Updater"))},
    )

    assert plugin.run() == []


def test_program_without_parameters_is_reported_alone(tmp_path: Path) -> None:
    """A notification program set with no parameters is still the command it runs."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin, {_QMGR_FILE: _queue(_job_record(program=r"C:\Temp\payload.exe"))}
    )

    assert plugin.run()[0].value == r"C:\Temp\payload.exe"


def test_notification_program_is_hashed_not_the_queue_file(tmp_path: Path) -> None:
    """Resolution inspects the program BITS runs, so it is hash- and signer-checked."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin,
        {
            _QMGR_FILE: _queue(
                _job_record(
                    program=r"C:\Temp\payload.exe",
                    parameters=r"C:\Temp\payload.exe -stage2",
                )
            ),
            r"Temp\payload.exe": b"MZ payload",
        },
    )

    finding = plugin.run()[0]
    resolved = ResolutionPipeline(plugin.filesystem).resolve(finding)

    assert finding.resolve_target == r"C:\Temp\payload.exe"
    assert resolved.exists is True
    assert resolved.sha256


def test_job_owned_by_the_system_account_reports_system_access(
    tmp_path: Path,
) -> None:
    """A job the SYSTEM account owns runs its notification command as SYSTEM."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin,
        {
            _QMGR_FILE: _queue(
                _job_record(program=r"C:\Temp\payload.exe", owner="S-1-5-18")
            )
        },
    )

    assert plugin.run()[0].access_gained is AccessLevel.SYSTEM


def test_repeated_record_copies_are_reported_once(tmp_path: Path) -> None:
    """The database keeps superseded page copies, which must not multiply findings."""
    record = _job_record(program=r"C:\Temp\payload.exe")
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(plugin, {_QMGR_FILE: _queue(record, record, record)})

    assert len(plugin.run()) == 1


def test_legacy_queue_file_is_read(tmp_path: Path) -> None:
    """Pre-Windows 10 hosts keep the queue in qmgr0.dat, which is read the same way."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin, {_LEGACY_FILE: _queue(_job_record(program=r"C:\Temp\payload.exe"))}
    )

    assert plugin.run()[0].path == rf"{_LEGACY_FILE}\{_JOB_ID}"


def test_absent_queue_reports_nothing(tmp_path: Path) -> None:
    """An image without a BITS state file produces no finding."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)

    assert plugin.run() == []


def test_truncated_record_is_ignored(tmp_path: Path) -> None:
    """A record cut short by a damaged image yields no half-read finding."""
    record = _job_record(program=r"C:\Temp\payload.exe")
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(plugin, {_QMGR_FILE: _FILLER + record[: len(record) // 2]})

    assert plugin.run() == []


def test_parameters_that_omit_the_program_keep_both(tmp_path: Path) -> None:
    """BITS runs the program with its parameters, so a report must carry both."""
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(
        plugin,
        {
            _QMGR_FILE: _queue(
                _job_record(
                    program=r"C:\Windows\System32\cmd.exe", parameters="/c whoami"
                )
            )
        },
    )

    assert plugin.run()[0].value == r"C:\Windows\System32\cmd.exe /c whoami"


def test_record_on_a_read_window_boundary_is_still_found(tmp_path: Path) -> None:
    """A large queue is read in overlapping windows, so no record falls between them."""
    record = _job_record(program=r"C:\Temp\payload.exe")
    lead = _WINDOW_BYTES - len(record) // 2
    plugin = make_plugin(BitsNotifyCommand, tmp_path)
    setup_filesystem(plugin, {_QMGR_FILE: b"\xab" * lead + record + _FILLER})

    assert len(plugin.run()) == 1
