"""Tests for OutputBase helpers: result_to_dict and build_flags."""

from __future__ import annotations

import io
import sys
from typing import Any

from pyrsistencesniper.core.models import AccessLevel, Enrichment, Finding
from pyrsistencesniper.output.base import OutputBase, _console_stream


def _make_finding(**kwargs: object) -> Finding:
    """Build a Finding with all required fields set; kwargs override the defaults."""
    defaults = {
        "path": "HKLM\\Run",
        "value": "test.exe",
        "technique": "Test",
        "mitre_id": "T0000",
        "description": "d",
        "access_gained": AccessLevel.SYSTEM,
        "hostname": "HOST",
        "check_id": "test_check",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def _row(**kwargs: object) -> dict[str, Any]:
    """Build the report row a renderer would emit for one Finding."""
    return OutputBase.result_to_dict((_make_finding(**kwargs), ()))


def test_result_to_dict_enum_to_value() -> None:
    """A report carries the enum's value, never the AccessLevel.USER repr."""
    assert _row(access_gained=AccessLevel.USER)["access_gained"] == "USER"


def test_result_to_dict_tuple_joined() -> None:
    """Multi-valued fields flatten into one cell so every format can carry them."""
    assert _row(references=("ref1", "ref2"))["references"] == "ref1 | ref2"


def test_result_to_dict_unresolved_field_renders_empty() -> None:
    """An unresolved field renders empty so it cannot read as a checked negative."""
    assert _row(is_lolbin=None)["is_lolbin"] == ""


def test_result_to_dict_resolved_false_stays_false() -> None:
    """A field the resolver actually determined to be false is preserved."""
    assert _row(is_lolbin=False)["is_lolbin"] is False


def test_build_flags_omits_not_found_when_existence_unknown() -> None:
    """An unresolved target is not claimed to be missing."""
    assert "NOT_FOUND" not in OutputBase.build_flags(_row(exists=None))


def test_build_flags_reports_not_found_when_resolution_missed() -> None:
    """A target the resolver looked for and did not find is flagged NOT_FOUND."""
    assert "NOT_FOUND" in OutputBase.build_flags(_row(exists=False))


def test_result_to_dict_enrichment_keys() -> None:
    """Enrichment data is flattened into the row dict with dotted keys."""
    enrichment = Enrichment(provider="vt", data={"score": "5/70"})
    row = OutputBase.result_to_dict((_make_finding(), (enrichment,)))
    assert row["enrichment.vt.score"] == "5/70"


def test_build_flags_lolbin() -> None:
    """A lone true flag renders as its bare name, with no separator debris."""
    row = _row(is_lolbin=True, is_builtin=False, is_in_os_directory=False, exists=True)
    assert OutputBase.build_flags(row) == "LOLBin"


def test_build_flags_not_found() -> None:
    """A resolved absence surfaces in the flag column an analyst reads."""
    row = _row(
        is_lolbin=False, is_builtin=False, is_in_os_directory=False, exists=False
    )
    assert "NOT_FOUND" in OutputBase.build_flags(row)


def test_build_flags_multiple() -> None:
    """Flags accumulate rather than the first true one winning the column."""
    row = _row(is_lolbin=True, is_builtin=True, is_in_os_directory=True, exists=True)
    flags = OutputBase.build_flags(row)
    assert "LOLBin" in flags
    assert "Builtin" in flags
    assert "OS_DIR" in flags


def test_build_flags_empty() -> None:
    """A plain, present, non-OS binary produces no flags at all."""
    row = _row(is_lolbin=False, is_builtin=False, is_in_os_directory=False, exists=True)
    assert OutputBase.build_flags(row) == ""


def test_console_stream_escapes_characters_the_codepage_cannot_encode() -> None:
    """A name outside the console codepage must not abort the report part-written."""
    # An attacker names the payload, so an unencodable artifact is reachable on
    # purpose: unescaped it would take every later finding down with it.
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    original = sys.stdout
    sys.stdout = legacy
    try:
        stream = _console_stream()
        stream.write("C:\\Users\\hx\\\u666e\u901a.exe\n")
        stream.flush()
    finally:
        sys.stdout = original

    written = legacy.buffer.getvalue().decode("cp1252")
    assert "\\u666e" in written
    assert "\\u901a" in written
