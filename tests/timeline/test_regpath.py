"""Tests for Sysmon TargetObject spellings: SID rewriting and control sets."""

from __future__ import annotations

from pyrsistencesniper.timeline.regpath import sysmon_target_candidates

_SIDS = {"jdoe": "S-1-5-21-7-8-9-1001"}


def test_machine_path_is_offered_unchanged() -> None:
    """HKLM needs no rewriting, so exactly one candidate is offered."""
    assert sysmon_target_candidates("HKLM\\SOFTWARE\\Run\\Evil", {}) == (
        "HKLM\\SOFTWARE\\Run\\Evil",
    )


def test_user_path_is_rewritten_onto_the_sid() -> None:
    """Sysmon logs HKU by SID, never by account name, so the name must go."""
    assert sysmon_target_candidates("HKU\\jdoe\\Software\\Run\\Evil", _SIDS) == (
        "HKU\\S-1-5-21-7-8-9-1001\\Software\\Run\\Evil",
    )


def test_user_lookup_ignores_case() -> None:
    """Profile folder casing varies across images and must not lose the SID."""
    assert sysmon_target_candidates("HKU\\JDoe\\Software\\Run", _SIDS) == (
        "HKU\\S-1-5-21-7-8-9-1001\\Software\\Run",
    )


def test_unknown_user_yields_nothing() -> None:
    """No SID means no string Sysmon could have written, so offer none."""
    assert sysmon_target_candidates("HKU\\ghost\\Software\\Run", _SIDS) == ()


def test_path_already_carrying_a_sid_is_left_alone() -> None:
    """A path already in SID form is usable as-is, even for an unmapped SID."""
    path = "HKU\\S-1-5-18\\Software\\Run"
    assert sysmon_target_candidates(path, _SIDS) == (path,)


def test_numbered_control_set_also_offers_the_current_spelling() -> None:
    """Sysmon may have logged the CurrentControlSet alias for the same key."""
    assert sysmon_target_candidates(
        "HKLM\\SYSTEM\\ControlSet002\\Services\\Evil\\ImagePath", {}
    ) == (
        "HKLM\\SYSTEM\\ControlSet002\\Services\\Evil\\ImagePath",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Evil\\ImagePath",
    )


def test_current_control_set_also_offers_the_numbered_spelling() -> None:
    """The reverse alias is equally likely, so ControlSet001 is offered too."""
    assert sysmon_target_candidates(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Evil\\ImagePath", {}
    ) == (
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Evil\\ImagePath",
        "HKLM\\SYSTEM\\ControlSet001\\Services\\Evil\\ImagePath",
    )


def test_user_path_under_a_control_set_gets_both_rewrites() -> None:
    """SID mapping and control-set aliasing compose rather than shadow each other."""
    assert sysmon_target_candidates("HKU\\jdoe\\ControlSet001\\Evil", _SIDS) == (
        "HKU\\S-1-5-21-7-8-9-1001\\ControlSet001\\Evil",
        "HKU\\S-1-5-21-7-8-9-1001\\CurrentControlSet\\Evil",
    )


def test_a_path_with_no_control_set_yields_one_spelling() -> None:
    """Candidates stay minimal so event matching is not flooded with noise."""
    assert len(sysmon_target_candidates("HKLM\\SOFTWARE\\Run\\Evil", {})) == 1
