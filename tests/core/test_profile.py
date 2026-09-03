"""Tests for DetectionProfile loading, rule merging, and per-check policy lookup."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import FilterRule
from pyrsistencesniper.core.profile import (
    CheckPolicy,
    DetectionProfile,
    _coerce_enabled,
    _parse_rules,
)

if TYPE_CHECKING:
    from pathlib import Path


def _write_profile(tmp_path: Path, yaml_content: str) -> Path:
    """Write a profile file under tmp_path and return its path."""
    profile_path = tmp_path / "profile.yaml"
    profile_path.write_text(yaml_content, encoding="utf-8")
    return profile_path


def _load_profile(tmp_path: Path, yaml_content: str) -> DetectionProfile:
    """Write a profile file and load it."""
    return DetectionProfile.load(_write_profile(tmp_path, yaml_content))


def test_empty_profile_no_rules() -> None:
    """A default profile filters nothing, so scans run unfiltered without config."""
    profile = DetectionProfile()
    assert profile.allow == ()
    assert profile.block == ()
    assert profile.checks == {}


def test_default_profile_has_rules() -> None:
    """The bundled default profile ships real rules, so noise is cut without setup."""
    profile = DetectionProfile.load(None)
    assert len(profile.checks) > 0
    rules = profile.policy_for("winlogon_shell")
    assert len(rules.allow) >= 1


def test_policy_for_unknown_check_returns_globals() -> None:
    """Global rules reach checks the profile never names, including new plugins."""
    profile = DetectionProfile(
        allow=(FilterRule(value_matches="global"),),
        block=(FilterRule(path_matches="Temp"),),
    )
    rules = profile.policy_for("unknown_check")
    assert rules.allow == (FilterRule(value_matches="global"),)
    assert rules.block == (FilterRule(path_matches="Temp"),)
    assert rules.enabled is True


def test_policy_for_merges_global_and_check_rules() -> None:
    """Check rules extend the globals rather than replacing them, globals first."""
    profile = DetectionProfile(
        allow=(FilterRule(value_matches="global_allow"),),
        block=(FilterRule(path_matches="global_block"),),
        checks={
            "my_check": CheckPolicy(
                allow=(FilterRule(value_matches="check_allow"),),
                block=(FilterRule(path_matches="check_block"),),
            )
        },
    )
    rules = profile.policy_for("my_check")
    assert len(rules.allow) == 2
    assert rules.allow[0].value_matches == "global_allow"
    assert rules.allow[1].value_matches == "check_allow"
    assert len(rules.block) == 2
    assert rules.block[0].path_matches == "global_block"
    assert rules.block[1].path_matches == "check_block"


def test_policy_for_disabled_check() -> None:
    """An operator can switch a whole check off, not just filter its findings."""
    profile = DetectionProfile(
        checks={"noisy": CheckPolicy(enabled=False)},
    )
    assert profile.policy_for("noisy").enabled is False


def test_policy_for_unknown_check_enabled_by_default() -> None:
    """Checks are opt-out, so a new plugin runs without being listed anywhere."""
    profile = DetectionProfile()
    assert profile.policy_for("any_check_id").enabled is True


def test_load_global_allow(tmp_path: Path) -> None:
    """YAML escaping is undone exactly once, so the stored regex still compiles."""
    profile = _load_profile(
        tmp_path,
        """\
allow:
  - reason: "Known good"
    value_matches: "^explorer\\\\.exe$"
""",
    )
    assert len(profile.allow) == 1
    assert profile.allow[0].value_matches == "^explorer\\.exe$"
    assert profile.allow[0].reason == "Known good"


def test_load_global_block(tmp_path: Path) -> None:
    """Blocking is configurable from the profile file, not only allow-listing."""
    profile = _load_profile(
        tmp_path,
        """\
block:
  - reason: "Suspicious"
    path_matches: "Temp"
""",
    )
    assert len(profile.block) == 1
    assert profile.block[0].path_matches == "Temp"


def test_load_check_override_disabled(tmp_path: Path) -> None:
    """Disabling one check leaves every other check running."""
    profile = _load_profile(
        tmp_path,
        """\
checks:
  noisy_check:
    enabled: false
""",
    )
    assert profile.policy_for("noisy_check").enabled is False
    assert profile.policy_for("other_check").enabled is True


def test_load_check_override_with_allow(tmp_path: Path) -> None:
    """Per-check allow entries are parsed into rules, not left as raw mappings."""
    profile = _load_profile(
        tmp_path,
        """\
checks:
  my_check:
    allow:
      - value_matches: "safe"
""",
    )
    assert len(profile.checks["my_check"].allow) == 1


def test_load_invalid_yaml_raises(tmp_path: Path) -> None:
    """A malformed profile fails loudly instead of silently scanning unfiltered."""
    profile_path = _write_profile(tmp_path, "not: [valid: yaml: {{{")
    with pytest.raises(ValueError, match="Failed to parse"):
        DetectionProfile.load(profile_path)


def test_load_nonexistent_returns_empty(tmp_path: Path) -> None:
    """A path that does not exist is no config at all, not a load failure."""
    profile = DetectionProfile.load(tmp_path / "missing.yaml")
    assert profile.allow == ()
    assert profile.checks == {}


def test_load_non_dict_yaml_raises(tmp_path: Path) -> None:
    """A top-level list is a structural mistake worth stopping on, not ignoring."""
    profile_path = _write_profile(tmp_path, "- item1\n- item2\n")
    with pytest.raises(TypeError, match="must be a YAML mapping"):
        DetectionProfile.load(profile_path)


def test_load_empty_yaml_raises(tmp_path: Path) -> None:
    """An empty YAML file parses to None, which is not a dict."""
    profile_path = _write_profile(tmp_path, "")
    with pytest.raises(TypeError, match="must be a YAML mapping"):
        DetectionProfile.load(profile_path)


def test_load_checks_as_list_no_crash(tmp_path: Path) -> None:
    """A wrongly shaped checks block degrades to no overrides, not a traceback."""
    profile = _load_profile(
        tmp_path,
        """\
checks:
  - item1
  - item2
""",
    )
    assert profile.checks == {}


def test_invalid_regex_rule_is_dropped_at_load() -> None:
    """A rule whose regex cannot compile is discarded, not raised at classify time."""
    rules = _parse_rules([{"reason": "bad", "value_matches": "([unclosed"}], "demo")

    assert rules == ()


def test_invalid_regex_rule_does_not_discard_sibling_rules() -> None:
    """One unusable rule leaves the rest of the check's rules in force."""
    rules = _parse_rules(
        [
            {"value_matches": "([unclosed"},
            {"value_matches": r"^good\.exe$"},
        ],
        "demo",
    )

    assert len(rules) == 1
    assert rules[0].value_matches == r"^good\.exe$"


def test_non_string_regex_rule_is_dropped() -> None:
    """A regex field holding a non-string is dropped rather than crashing re.compile."""
    rules = _parse_rules([{"path_matches": 42}], "demo")

    assert rules == ()


def test_unknown_rule_key_is_reported(caplog: pytest.LogCaptureFixture) -> None:
    """A misspelled rule key is warned about, because it silently widens the rule."""
    with caplog.at_level(logging.WARNING):
        rules = _parse_rules([{"signer_matches": "Microsoft"}], "demo")

    assert len(rules) == 1
    assert "unknown key" in caplog.text
    assert "signer_matches" in caplog.text


def test_enabled_accepts_real_booleans() -> None:
    """A genuine boolean passes through untouched."""
    assert _coerce_enabled(False, "demo") is False
    assert _coerce_enabled(True, "demo") is True


def test_enabled_accepts_yaml_string_spellings() -> None:
    """Quoted booleans are honoured rather than being read as a truthy string."""
    assert _coerce_enabled("false", "demo") is False
    assert _coerce_enabled("No", "demo") is False
    assert _coerce_enabled("true", "demo") is True


def test_enabled_fails_open_on_garbage(caplog: pytest.LogCaptureFixture) -> None:
    """An unusable enabled value keeps the check running and says so."""
    with caplog.at_level(logging.WARNING):
        assert _coerce_enabled("maybe", "demo") is True

    assert "unusable" in caplog.text
