"""YAML-driven detection profiles with global and per-check allow/block rules."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from pyrsistencesniper.core.models import (
    MATCH_TO_SEVERITY,
    FilterRule,
    Finding,
    MatchResult,
    Severity,
)

logger = logging.getLogger(__name__)

_RULE_KEYS = frozenset(
    {"reason", "value_matches", "path_matches", "signer", "hash", "not_lolbin"}
)
_REGEX_KEYS = ("value_matches", "path_matches")
_TRUTHY = frozenset({"true", "yes", "on", "1"})
_FALSY = frozenset({"false", "no", "off", "0"})

_DEFAULT_PROFILE_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "default_profile.yaml"
)


@dataclass(frozen=True, slots=True)
class CheckPolicy:
    """Allow and block rules that decide one check's severities."""

    enabled: bool = True
    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)

    def classify(self, finding: Finding) -> Severity:
        """Assign a severity by matching the finding against block then allow rules."""
        if any(rule.matches(finding) for rule in self.block):
            return Severity.HIGH

        best = MatchResult.NONE
        for rule in self.allow:
            result = rule.match_result(finding)
            if result == MatchResult.FULL:
                return MATCH_TO_SEVERITY[MatchResult.FULL]
            if result == MatchResult.PARTIAL:
                best = MatchResult.PARTIAL

        return MATCH_TO_SEVERITY[best]


@dataclass(frozen=True, slots=True)
class DetectionProfile:
    """A parsed profile: global rules plus per-check overrides."""

    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)
    checks: dict[str, CheckPolicy] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None) -> DetectionProfile:
        """Parse a YAML profile file, or the bundled default when path is None."""
        if path is None:
            path = _DEFAULT_PROFILE_PATH
        data = _read_yaml(path)
        if data is None:
            return cls()
        return cls(
            allow=_parse_rules(data.get("allow", [])),
            block=_parse_rules(data.get("block", [])),
            checks=_parse_checks(data.get("checks", {})),
        )

    def policy_for(self, check_id: str) -> CheckPolicy:
        """Return the merged policy (global and check-specific rules) for a check."""
        override = self.checks.get(check_id)
        if override is None:
            return CheckPolicy(allow=self.allow, block=self.block)
        return CheckPolicy(
            enabled=override.enabled,
            allow=(*self.allow, *override.allow),
            block=(*self.block, *override.block),
        )


def _read_yaml(path: Path) -> dict[str, object] | None:
    """Read a YAML profile into a dict, or None when the file does not exist."""
    try:
        with path.open("r", encoding="utf-8") as profile_file:
            data = yaml.safe_load(profile_file)
    except FileNotFoundError:
        logger.warning("Profile not found: %s, using defaults", path)
        return None
    except (yaml.YAMLError, OSError) as exc:
        raise ValueError(f"Failed to parse detection profile {path}") from exc

    if not isinstance(data, dict):
        raise TypeError(
            f"Detection profile {path} must be a YAML mapping,"
            f" got {type(data).__name__}"
        )
    return data


def _parse_checks(raw: object) -> dict[str, CheckPolicy]:
    """Convert a raw checks mapping into a dict of CheckPolicy instances."""
    if not isinstance(raw, dict):
        return {}
    checks: dict[str, CheckPolicy] = {}
    for check_id, check_data in raw.items():
        if not isinstance(check_data, dict):
            continue
        checks[check_id] = CheckPolicy(
            enabled=_coerce_enabled(check_data.get("enabled", True), check_id),
            allow=_parse_rules(check_data.get("allow", []), check_id),
            block=_parse_rules(check_data.get("block", []), check_id),
        )
    return checks


def _coerce_enabled(raw: object, check_id: str) -> bool:
    """Interpret a check's enabled flag, failing open when the value is unusable."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in _TRUTHY:
            return True
        if text in _FALSY:
            return False
    logger.warning(
        "Check %s has an unusable 'enabled' value (%r); keeping the check enabled",
        check_id,
        raw,
    )
    return True


def _rule_is_usable(item: dict[str, object], check_id: str) -> bool:
    """Report whether a rule mapping is safe to evaluate against findings."""
    for key in item:
        if key not in _RULE_KEYS:
            logger.warning(
                "Rule for %s has unknown key %r; it will match too widely",
                check_id,
                key,
            )
    for key in _REGEX_KEYS:
        pattern = item.get(key, "")
        if not pattern:
            continue
        if not isinstance(pattern, str):
            logger.warning(
                "Rule for %s has a non-string %s (%r); rule dropped",
                check_id,
                key,
                pattern,
            )
            return False
        try:
            re.compile(pattern)
        except re.error as exc:
            logger.warning(
                "Rule for %s has an invalid %s regex (%s); rule dropped",
                check_id,
                key,
                exc,
            )
            return False
    return True


def _parse_rules(raw: object, check_id: str = "<global>") -> tuple[FilterRule, ...]:
    """Convert rule dictionaries into a tuple of validated FilterRule instances."""
    if not isinstance(raw, list):
        return ()
    rules: list[FilterRule] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        if not _rule_is_usable(item, check_id):
            continue
        rules.append(
            FilterRule(
                reason=item.get("reason", ""),
                value_matches=item.get("value_matches", ""),
                path_matches=item.get("path_matches", ""),
                signer=item.get("signer", ""),
                hash=item.get("hash", ""),
                not_lolbin=bool(item.get("not_lolbin", False)),
            )
        )
    return tuple(rules)
