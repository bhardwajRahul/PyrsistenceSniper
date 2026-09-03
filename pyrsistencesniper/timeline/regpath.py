"""Registry path spellings a Sysmon TargetObject may carry for one finding."""

from __future__ import annotations

import re
from collections.abc import Mapping

__all__ = ["sysmon_target_candidates"]

_HKU_PREFIX = "HKU\\"
_SID_PREFIX = "S-1-"
_NUMBERED_CONTROLSET = re.compile(r"\\ControlSet\d{3}\\", re.IGNORECASE)
_CURRENT_CONTROLSET = "\\CurrentControlSet\\"
_DEFAULT_CONTROLSET = "\\ControlSet001\\"


# Sysmon names the key as the running system saw it, which an offline scan never
# reproduces exactly: a per-user hive appears under the account's SID rather than
# its profile directory name, and the SYSTEM hive's numbered control set appears
# as CurrentControlSet. match_value holds one string, so each spelling becomes
# its own descriptor rather than widening the model.
def sysmon_target_candidates(
    finding_path: str, sid_by_username: Mapping[str, str]
) -> tuple[str, ...]:
    """Return the spellings of a finding path a Sysmon record could carry."""
    rooted = _with_sid(finding_path, sid_by_username)
    if rooted is None:
        return ()
    return tuple(dict.fromkeys(_controlset_spellings(rooted)))


# None rather than an unmatchable descriptor: a descriptor that cannot match
# would report the artifact as merely unmatched instead of leaving it blank.
def _with_sid(finding_path: str, sid_by_username: Mapping[str, str]) -> str | None:
    """Rewrite an HKU path onto the owner's SID, or None if no SID is known."""
    if not finding_path.upper().startswith(_HKU_PREFIX):
        return finding_path
    owner, separator, remainder = finding_path[len(_HKU_PREFIX) :].partition("\\")
    if owner.upper().startswith(_SID_PREFIX):
        return finding_path
    sid = sid_by_username.get(owner.casefold(), "")
    if not sid:
        return None
    return f"{_HKU_PREFIX}{sid}{separator}{remainder}"


def _controlset_spellings(path: str) -> list[str]:
    """Return the path under both the numbered and the current control set."""
    # The replacement is a function: re.sub reads backslashes in a literal one.
    swapped = _NUMBERED_CONTROLSET.sub(lambda _match: _CURRENT_CONTROLSET, path)
    if swapped != path:
        return [path, swapped]
    lowered = path.casefold()
    marker = _CURRENT_CONTROLSET.casefold()
    if marker not in lowered:
        return [path]
    marker_index = lowered.index(marker)
    return [
        path,
        path[:marker_index] + _DEFAULT_CONTROLSET + path[marker_index + len(marker) :],
    ]
