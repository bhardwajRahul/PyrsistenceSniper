"""Resolves file-backed time evidence descriptors into $MFT candidates."""

from __future__ import annotations

from datetime import timedelta

from pyrsistencesniper.core.models import FileWriteTime
from pyrsistencesniper.timeline.base import Precision, TimeCandidate, format_ts
from pyrsistencesniper.timeline.mft_index import MftIndex

_TIMESTOMP_SLACK = timedelta(seconds=60)


# Only the $MFT is consulted: its timestamps live inside the parsed record and
# survive collection intact. Filesystem mtimes are never used because a repacked
# collection may carry copy times indistinguishable from originals.
class FileTimeResolver:
    """Turns FileWriteTime descriptors into $MFT record candidates."""

    def __init__(self, mft_index: MftIndex) -> None:
        self._mft = mft_index

    @property
    def available(self) -> bool:
        """Report whether an $MFT was found and parsed at all."""
        return self._mft.available

    def resolve_file(self, evidence: FileWriteTime) -> list[TimeCandidate]:
        """Return the $MFT $SI write candidate for a declared artifact file."""
        entry = self._mft.lookup(evidence.path)
        if entry is None or entry.si_modified is None:
            return []

        detail = f"$MFT $SI Modified of {evidence.path} (record {entry.record_number})"
        if (
            entry.fn_modified is not None
            and entry.si_modified < entry.fn_modified - _TIMESTOMP_SLACK
        ):
            delta = entry.fn_modified - entry.si_modified
            detail += (
                f"; timestomping hint: $SI predates $FN by {delta} "
                f"($FN Modified {format_ts(entry.fn_modified)})"
            )
        return [
            TimeCandidate(
                when=entry.si_modified,
                source="$MFT",
                detail=detail,
                precision=Precision.WEAK if evidence.weak else Precision.EXACT,
            )
        ]
