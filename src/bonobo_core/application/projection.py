"""Project authenticated public record views into deterministic safe list data.

The application facade retains the handle-to-key map.  This module consumes that
map to produce only UI-safe summaries and does not mutate a PasswordSafe view.
"""

from collections.abc import Mapping

from bonobo_core.passwordsafe import RecordHandle, RecordView

from .types import RecordKey, RecordSummary



#### Project views through facade-owned keys and sort their safe summaries deterministically.
####
#### The supplied mapping is keyed by the exact session-scoped handles.  Missing
#### handles are rejected rather than inventing a new identity at this boundary.
####
def project_records(
    records: tuple[RecordView, ...],
    record_keys: Mapping[RecordHandle, RecordKey],
) -> tuple[RecordSummary, ...]:
    summaries = tuple(
        RecordSummary(record_keys[record.handle], record.title, record.group, record.username, record.protected)
        for record in records
    )
    return tuple(
        sorted(
            summaries,
            key=lambda summary: (summary.group.casefold(), summary.title.casefold(), summary.key),
        )
    )



#### Filter safe summaries by title, group, or username without changing their order.
####
#### Default matching uses Unicode casefolding to make case-insensitive search
#### deterministic.  The case-sensitive mode compares the same three fields as-is.
####
def search_records(
    records: tuple[RecordSummary, ...],
    query: str,
    *,
    case_sensitive: bool = False,
) -> tuple[RecordSummary, ...]:
    if case_sensitive:
        return tuple(
            summary
            for summary in records
            if query in summary.title or query in summary.group or query in summary.username
        )
    normalized_query = query.casefold()
    return tuple(
        summary
        for summary in records
        if normalized_query in summary.title.casefold()
        or normalized_query in summary.group.casefold()
        or normalized_query in summary.username.casefold()
    )
