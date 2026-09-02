"""Verify record projection and search disclose only the approved summary fields.

Projection owns no domain identities and never mutates the immutable views it
receives from the authenticated PasswordSafe session.
"""

from hypothesis import given
from hypothesis import strategies as st
from tests.passwordsafe.helpers import fabricated_record_view

from bonobo_core.application import RecordKey, RecordSummary, project_records, search_records
from bonobo_core.passwordsafe import RecordView



#### Project a record with its exact pre-bound handle-to-key identity.
####
def test_projection_exposes_only_non_secret_record_summary() -> None:
    view = fabricated_record_view()

    summary = project_records((view,), {view.handle: RecordKey(1)})[0]

    assert summary == RecordSummary(RecordKey(1), "Alpha Portal", "Research", "sample-user", False)
    assert "example.invalid" not in repr(summary)
    assert "fabricated-password" not in repr(summary)
    assert "fabricated-note" not in repr(summary)
    assert "fabricated-email" not in repr(summary)
    assert "fabricated-uuid" not in repr(summary)
    assert "fabricated-unknown" not in repr(summary)



#### Sort summaries predictably while keeping facade-issued keys unchanged.
####
def test_projection_sorts_by_casefolded_group_title_then_key() -> None:
    views = (
        _view("Zulu", "Team", "one"),
        _view("alpha", "team", "two"),
        _view("Alpha", "Team", "three"),
    )
    keys = {view.handle: RecordKey(index) for index, view in enumerate(views, start=1)}

    summaries = project_records(views, keys)

    assert tuple(summary.key for summary in summaries) == (RecordKey(2), RecordKey(3), RecordKey(1))



#### Match only safe summary fields and retain their existing relative order.
####
def test_search_matches_safe_fields_without_reordering() -> None:
    records = (
        RecordSummary(RecordKey(1), "Alpha", "Research", "sample-user", False),
        RecordSummary(RecordKey(2), "Beta", "Alpha group", "other", False),
        RecordSummary(RecordKey(3), "Gamma", "Elsewhere", "ALPHA-user", True),
    )

    assert search_records(records, "alpha") == (records[0], records[1], records[2])
    assert search_records(records, "ALPHA", case_sensitive=True) == (records[2],)



#### Preserve each fabricated view and omit its generated URL from the projection.
####
@given(
    title=st.text(min_size=0, max_size=24),
    group=st.text(min_size=0, max_size=24),
    username=st.text(min_size=0, max_size=24),
    url=st.text(min_size=1, max_size=24),
)
def test_projection_never_mutates_or_exposes_generated_urls(
    title: str,
    group: str,
    username: str,
    url: str,
) -> None:
    source = fabricated_record_view()
    sensitive_url = f"https://example.invalid/{url}"
    view = RecordView(source.handle, source.revision, title, group, username, sensitive_url, source.protected)

    summary = project_records((view,), {view.handle: RecordKey(1)})[0]

    assert view.url == sensitive_url
    assert summary == RecordSummary(RecordKey(1), title, group, username, False)
    assert sensitive_url not in repr(summary)



#### Build one view whose URL must never become part of its application summary.
####
def _view(title: str, group: str, username: str) -> RecordView:
    source = fabricated_record_view()
    return RecordView(source.handle, source.revision, title, group, username, source.url, source.protected)
