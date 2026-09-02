"""Specify revision-bound record draft commands without real vault I/O.

These tests exercise only fabricated public metadata.  The fake session keeps
opaque PasswordSafe identities private while exposing observable mutations.
"""

from dataclasses import fields, replace
from pathlib import Path

import pytest
from fakes import FakeVaultService, FakeVaultSession, fabricated_record_view

from bonobo_core.application import ApplicationCommandError, RecordDraft, RecordKey, VaultApplication
from bonobo_core.passwordsafe import SecretBuffer



#### Provide a fabricated unlocked application with one editable record.
####
@pytest.fixture
def application() -> VaultApplication[FakeVaultSession]:
    session = FakeVaultSession((fabricated_record_view(),))
    service = FakeVaultService(session)
    app = VaultApplication(service)
    app.open(Path("fabricated-vault.psafe3"), SecretBuffer.from_bytes(b"fabricated-unlock"), "Fabricated")
    return app



#### Keep the draft contract closed to immutable non-secret metadata.
####
def test_record_draft_never_exposes_secret_or_url_fields() -> None:
    assert {field.name for field in fields(RecordDraft)} == {
        "key",
        "generation",
        "title",
        "group",
        "username",
        "protected",
    }



#### Apply one confirmed draft as one session revision and safely reproject it.
####
def test_confirming_record_draft_commits_exactly_one_revision(
    application: VaultApplication[FakeVaultSession],
) -> None:
    draft = application.begin_edit(RecordKey(1), application.snapshot.generation)
    changed = replace(draft, title="Alpha Portal Renamed")
    password = SecretBuffer.from_bytes(b"fabricated-password-change")

    result = application.commit_edit(changed, password)

    assert password.closed
    assert result.dirty
    assert result.records[0].title == "Alpha Portal Renamed"
    assert application.test_session_change_count == 1



#### Reject a stale draft without mutating the current session or consuming another revision.
####
def test_stale_draft_rejects_before_session_mutation(
    application: VaultApplication[FakeVaultSession],
) -> None:
    draft = application.begin_edit(RecordKey(1), application.snapshot.generation)
    password = SecretBuffer.from_bytes(b"fabricated-password-change")
    application.set_search("alpha", application.snapshot.generation)

    with pytest.raises(ApplicationCommandError, match="view is stale"):
        application.commit_edit(draft, password)

    assert password.closed
    assert application.test_session_change_count == 0



#### Filter only safe record projection fields while preserving facade-owned keys.
####
def test_search_changes_only_the_safe_projection(application: VaultApplication[FakeVaultSession]) -> None:
    result = application.set_search("research", application.snapshot.generation)

    assert result.records == application.snapshot.records
    assert result.records[0].key == RecordKey(1)
    assert "example.invalid" not in repr(result)



#### Keep a transient URL edit out of every draft and committed application snapshot.
####
def test_url_edit_uses_a_closed_transient_secret_buffer(
    application: VaultApplication[FakeVaultSession],
) -> None:
    draft = application.begin_edit(RecordKey(1), application.snapshot.generation)
    website = SecretBuffer.from_bytes(b"https://changed.example.invalid/private")

    result = application.commit_edit(draft, None, url=website)

    assert website.closed
    assert application.test_session_change_count == 1
    assert "example.invalid" not in repr(result)
