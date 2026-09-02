"""Verify application DTOs remain immutable, closed, and safe to present.

The application boundary must not make vault paths, handles, revisions, or
secret-bearing values available to presentation clients.
"""

from dataclasses import fields

import pytest

import bonobo_core.application as application
from bonobo_core.application import (
    ApplicationFailureReason,
    ApplicationPhase,
    ApplicationSnapshot,
    RecordKey,
    RecordSummary,
)
from bonobo_core.application.errors import to_application_failure
from bonobo_core.passwordsafe import (
    AuthenticationError,
    AuthenticationReason,
    CryptoBackendError,
    CryptoBackendReason,
    ExternalModificationError,
    IncompatibleExportError,
    IncompatibleExportReason,
    IntegrityError,
    IntegrityReason,
    MalformedReason,
    MalformedVaultError,
    PasswordSafeError,
    ProtectedRecordError,
    RecoveryAvailableError,
    ResourceLimitError,
    ResourceLimitReason,
    StaleRevisionError,
    StorageError,
    StorageReason,
    UnsavedChangesError,
    UnsupportedFormatError,
    UnsupportedFormatReason,
)
from bonobo_core.passwordsafe.errors import FailureStage



#### Keep the snapshot schema closed to the UI-safe application contract.
####
def test_application_snapshot_rejects_secret_or_path_fields() -> None:
    assert {field.name for field in fields(ApplicationSnapshot)} == {
        "generation",
        "phase",
        "display_label",
        "dirty",
        "records",
        "selected",
        "failure",
        "decision",
    }



#### Preserve the exact phase values used by adapters and persisted tests.
####
def test_application_phase_uses_the_closed_state_values() -> None:
    assert set(ApplicationPhase) == {
        ApplicationPhase.EMPTY,
        ApplicationPhase.BUSY,
        ApplicationPhase.UNLOCKED_CLEAN,
        ApplicationPhase.UNLOCKED_DIRTY,
        ApplicationPhase.LOCKED,
        ApplicationPhase.AWAITING_DECISION,
    }



#### Expose exactly the application contract needed by adapters and later facade work.
####
def test_application_package_exports_only_the_reviewed_contract() -> None:
    assert set(application.__all__) == {
        "ApplicationFailure",
        "ApplicationFailureReason",
        "ApplicationPhase",
        "ApplicationSnapshot",
        "BrowserPort",
        "ClipboardPort",
        "DecisionToken",
        "RecordKey",
        "RecordDraft",
        "RecordSummary",
        "ApplicationCommandError",
        "CloseChoice",
        "VaultApplication",
        "project_records",
        "search_records",
    }



#### Refuse mutation of the DTO supplied to desktop and future mobile clients.
####
def test_record_summary_is_immutable() -> None:
    summary = RecordSummary(RecordKey(1), "Alpha", "Research", "sample-user", False)

    with pytest.raises(AttributeError):
        summary.title = "Changed"  # type: ignore[misc]



#### Map public PasswordSafe failures to closed application reasons only.
####
def test_failure_mapping_uses_stable_reason_without_exception_text() -> None:
    failure = to_application_failure(AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED))

    assert failure.reason is ApplicationFailureReason.AUTHENTICATION_FAILED
    assert "authentication" in failure.presentation_key
    assert "vault authentication failed" not in repr(failure)



#### Preserve distinct recovery behavior while retaining the active session.
####
def test_failure_mapping_distinguishes_external_modification() -> None:
    failure = to_application_failure(ExternalModificationError())

    assert failure.reason is ApplicationFailureReason.EXTERNAL_MODIFICATION



#### Fail closed when a public base error has no more-specific application map.
####
def test_failure_mapping_uses_unexpected_fallback_without_error_text() -> None:
    error = PasswordSafeError(FailureStage.PARSE, IntegrityReason.HMAC_MISMATCH)
    failure = to_application_failure(error)

    assert failure.reason is ApplicationFailureReason.UNEXPECTED
    assert str(error) not in repr(failure)



#### Omit arbitrary unexpected exception text from the generic fallback DTO.
####
def test_failure_mapping_hides_unexpected_exception_text() -> None:
    failure = to_application_failure(RuntimeError("fabricated-secret E:/fabricated/path"))

    assert failure.reason is ApplicationFailureReason.UNEXPECTED
    assert "fabricated-secret" not in repr(failure)



#### Cover every public PasswordSafe leaf in the closed application failure map.
####
@pytest.mark.parametrize(
    ("error", "reason"),
    (
        (
            AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED),
            ApplicationFailureReason.AUTHENTICATION_FAILED,
        ),
        (IntegrityError(IntegrityReason.HMAC_MISMATCH), ApplicationFailureReason.INTEGRITY_FAILED),
        (MalformedVaultError(MalformedReason.INVALID_FIELD), ApplicationFailureReason.MALFORMED_VAULT),
        (
            UnsupportedFormatError(UnsupportedFormatReason.UNSUPPORTED_VERSION),
            ApplicationFailureReason.UNSUPPORTED_FORMAT,
        ),
        (
            IncompatibleExportError(IncompatibleExportReason.UNREPRESENTABLE_FIELD),
            ApplicationFailureReason.INCOMPATIBLE_EXPORT,
        ),
        (ResourceLimitError(ResourceLimitReason.MAX_RECORDS), ApplicationFailureReason.RESOURCE_LIMIT),
        (CryptoBackendError(CryptoBackendReason.UNAVAILABLE), ApplicationFailureReason.CRYPTO_BACKEND),
        (ProtectedRecordError(), ApplicationFailureReason.PROTECTED_RECORD),
        (StaleRevisionError(), ApplicationFailureReason.STALE_REVISION),
        (UnsavedChangesError(), ApplicationFailureReason.UNSAVED_CHANGES),
        (ExternalModificationError(), ApplicationFailureReason.EXTERNAL_MODIFICATION),
        (StorageError(StorageReason.PUBLICATION_FAILED), ApplicationFailureReason.STORAGE),
        (RecoveryAvailableError(), ApplicationFailureReason.RECOVERY_AVAILABLE),
    ),
)
def test_failure_mapping_covers_every_public_passwordsafe_leaf(
    error: PasswordSafeError,
    reason: ApplicationFailureReason,
) -> None:
    failure = to_application_failure(error)

    assert failure.reason is reason
    assert str(error) not in repr(failure)
