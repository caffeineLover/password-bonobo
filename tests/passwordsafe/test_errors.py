"""Verify the PasswordSafe failure taxonomy exposes only safe stable metadata.

Failures are intentionally structured for callers while avoiding decrypted data,
paths, record identities, and platform exception text.
"""

from collections.abc import Callable
from typing import cast

import pytest

import bonobo_core.passwordsafe as passwordsafe
from bonobo_core.passwordsafe.errors import (
    AuthenticationError,
    AuthenticationReason,
    CryptoBackendError,
    CryptoBackendReason,
    ExternalModificationError,
    FailureStage,
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



#### Give callers a typed integrity category with a stable reason code.
####
#### The stored message remains generic even when callers keep unrelated
#### sensitive context nearby, preventing error presentation from leaking it.
####
def test_integrity_error_is_typed_and_safe() -> None:
    fabricated_secret = "fabricated-secret"
    error = IntegrityError(IntegrityReason.HMAC_MISMATCH)

    assert error.stage is FailureStage.AUTHENTICATE
    assert error.reason == "hmac-mismatch"
    assert str(error) == "vault integrity validation failed"
    assert fabricated_secret not in str(error)
    assert fabricated_secret not in repr(error)



#### Expose the outer encrypted-file budget through the closed resource taxonomy.
####
def test_encrypted_file_resource_error_is_typed_and_safe() -> None:
    error = ResourceLimitError(ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES)

    assert error.stage is FailureStage.ENVELOPE
    assert error.reason == "max-encrypted-file-bytes"
    assert str(error) == "vault resource limit exceeded"



#### Keep every public leaf failure in the safe PasswordSafe hierarchy.
####
#### Each constructor receives a closed set of reason codes rather than an
#### arbitrary caller string that could contain a path or decrypted fragment.
####
def test_leaf_failures_expose_stable_safe_metadata() -> None:
    errors = (
        (AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED), FailureStage.AUTHENTICATE,
         "password-check-failed", "vault authentication failed"),
        (IntegrityError(IntegrityReason.HMAC_MISMATCH), FailureStage.AUTHENTICATE, "hmac-mismatch",
         "vault integrity validation failed"),
        (MalformedVaultError(MalformedReason.INVALID_FIELD), FailureStage.VALIDATE, "invalid-field",
         "vault content is malformed"),
        (UnsupportedFormatError(UnsupportedFormatReason.UNSUPPORTED_VERSION), FailureStage.VALIDATE,
         "unsupported-version", "vault format is unsupported"),
        (IncompatibleExportError(IncompatibleExportReason.UNREPRESENTABLE_FIELD), FailureStage.SERIALIZE,
         "unrepresentable-field", "vault export is incompatible"),
        (ResourceLimitError(ResourceLimitReason.MAX_ITERATIONS), FailureStage.ENVELOPE, "max-iterations",
         "vault resource limit exceeded"),
        (CryptoBackendError(CryptoBackendReason.UNAVAILABLE), FailureStage.AUTHENTICATE, "unavailable",
         "cryptographic backend is unavailable"),
        (ProtectedRecordError(), FailureStage.MUTATE, "protected-record", "record is protected"),
        (StaleRevisionError(), FailureStage.MUTATE, "stale-revision", "vault revision is stale"),
        (UnsavedChangesError(), FailureStage.LOCK, "unsaved-changes", "vault has unsaved changes"),
        (ExternalModificationError(), FailureStage.PUBLISH, "external-modification", "vault changed externally"),
        (StorageError(StorageReason.PUBLICATION_FAILED), FailureStage.PUBLISH, "publication-failed",
         "vault storage operation failed"),
        (RecoveryAvailableError(), FailureStage.RECOVER, "recovery-available", "encrypted recovery is available"),
    )

    for error, stage, reason, message in errors:
        assert error.stage is stage
        assert error.reason == reason
        assert str(error) == message
        assert "fabricated-secret" not in str(error)
        assert "fabricated-secret" not in repr(error)



#### Refuse a reason enum from the wrong leaf family at the runtime boundary.
####
def test_leaf_failures_reject_wrong_reason_family() -> None:
    wrong_reason = cast(AuthenticationReason, IntegrityReason.HMAC_MISMATCH)

    with pytest.raises(TypeError, match="authentication reason"):
        AuthenticationError(wrong_reason)



#### Keep arbitrary constructor text out of a base error's args, str, and repr.
####
#### The dynamic call intentionally models an untyped caller attempting to pass a
#### path and secret as a legacy message argument; that call must be rejected.
####
def test_base_error_rejects_arbitrary_message_and_remains_safe() -> None:
    fabricated_text = "E:/fabricated/path/fabricated-secret"
    unsafe_constructor = cast(Callable[..., PasswordSafeError], PasswordSafeError)

    with pytest.raises(TypeError) as caught:
        unsafe_constructor(FailureStage.PARSE, IntegrityReason.HMAC_MISMATCH, fabricated_text)

    base_error = PasswordSafeError(FailureStage.PARSE, IntegrityReason.HMAC_MISMATCH)

    assert fabricated_text not in str(caught.value)
    assert fabricated_text not in repr(caught.value)
    assert fabricated_text not in str(base_error)
    assert fabricated_text not in repr(base_error)
    assert all(fabricated_text not in str(argument) for argument in base_error.args)



#### Export all stage and reason types required to construct public leaf failures.
####
def test_public_package_exports_the_closed_failure_taxonomy() -> None:
    error = passwordsafe.AuthenticationError(passwordsafe.AuthenticationReason.PASSWORD_CHECK_FAILED)

    assert error.stage is passwordsafe.FailureStage.AUTHENTICATE
    assert passwordsafe.IntegrityReason.HMAC_MISMATCH.value == "hmac-mismatch"
    assert passwordsafe.MalformedReason.INVALID_FIELD.value == "invalid-field"
    assert passwordsafe.UnsupportedFormatReason.UNSUPPORTED_VERSION.value == "unsupported-version"
    assert passwordsafe.IncompatibleExportReason.UNREPRESENTABLE_FIELD.value == "unrepresentable-field"
    assert passwordsafe.ResourceLimitReason.MAX_FIELDS.value == "max-fields"
    assert passwordsafe.CryptoBackendReason.UNAVAILABLE.value == "unavailable"
    assert passwordsafe.OperationReason.STALE_REVISION.value == "stale-revision"
    assert passwordsafe.StorageReason.PUBLICATION_FAILED.value == "publication-failed"
