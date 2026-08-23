"""Verify the PasswordSafe failure taxonomy exposes only safe stable metadata.

Failures are intentionally structured for callers while avoiding decrypted data,
paths, record identities, and platform exception text.
"""

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



#### Keep every public leaf failure in the safe PasswordSafe hierarchy.
####
#### Each constructor receives a closed set of reason codes rather than an
#### arbitrary caller string that could contain a path or decrypted fragment.
####
def test_leaf_failures_expose_stable_safe_metadata() -> None:
    errors = (
        AuthenticationError(AuthenticationReason.PASSWORD_CHECK_FAILED),
        MalformedVaultError(MalformedReason.INVALID_FIELD),
        UnsupportedFormatError(UnsupportedFormatReason.UNSUPPORTED_VERSION),
        IncompatibleExportError(IncompatibleExportReason.UNREPRESENTABLE_FIELD),
        ResourceLimitError(ResourceLimitReason.MAX_ITERATIONS),
        CryptoBackendError(CryptoBackendReason.UNAVAILABLE),
        ProtectedRecordError(),
        StaleRevisionError(),
        UnsavedChangesError(),
        ExternalModificationError(),
        StorageError(StorageReason.PUBLICATION_FAILED),
        RecoveryAvailableError(),
    )

    for error in errors:
        assert isinstance(error.stage, FailureStage)
        assert error.reason
        assert str(error)
        assert "fabricated-secret" not in str(error)
        assert "fabricated-secret" not in repr(error)
