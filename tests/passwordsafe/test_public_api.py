"""Verify the reviewed public PasswordSafe package boundary."""

import bonobo_core
import bonobo_core.passwordsafe as passwordsafe



#### Expose service, session, safe result, limit, and failure categories.
####
def test_public_surface_contains_only_reviewed_categories() -> None:
    reviewed = {
        "AuthenticationError",
        "AuthenticationReason",
        "CURRENT_FORMAT_VERSION",
        "Change",
        "CryptoBackendError",
        "CryptoBackendReason",
        "ExternalModificationError",
        "FailureReason",
        "FailureStage",
        "FieldKind",
        "FormatVersion",
        "HeaderFieldType",
        "IncompatibleExportError",
        "IncompatibleExportReason",
        "IntegrityError",
        "IntegrityReason",
        "MINIMUM_ITERATIONS",
        "MalformedReason",
        "MalformedVaultError",
        "NewRecord",
        "OperationReason",
        "PasswordSafeError",
        "PreservationWarning",
        "PreservationWarningCode",
        "ProtectedRecordError",
        "RecordFieldType",
        "RecordHandle",
        "RecordView",
        "RecoveryAvailableError",
        "RecoveryRevision",
        "RemoveField",
        "ResourceLimitError",
        "ResourceLimitReason",
        "ResourceLimits",
        "RevisionToken",
        "SaveResult",
        "SecretBuffer",
        "SecretClosedError",
        "SecretLease",
        "SetBytesField",
        "SetSecretField",
        "SetTextField",
        "SetTimeField",
        "SetUInt32Field",
        "StaleRevisionError",
        "StorageError",
        "StorageReason",
        "SuspendedSession",
        "UnsavedChangesError",
        "UnsupportedFormatError",
        "UnsupportedFormatReason",
        "VaultService",
        "VaultSession",
    }

    assert set(passwordsafe.__all__) == reviewed
    assert all(hasattr(passwordsafe, name) for name in reviewed)



#### Keep raw save documents and retained key state off the public session API.
####
def test_public_session_has_no_codec_or_publication_escape_hatches() -> None:
    forbidden = {
        "abort_save",
        "crypto_state",
        "export_snapshot",
        "finish_save",
        "prepare_save",
    }

    assert forbidden.isdisjoint(passwordsafe.VaultSession.__dict__)



#### Publish the first reviewed core facade version consistently.
####
def test_public_package_version_is_first_facade_release() -> None:
    assert bonobo_core.__version__ == "0.1.0"
