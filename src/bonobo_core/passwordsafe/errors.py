"""Provide safe typed failure categories for the PasswordSafe core.

Errors expose stable stages and reason codes for caller-owned presentation.  They
never accept or retain paths, vault content, record identities, or secret values.
"""

from enum import StrEnum



#### Identify the core operation boundary that produced a safe failure.
####
#### Stages let callers choose remediation without receiving platform exception
#### text or decrypted data from an internal implementation detail.
####
class FailureStage(StrEnum):
    ENVELOPE = "envelope"
    AUTHENTICATE = "authenticate"
    DECRYPT = "decrypt"
    PARSE = "parse"
    VALIDATE = "validate"
    MUTATE = "mutate"
    SERIALIZE = "serialize"
    PUBLISH = "publish"
    RECOVER = "recover"
    LOCK = "lock"



#### Supply a closed family for stable PasswordSafe failure reason codes.
####
#### Leaf-specific enums inherit this base so the base exception cannot receive
#### arbitrary caller text that might accidentally include sensitive context.
####
class FailureReason(StrEnum):
    pass



#### Describe a failed authentication check without distinguishing user input.
####
class AuthenticationReason(FailureReason):
    PASSWORD_CHECK_FAILED = "password-check-failed"
    INVALID_PASSWORD_CHECK = "invalid-password-check"



#### Describe an authenticated-data integrity failure.
####
class IntegrityReason(FailureReason):
    HMAC_MISMATCH = "hmac-mismatch"
    UNEXPECTED_EOF = "unexpected-eof"



#### Describe a mandatory format-structure violation.
####
class MalformedReason(FailureReason):
    INVALID_FIELD = "invalid-field"
    MISSING_MANDATORY_FIELD = "missing-mandatory-field"
    INVALID_ENVELOPE = "invalid-envelope"



#### Describe a declared format level or mandatory feature this core cannot use.
####
class UnsupportedFormatReason(FailureReason):
    UNSUPPORTED_VERSION = "unsupported-version"
    UNSUPPORTED_MANDATORY_CONTENT = "unsupported-mandatory-content"



#### Describe an explicit export that cannot preserve all source content.
####
class IncompatibleExportReason(FailureReason):
    UNREPRESENTABLE_FIELD = "unrepresentable-field"
    TARGET_VERSION_UNSUPPORTED = "target-version-unsupported"



#### Describe a resource budget exceeded before unsafe work occurs.
####
class ResourceLimitReason(FailureReason):
    MAX_ITERATIONS = "max-iterations"
    MAX_RECORDS = "max-records"
    MAX_FIELDS = "max-fields"
    MAX_ENCRYPTED_FILE_BYTES = "max-encrypted-file-bytes"
    MAX_INLINE_PAYLOAD_BYTES = "max-inline-payload-bytes"
    MAX_DECODED_TEXT_BYTES = "max-decoded-text-bytes"



#### Describe a required cryptographic backend that cannot be trusted or used.
####
class CryptoBackendReason(FailureReason):
    UNAVAILABLE = "unavailable"
    INVALID_ABI = "invalid-abi"
    SELF_TEST_FAILED = "self-test-failed"



#### Describe a fixed session or storage state failure.
####
class OperationReason(FailureReason):
    PROTECTED_RECORD = "protected-record"
    STALE_REVISION = "stale-revision"
    UNSAVED_CHANGES = "unsaved-changes"
    EXTERNAL_MODIFICATION = "external-modification"
    RECOVERY_AVAILABLE = "recovery-available"



#### Describe a storage or publication operation that did not complete safely.
####
class StorageReason(FailureReason):
    PREPARATION_FAILED = "preparation-failed"
    PUBLICATION_FAILED = "publication-failed"
    VERIFICATION_FAILED = "verification-failed"



_FAILURE_MESSAGES: dict[FailureReason, str] = {
    AuthenticationReason.PASSWORD_CHECK_FAILED: "vault authentication failed",
    AuthenticationReason.INVALID_PASSWORD_CHECK: "vault authentication failed",
    IntegrityReason.HMAC_MISMATCH: "vault integrity validation failed",
    IntegrityReason.UNEXPECTED_EOF: "vault integrity validation failed",
    MalformedReason.INVALID_FIELD: "vault content is malformed",
    MalformedReason.MISSING_MANDATORY_FIELD: "vault content is malformed",
    MalformedReason.INVALID_ENVELOPE: "vault content is malformed",
    UnsupportedFormatReason.UNSUPPORTED_VERSION: "vault format is unsupported",
    UnsupportedFormatReason.UNSUPPORTED_MANDATORY_CONTENT: "vault format is unsupported",
    IncompatibleExportReason.UNREPRESENTABLE_FIELD: "vault export is incompatible",
    IncompatibleExportReason.TARGET_VERSION_UNSUPPORTED: "vault export is incompatible",
    ResourceLimitReason.MAX_ITERATIONS: "vault resource limit exceeded",
    ResourceLimitReason.MAX_RECORDS: "vault resource limit exceeded",
    ResourceLimitReason.MAX_FIELDS: "vault resource limit exceeded",
    ResourceLimitReason.MAX_ENCRYPTED_FILE_BYTES: "vault resource limit exceeded",
    ResourceLimitReason.MAX_INLINE_PAYLOAD_BYTES: "vault resource limit exceeded",
    ResourceLimitReason.MAX_DECODED_TEXT_BYTES: "vault resource limit exceeded",
    CryptoBackendReason.UNAVAILABLE: "cryptographic backend is unavailable",
    CryptoBackendReason.INVALID_ABI: "cryptographic backend is unavailable",
    CryptoBackendReason.SELF_TEST_FAILED: "cryptographic backend is unavailable",
    OperationReason.PROTECTED_RECORD: "record is protected",
    OperationReason.STALE_REVISION: "vault revision is stale",
    OperationReason.UNSAVED_CHANGES: "vault has unsaved changes",
    OperationReason.EXTERNAL_MODIFICATION: "vault changed externally",
    OperationReason.RECOVERY_AVAILABLE: "encrypted recovery is available",
    StorageReason.PREPARATION_FAILED: "vault storage operation failed",
    StorageReason.PUBLICATION_FAILED: "vault storage operation failed",
    StorageReason.VERIFICATION_FAILED: "vault storage operation failed",
}



#### Validate that a leaf receives only its designated closed reason family.
####
#### Runtime checks protect untyped callers and deserialized adapters, whose values
#### bypass static annotations and must not select another leaf's remediation code.
####
def _require_reason(reason: FailureReason, expected: type[FailureReason], label: str) -> None:
    if not isinstance(reason, expected):
        raise TypeError(f"{label} reason must use its designated reason enum")



#### Carry safe stage and reason metadata for all PasswordSafe core failures.
####
#### The generic message is selected only by leaf classes.  Callers supply their
#### own localized wording and must not present raw platform exceptions instead.
####
class PasswordSafeError(Exception):
    stage: FailureStage
    reason: str
    _message: str



    #### Initialize one safe failure from closed stage and reason taxonomy values.
    ####
    #### Direct construction remains safe for framework boundaries because callers
    #### cannot supply a message; the stored text is selected only from the map.
    ####
    def __init__(self, stage: FailureStage, reason: FailureReason) -> None:
        if not isinstance(stage, FailureStage):
            raise TypeError("failure stage must use the FailureStage enum")
        if not isinstance(reason, FailureReason):
            raise TypeError("failure reason must use a closed reason enum")
        self.stage = stage
        self.reason = reason.value
        self._message = _FAILURE_MESSAGES[reason]
        super().__init__(self._message)



    #### Return the leaf's generic message for safe ordinary exception handling.
    ####
    def __str__(self) -> str:
        return self._message



#### Report a password-check failure without exposing the supplied passphrase.
####
class AuthenticationError(PasswordSafeError):



    #### Initialize an authentication failure at the fixed authentication stage.
    ####
    def __init__(self, reason: AuthenticationReason) -> None:
        _require_reason(reason, AuthenticationReason, "authentication")
        super().__init__(FailureStage.AUTHENTICATE, reason)



#### Report an HMAC or authenticated-stream integrity failure safely.
####
class IntegrityError(PasswordSafeError):



    #### Initialize an integrity failure at the fixed authentication stage.
    ####
    def __init__(self, reason: IntegrityReason) -> None:
        _require_reason(reason, IntegrityReason, "integrity")
        super().__init__(FailureStage.AUTHENTICATE, reason)



#### Report malformed mandatory content without retaining decoded fragments.
####
class MalformedVaultError(PasswordSafeError):



    #### Initialize a malformed-content failure at the validation stage.
    ####
    def __init__(self, reason: MalformedReason) -> None:
        _require_reason(reason, MalformedReason, "malformed vault")
        super().__init__(FailureStage.VALIDATE, reason)



#### Report a valid but unsupported format declaration or mandatory feature.
####
class UnsupportedFormatError(PasswordSafeError):



    #### Initialize an unsupported-format failure at the validation stage.
    ####
    def __init__(self, reason: UnsupportedFormatReason) -> None:
        _require_reason(reason, UnsupportedFormatReason, "unsupported format")
        super().__init__(FailureStage.VALIDATE, reason)



#### Report an explicit export that would violate the no-loss contract.
####
class IncompatibleExportError(PasswordSafeError):



    #### Initialize an incompatible-export failure at the serialization stage.
    ####
    def __init__(self, reason: IncompatibleExportReason) -> None:
        _require_reason(reason, IncompatibleExportReason, "incompatible export")
        super().__init__(FailureStage.SERIALIZE, reason)



#### Report exhausted parsing or authentication budgets before unsafe allocation.
####
class ResourceLimitError(PasswordSafeError):



    #### Initialize a resource-limit failure at the fixed envelope stage.
    ####
    def __init__(self, reason: ResourceLimitReason) -> None:
        _require_reason(reason, ResourceLimitReason, "resource limit")
        super().__init__(FailureStage.ENVELOPE, reason)



#### Report an unavailable, incompatible, or failed required cryptographic backend.
####
class CryptoBackendError(PasswordSafeError):



    #### Initialize a crypto-backend failure at the authentication stage.
    ####
    def __init__(self, reason: CryptoBackendReason) -> None:
        _require_reason(reason, CryptoBackendReason, "crypto backend")
        super().__init__(FailureStage.AUTHENTICATE, reason)



#### Report that a protected record blocks an ordinary mutation.
####
class ProtectedRecordError(PasswordSafeError):



    #### Initialize the fixed protected-record mutation failure.
    ####
    def __init__(self) -> None:
        super().__init__(FailureStage.MUTATE, OperationReason.PROTECTED_RECORD)



#### Report that a mutation was based on an obsolete document revision.
####
class StaleRevisionError(PasswordSafeError):



    #### Initialize the fixed stale-revision mutation failure.
    ####
    def __init__(self) -> None:
        super().__init__(FailureStage.MUTATE, OperationReason.STALE_REVISION)



#### Report that locking would discard uncommitted session changes.
####
class UnsavedChangesError(PasswordSafeError):



    #### Initialize the fixed unsaved-changes lock failure.
    ####
    def __init__(self) -> None:
        super().__init__(FailureStage.LOCK, OperationReason.UNSAVED_CHANGES)



#### Report that the source changed since the session captured its baseline.
####
class ExternalModificationError(PasswordSafeError):



    #### Initialize the fixed external-modification publication failure.
    ####
    def __init__(self) -> None:
        super().__init__(FailureStage.PUBLISH, OperationReason.EXTERNAL_MODIFICATION)



#### Report a storage failure without including a selected path or platform text.
####
class StorageError(PasswordSafeError):



    #### Initialize a storage failure at the fixed publication stage.
    ####
    def __init__(self, reason: StorageReason) -> None:
        _require_reason(reason, StorageReason, "storage")
        super().__init__(FailureStage.PUBLISH, reason)



#### Report that a known-good encrypted recovery revision is available.
####
class RecoveryAvailableError(PasswordSafeError):



    #### Initialize the fixed recovery-availability notification category.
    ####
    def __init__(self) -> None:
        super().__init__(FailureStage.RECOVER, OperationReason.RECOVERY_AVAILABLE)
