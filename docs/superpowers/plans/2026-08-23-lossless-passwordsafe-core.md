# Lossless PasswordSafe Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fully typed, lossless, authenticated PasswordSafe V3 core with Botan-backed Twofish and crash-safe
local publication.

**Architecture:** The Python package owns the ordered lossless document model, schema, authenticated streaming codec,
session mutations, and transaction coordinator.  A narrow `ctypes` adapter delegates Twofish blocks to a pinned Botan
3.13 library, while storage adapters publish only fully reopened and validated encrypted candidates.

**Tech Stack:** CPython 3.14, standard-library `ctypes`/`hashlib`/`hmac`/`secrets`, Botan 3.13.0, pytest 9, Hypothesis
6.161, strict mypy, Ruff, Bandit, pip-audit, REUSE, Pandoc, XeLaTeX, and GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-23-lossless-passwordsafe-core-design.md`

## Global Constraints

- Read the complete spec, root `AGENTS.md`, and routed Python standards before each implementation task.
- Support Python `>=3.14,<3.15`; all human-authored Python is strictly typed and passes the structure checker.
- Precede every Python class and function with the required adjacent `####` prose block and preserve three blank lines
  between declaration units.
- Use only the official PasswordSafe format specification, Bonobo documents, and synthetic observations as behavioral
  authorities; no Gorilla source, comments, identifiers, tests, or fixtures enter implementation code.
- New vaults declare `0x0311`; ordinary saves retain supported declarations from `0x0300` through `0x0311`.
- Preserve unknown field type, payload, order, multiplicity, and association; never add a Bonobo-private field.
- Treat attachments `0x25`-`0x29` and passkeys `0x2A`-`0x2F` as opaque, losslessly streamed content.
- Use Botan `3.13.0` as the only production Twofish backend; no home-grown or silent fallback cipher is permitted.
- Use at least `262_144` stretching iterations for new or hardened vaults; stronger existing counts survive unchanged.
- Never write plaintext vault, field, attachment, temporary, or recovery data to storage.
- Never put a passphrase, credential, URL, UUID, record identity, or vault path in logs, exceptions, or object reprs.
- Authentication, integrity, parsing, validation, and publication failures leave the source vault unchanged.
- Apply test-driven development: observe every targeted test fail before implementing its behavior, then make the
  smallest production change that passes it.
- Run focused tests after each step and the full quality suite at every task checkpoint.
- Commit each completed task independently; do not combine unrelated cleanup with a task commit.

---

## Planned File Map

### Product package

- `src/bonobo_core/passwordsafe/__init__.py`: reviewed public PasswordSafe API exports.
- `src/bonobo_core/passwordsafe/constants.py`: envelope constants, field identifiers, versions, and resource limits.
- `src/bonobo_core/passwordsafe/errors.py`: safe typed failure taxonomy.
- `src/bonobo_core/passwordsafe/secrets.py`: mutable secret owners and bounded secret leases.
- `src/bonobo_core/passwordsafe/crypto.py`: key stretching, HMAC, CBC, random-source, and Twofish protocols.
- `src/bonobo_core/passwordsafe/botan.py`: narrow Botan 3.13 `ctypes` adapter and known-answer self-test.
- `src/bonobo_core/passwordsafe/payloads.py`: inline and encrypted-span field payloads.
- `src/bonobo_core/passwordsafe/snapshots.py`: immutable encrypted snapshots and safe span readers.
- `src/bonobo_core/passwordsafe/model.py`: ordered raw fields, records, documents, handles, revisions, and manifests.
- `src/bonobo_core/passwordsafe/schema.py`: official header/record field schemas and typed codecs.
- `src/bonobo_core/passwordsafe/custom_fields.py`: `0x0311` property parsing and targeted editing.
- `src/bonobo_core/passwordsafe/reader.py`: quarantined streaming authentication and parser.
- `src/bonobo_core/passwordsafe/writer.py`: authenticated streaming serializer and candidate verifier.
- `src/bonobo_core/passwordsafe/session.py`: immutable views, explicit mutations, dirty state, and locking.
- `src/bonobo_core/passwordsafe/storage.py`: baseline detection, atomic replacement, and encrypted recovery.
- `src/bonobo_core/passwordsafe/service.py`: create/open/save/export/restore facade.

### Build, verification, fixtures, and documentation

- `tools/botan-source.json`: exact upstream Botan archive pin and checksum.
- `tools/build_botan.py`: safe fetch, verify, extract, configure, and build driver.
- `tools/run_passwordsafe_fuzz.py`: parser fuzz entry point and deterministic corpus runner.
- `tools/verify_passwordsafe_interop.py`: ordered synthetic-manifest comparison tool.
- `tests/passwordsafe/`: focused crypto, model, schema, reader, writer, session, storage, service, property, and fuzz
  tests.
- `tests/fixtures/synthetic/passwordsafe/`: allowlisted encrypted fabricated vaults and nonsecret manifests.
- `docs/guides/lossless-passwordsafe-core.md`: operator and developer run guide.
- `.github/workflows/foundation.yml`: desktop Botan build/integration gates and mobile cross-build smoke gates.
- Existing legal, compatibility, README, project-memory, REUSE, package, and lock files: delivery evidence and routing.

---

### Task 1: Pin and Build the Botan Dependency

**Files:**
- Create: `tools/botan-source.json`
- Create: `tools/build_botan.py`
- Create: `tests/foundation/test_botan_build.py`
- Modify: `.gitignore`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`
- Modify: `tools/check_provenance.py`
- Modify: `tests/foundation/test_provenance_ledger.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: Botan archive `https://botan.randombit.net/releases/Botan-3.13.0.tar.xz`.
- Produces: `BotanSourcePin`, `load_source_pin()`, `download_verified_archive()`, `extract_verified_archive()`,
  `build_botan()`, and a native-library path consumed by Task 3.

- [ ] **Step 1: Write failing source-pin and malicious-archive tests**

```python
def test_botan_source_pin_matches_approved_release() -> None:
    pin = load_source_pin(REPOSITORY_ROOT / "tools" / "botan-source.json")
    assert pin.version == "3.13.0"
    assert pin.sha256 == "12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620"
    assert pin.modules == ("ffi", "twofish")


def test_extract_rejects_parent_escape(tmp_path: Path) -> None:
    archive = create_tar_xz(tmp_path / "bad.tar.xz", {"../outside": b"forbidden"})
    with pytest.raises(BotanBuildError, match="unsafe archive member"):
        extract_verified_archive(archive, tmp_path / "output")
```

- [ ] **Step 2: Run the focused tests and confirm missing imports fail**

Run: `uv run pytest tests/foundation/test_botan_build.py -v`

Expected: collection fails because `tools.build_botan` does not exist.

- [ ] **Step 3: Add the exact machine-readable source pin**

```json
{
  "archive": "Botan-3.13.0.tar.xz",
  "modules": ["ffi", "twofish"],
  "sha256": "12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620",
  "signature": "https://botan.randombit.net/releases/Botan-3.13.0.tar.xz.asc",
  "source": "https://botan.randombit.net/releases/Botan-3.13.0.tar.xz",
  "version": "3.13.0"
}
```

- [ ] **Step 4: Implement verified acquisition, safe extraction, and platform command generation**

```python
@dataclass(frozen=True, slots=True)
class BotanSourcePin:
    version: str
    archive: str
    source: str
    signature: str
    sha256: str
    modules: tuple[str, ...]


def download_verified_archive(pin: BotanSourcePin, cache_directory: Path) -> Path:
    cache_directory.mkdir(parents=True, exist_ok=True)
    destination = cache_directory / pin.archive
    if not destination.exists():
        temporary = destination.with_suffix(destination.suffix + ".partial")
        with urlopen(pin.source, timeout=60) as response, temporary.open("xb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        temporary.replace(destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, pin.sha256):
        raise BotanBuildError("Botan archive checksum mismatch")
    return destination
```

Use `tarfile.data_filter` plus an explicit `member_path.is_relative_to(destination)` check.  Generate these configure
profiles exactly: Windows `--cc=msvc --os=windows --cpu=x86_64`; macOS `--cc=clang --os=darwin`; Linux
`--cc=gcc --os=linux`; Android `--cc=clang --os=android --cpu=arm64`; iOS `--cc=clang --os=ios --cpu=arm64`.  Every
profile also supplies `--minimized-build`, `--enable-modules=ffi,twofish`, and `--build-targets=shared`.

- [ ] **Step 5: Test command generation and execute a host build**

Run: `uv run pytest tests/foundation/test_botan_build.py -v`

Run: `uv run python -m tools.build_botan --target host --output build/botan`

Expected: tests pass and the command prints only the resulting library path and Botan version, never source or vault
paths.

- [ ] **Step 6: Record provenance and ignored build locations**

Add `/build/botan/` and `/.cache/botan/` to `.gitignore`.  Record Botan 3.13.0 as a direct native runtime dependency,
BSD-2-Clause, distributed with application artifacts but not the pure Python wheel.  Extend the provenance checker so
the JSON pin, ledger row, archive checksum, and enabled modules must agree.

- [ ] **Step 7: Run foundation gates and commit**

Run: `uv run pytest tests/foundation -v`

Run: `uv run python -m tools.check_provenance`

Run: `uv run reuse --no-multiprocessing lint`

```bash
git add .gitignore REUSE.toml tools/botan-source.json tools/build_botan.py \
  tools/check_provenance.py tests/foundation/test_botan_build.py \
  tests/foundation/test_provenance_ledger.py docs/legal/dependency-asset-provenance-ledger.md
git commit -m "build: pin verified Botan backend"
```

---

### Task 2: Establish Format Constants, Failures, Limits, and Secret Owners

**Files:**
- Create: `src/bonobo_core/passwordsafe/__init__.py`
- Create: `src/bonobo_core/passwordsafe/constants.py`
- Create: `src/bonobo_core/passwordsafe/errors.py`
- Create: `src/bonobo_core/passwordsafe/secrets.py`
- Create: `tests/passwordsafe/test_constants.py`
- Create: `tests/passwordsafe/test_errors.py`
- Create: `tests/passwordsafe/test_secrets.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: Python 3.14 buffer and enum facilities.
- Produces: `FormatVersion`, `ResourceLimits`, field enums, `PasswordSafeError` subclasses, `SecretBuffer`, and
  `SecretLease` used by every subsequent task.

- [ ] **Step 1: Write failing version, limit, safe-repr, and wipe tests**

```python
def test_format_version_round_trip() -> None:
    version = FormatVersion.from_uint16(0x0311)
    assert version.to_bytes() == b"\x11\x03"
    assert version.supported


def test_secret_buffer_wipes_owned_storage() -> None:
    storage = bytearray(b"fabricated-secret")
    secret = SecretBuffer.take_ownership(storage)
    secret.close()
    assert storage == bytearray(len(storage))
    assert "fabricated-secret" not in repr(secret)
```

- [ ] **Step 2: Run tests and confirm package imports fail**

Run: `uv run pytest tests/passwordsafe -k "constants or errors or secrets" -v`

Expected: collection fails because `bonobo_core.passwordsafe` is absent.

- [ ] **Step 3: Implement immutable versions and budgets**

```python
@dataclass(frozen=True, order=True, slots=True)
class FormatVersion:
    value: int

    @classmethod
    def from_uint16(cls, value: int) -> FormatVersion:
        if not 0 <= value <= 0xFFFF:
            raise ValueError("format version must fit uint16")
        return cls(value)

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(2, "little")

    @property
    def supported(self) -> bool:
        return 0x0300 <= self.value <= 0x0311


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_iterations: int = 10_000_000
    max_records: int = 1_000_000
    max_fields: int = 2_000_000
    max_inline_payload_bytes: int = 1_048_576
    max_decoded_text_bytes: int = 16_777_216
    io_chunk_bytes: int = 65_536
```

Define exact envelope constants, `HeaderFieldType`, `RecordFieldType`, `FieldKind`, current version `0x0311`, and
minimum
iterations `262_144`.

- [ ] **Step 4: Implement safe typed failures**

Create leaf exceptions for authentication, integrity, malformed content, unsupported format, incompatible export,
resource limit, crypto backend, protected record, stale revision, unsaved changes, external modification, storage, and
recovery availability.  Each accepts only a `FailureStage` enum and stable reason code; `__str__` returns a generic safe
message.

```python
class IntegrityError(PasswordSafeError):
    def __init__(self, reason: IntegrityReason) -> None:
        super().__init__(FailureStage.AUTHENTICATE, reason.value, "vault integrity validation failed")
```

- [ ] **Step 5: Implement mutable secret ownership and leases**

```python
class SecretBuffer:
    __slots__ = ("_closed", "_data")

    def __init__(self, data: bytearray) -> None:
        self._data = data
        self._closed = False

    def borrow(self) -> memoryview:
        if self._closed:
            raise SecretClosedError()
        return memoryview(self._data).toreadonly()

    def close(self) -> None:
        if not self._closed:
            self._data[:] = b"\x00" * len(self._data)
            self._closed = True
```

`SecretBuffer.take_ownership()` retains the caller's mutable bytearray, `from_bytes()` makes one controlled mutable
copy,
and `__enter__`/`__exit__` close it deterministically.  `SecretLease` owns a separate bounded `SecretBuffer`, implements
the same context contract, and never exposes its value in `repr`, exception messages, hashing, or equality diagnostics.

- [ ] **Step 6: Run focused quality gates and commit**

Run: `uv run pytest tests/passwordsafe -k "constants or errors or secrets" -v`

Run: `uv run ruff check src/bonobo_core/passwordsafe tests/passwordsafe`

Run: `uv run mypy src/bonobo_core/passwordsafe tests/passwordsafe`

Run: `uv run python -m tools.check_python_structure src tests tools`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe tests/passwordsafe
git commit -m "feat: add PasswordSafe domain primitives"
```

---

### Task 3: Bind Botan and Enforce the Twofish Known-Answer Gate

**Files:**
- Create: `src/bonobo_core/passwordsafe/crypto.py`
- Create: `src/bonobo_core/passwordsafe/botan.py`
- Create: `tests/passwordsafe/test_botan.py`
- Create: `tests/passwordsafe/test_crypto_protocol.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: `SecretBuffer`, a Task 1 Botan shared-library path, and fixed algorithm name `Twofish`.
- Produces: `TwofishBackend`, `TwofishKey`, `BotanBackend.open()`, and `BotanBackend.self_test()`.

- [ ] **Step 1: Write failing ABI, version, fixed-name, and vector tests**

```python
TWOFISH_ZERO_KEY = bytes(16)
TWOFISH_ZERO_BLOCK = bytes(16)
TWOFISH_ZERO_CIPHERTEXT = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")


def test_botan_twofish_known_answer(botan_library: Path) -> None:
    backend = BotanBackend.open(botan_library)
    backend.self_test()
    with SecretBuffer.from_bytes(TWOFISH_ZERO_KEY) as key_material:
        with backend.key(key_material) as key:
            assert key.encrypt_block(TWOFISH_ZERO_BLOCK) == TWOFISH_ZERO_CIPHERTEXT
            assert key.decrypt_block(TWOFISH_ZERO_CIPHERTEXT) == TWOFISH_ZERO_BLOCK
```

- [ ] **Step 2: Run and observe the missing adapter failure**

Run: `uv run pytest tests/passwordsafe/test_botan.py tests/passwordsafe/test_crypto_protocol.py -v`

Expected: collection fails because `BotanBackend` is not defined.

- [ ] **Step 3: Define narrow backend protocols**

```python
class TwofishKey(Protocol):
    def encrypt_block(self, block: bytes) -> bytes: raise NotImplementedError
    def decrypt_block(self, block: bytes) -> bytes: raise NotImplementedError
    def close(self) -> None: raise NotImplementedError


class TwofishBackend(Protocol):
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]: raise NotImplementedError
    def self_test(self) -> None: raise NotImplementedError
```

- [ ] **Step 4: Implement exact Botan FFI declarations and ownership**

Bind `botan_ffi_supports_api`, version functions, `botan_block_cipher_init`, `botan_block_cipher_destroy`,
`botan_block_cipher_set_key`, `botan_block_cipher_encrypt_blocks`, and `botan_block_cipher_decrypt_blocks`.  Fix every
`argtypes` and `restype`, pass only `b"Twofish"`, require major `3` and minor at least `13`, check every return code,
and
destroy native handles in explicit `close()` and defensive finalization.

```python
result = library.botan_block_cipher_init(ctypes.byref(handle), b"Twofish")
if result != 0:
    raise CryptoBackendError(CryptoReason.INITIALIZATION_FAILED)
```

- [ ] **Step 5: Run real integration tests and negative fake-library tests**

Run: `uv run pytest tests/passwordsafe/test_botan.py tests/passwordsafe/test_crypto_protocol.py -v`

Expected: official vectors pass; wrong ABI/version and forced nonzero FFI statuses raise safe typed errors.

- [ ] **Step 6: Run security/static gates and commit**

Run: `uv run ruff check src tests`

Run: `uv run mypy src tests`

Run: `uv run bandit -c pyproject.toml -r src tools`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/crypto.py src/bonobo_core/passwordsafe/botan.py \
  tests/passwordsafe/test_botan.py tests/passwordsafe/test_crypto_protocol.py
git commit -m "feat: add Botan Twofish backend"
```

---

### Task 4: Implement PasswordSafe Key Derivation, CBC, HMAC, and Randomness

**Files:**
- Modify: `src/bonobo_core/passwordsafe/crypto.py`
- Create: `tests/passwordsafe/test_crypto.py`
- Create: `tests/passwordsafe/helpers.py`
- Create: `tests/fixtures/synthetic/passwordsafe/crypto-vectors.json`

**Interfaces:**
- Consumes: `TwofishBackend`, passphrase `SecretBuffer`, salt, iteration count, IV, and ordered field chunks.
- Produces: `DerivedKey`, `VaultKeys`, `stretch_passphrase()`, `wrap_vault_keys()`, `unwrap_vault_keys()`,
  `CbcEncryptor`, `CbcDecryptor`, `FieldAuthenticator`, and `SystemRandomSource`.

- [ ] **Step 1: Write failing deterministic construction tests**

```python
def test_stretch_passphrase_matches_vector() -> None:
    password = SecretBuffer.from_bytes(b"fabricated-master-input-one")
    result = stretch_passphrase(password, bytes(range(32)), 2)
    assert bytes(result.borrow()).hex() == "5f6c18d1eb9bc8b0ea2b8fb5dd3720e02b57d8dd6b91ff0cc8ebb5b9a5bd45f8"


def test_cbc_round_trip_uses_previous_ciphertext(fake_twofish: TwofishBackend) -> None:
    plaintext = bytes(range(32))
    ciphertext = encrypt_cbc(fake_twofish, bytes(32), bytes(16), plaintext)
    assert decrypt_cbc(fake_twofish, bytes(32), bytes(16), ciphertext) == plaintext
```

Record the vector inputs, expected output, independent-authority description, and SHA-256 in
`crypto-vectors.json`; do not derive expected values by calling production code.

- [ ] **Step 2: Run tests and confirm missing construction functions fail**

Run: `uv run pytest tests/passwordsafe/test_crypto.py -v`

- [ ] **Step 3: Implement stretching and wrapped keys**

```python
digest = hashlib.sha256(passphrase.borrow())
digest.update(salt)
stretched = bytearray(digest.digest())
for _iteration in range(iterations):
    replacement = hashlib.sha256(stretched).digest()
    stretched[:] = replacement
return DerivedKey(stretched)
```

Reject iterations outside `1..limits.max_iterations` before looping.  Wrap and unwrap exactly four 16-byte blocks:
content key in B1/B2 and independent HMAC key in B3/B4.  Wipe intermediate mutable buffers in `finally` blocks.

- [ ] **Step 4: Implement continuous CBC and field authentication**

CBC accepts only 16-byte blocks.  Encryption XORs plaintext with the preceding ciphertext before the Twofish call;
decryption saves the current ciphertext, decrypts, XORs with the preceding ciphertext, then advances.  HMAC uses
SHA-256 with key L and updates only with each field's declared payload bytes in document order.

- [ ] **Step 5: Implement production randomness and deterministic test-only randomness**

```python
class SystemRandomSource:
    def bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length cannot be negative")
        return secrets.token_bytes(length)
```

Keep deterministic randomness and the independent `build_spec_vault()` fixture constructor in
`tests/passwordsafe/helpers.py`; do not import product reader/writer code into that constructor and do not export either
helper from `bonobo_core`.

- [ ] **Step 6: Verify vectors, zeroization paths, and commit**

Run: `uv run pytest tests/passwordsafe/test_crypto.py tests/passwordsafe/test_botan.py -v`

Run: `uv run ruff check src tests`

Run: `uv run mypy src tests`

```bash
git add src/bonobo_core/passwordsafe/crypto.py tests/passwordsafe/test_crypto.py tests/passwordsafe/helpers.py \
  tests/fixtures/synthetic/passwordsafe/crypto-vectors.json
git commit -m "feat: implement PasswordSafe cryptographic construction"
```

---

### Task 5: Build Immutable Snapshots, Payloads, and the Ordered Raw Model

**Files:**
- Create: `src/bonobo_core/passwordsafe/snapshots.py`
- Create: `src/bonobo_core/passwordsafe/payloads.py`
- Create: `src/bonobo_core/passwordsafe/model.py`
- Create: `tests/passwordsafe/test_snapshots.py`
- Create: `tests/passwordsafe/test_payloads.py`
- Create: `tests/passwordsafe/test_model.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: encrypted file objects, authenticated content keys, `FormatVersion`, and `SecretBuffer`.
- Produces: `EncryptedSnapshot`, `InlinePayload`, `EncryptedSpanPayload`, `RawField`, `RawRecord`, `VaultDocument`,
  `RecordHandle`, `RevisionToken`, `PreservationWarning`, and `SemanticManifest`.

- [ ] **Step 1: Write failing order, duplicate-UUID, deferred-payload, and close tests**

```python
def test_document_preserves_duplicate_uuid_records() -> None:
    first = raw_record(uuid_bytes=FABRICATED_RECORD_UUID, title=b"Alpha")
    second = raw_record(uuid_bytes=FABRICATED_RECORD_UUID, title=b"Beta")
    document = VaultDocument.create(VERSION_0311, HEADER_FIELDS, (first, second))
    assert document.records[0].handle != document.records[1].handle
    assert document.semantic_manifest().record_count == 2


def test_large_payload_streams_without_read_bytes(snapshot: EncryptedSnapshot) -> None:
    payload = EncryptedSpanPayload(snapshot, LARGE_FIELD_SPAN)
    assert b"".join(payload.iter_chunks(65_536)) == FABRICATED_LARGE_PAYLOAD
    assert snapshot.read_bytes_calls == 0
```

- [ ] **Step 2: Run and observe missing model imports**

Run: `uv run pytest tests/passwordsafe -k "snapshots or payloads or model" -v`

- [ ] **Step 3: Implement immutable snapshot identity and bounded readers**

`EncryptedSnapshot.capture()` copies ciphertext in bounded chunks to a caller-provided private directory using
exclusive creation and owner-only permissions, records SHA-256 and size, synchronizes it, and exposes bounded offset
reads.  It never includes source paths in `repr`.

- [ ] **Step 4: Implement payload ownership**

```python
class FieldPayload(Protocol):
    @property
    def length(self) -> int: raise NotImplementedError
    def iter_chunks(self, chunk_size: int) -> Iterator[memoryview]: raise NotImplementedError
    def close(self) -> None: raise NotImplementedError
```

`InlinePayload` owns a mutable buffer.  `EncryptedSpanPayload` retains snapshot, CBC starting state, ciphertext range,
five-byte frame offset, and declared data length; it decrypts only requested blocks and yields only payload bytes.

- [ ] **Step 5: Implement ordered immutable model and semantic manifests**

```python
@dataclass(frozen=True, slots=True)
class RawField:
    type_code: int
    payload: FieldPayload
    ordinal: int
    classification: FieldClassification


@dataclass(frozen=True, slots=True)
class VaultDocument:
    version: FormatVersion
    header_fields: tuple[RawField, ...]
    records: tuple[RawRecord, ...]
    revision: RevisionToken
    warnings: tuple[PreservationWarning, ...]
```

Manifest entries record section, record ordinal, field ordinal, type code, payload length, and SHA-256.  Exact
streaming comparison remains available; hashes are evidence indexes, not substitutes for final equality checks.

- [ ] **Step 6: Verify bounded memory and commit**

Run: `uv run pytest tests/passwordsafe -k "snapshots or payloads or model" -v`

Run: `uv run mypy src tests`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/snapshots.py src/bonobo_core/passwordsafe/payloads.py \
  src/bonobo_core/passwordsafe/model.py tests/passwordsafe/test_snapshots.py \
  tests/passwordsafe/test_payloads.py tests/passwordsafe/test_model.py
git commit -m "feat: add lossless ordered vault model"
```

---

### Task 6: Define the Official Field Schema and Custom Fields

**Files:**
- Create: `src/bonobo_core/passwordsafe/schema.py`
- Create: `src/bonobo_core/passwordsafe/custom_fields.py`
- Create: `tests/passwordsafe/test_schema.py`
- Create: `tests/passwordsafe/test_custom_fields.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: `RawField`, field enums, declared version, UTF-8/UUID/time/integer encodings.
- Produces: `FieldSpec`, `HEADER_SCHEMA`, `RECORD_SCHEMA`, typed decode/encode functions, `CustomField`,
  `CustomProperty`, and targeted custom-field replacement.

- [ ] **Step 1: Write failing schema-version and raw-preservation tests**

```python
def test_attachment_is_known_opaque_since_030f() -> None:
    spec = RECORD_SCHEMA[RecordFieldType.ATTACHMENT_CONTENT]
    assert spec.kind is FieldKind.OPAQUE
    assert spec.since == FormatVersion.from_uint16(0x030F)


def test_unknown_custom_property_survives_value_edit() -> None:
    encoded = b"010004Name020005Value7f0003xyz"
    parsed = parse_custom_fields(encoded)
    edited = replace_custom_value(parsed, name="Name", value=SecretBuffer.from_bytes(b"Other"))
    assert b"7f0003xyz" in encode_custom_fields(edited)
```

- [ ] **Step 2: Run and confirm missing schema modules fail**

Run: `uv run pytest tests/passwordsafe/test_schema.py tests/passwordsafe/test_custom_fields.py -v`

- [ ] **Step 3: Encode the official header and record tables**

For every field through `0x30`, record its field kind, introduction version, multiplicity, secret classification,
mandatory role, and editable/opaque status.  Validate two-byte little-endian action values, four-byte little-endian
times/integers, 16-byte RFC 4122 UUIDs, UTF-8 without BOM, and documented historical eight-hex-digit timestamps.

- [ ] **Step 4: Implement typed projection without normalization**

Decoders return typed projections paired with the original `RawField`.  Malformed optional data yields a
`PreservationWarning` and no typed value; malformed mandatory data raises `MalformedVaultError`.  Encoders create a new
payload only for an explicit edit.

- [ ] **Step 5: Implement `0x0311` custom property grammar**

Parse property ID as two lowercase hex digits and byte length as four lowercase hex digits, enforce unique nonempty
name/value properties, validate sensitivity `0`/`1`, preserve property ordering and unknown IDs, and replace only the
named value/sensitivity property bytes.  Reject a legacy export when custom fields are present.

- [ ] **Step 6: Run focused tests and commit**

Run: `uv run pytest tests/passwordsafe/test_schema.py tests/passwordsafe/test_custom_fields.py -v`

Run: `uv run ruff check src tests`

Run: `uv run mypy src tests`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/schema.py src/bonobo_core/passwordsafe/custom_fields.py \
  tests/passwordsafe/test_schema.py tests/passwordsafe/test_custom_fields.py
git commit -m "feat: add PasswordSafe field schema"
```

---

### Task 7: Authenticate and Parse Vaults into a Quarantined Document

**Files:**
- Create: `src/bonobo_core/passwordsafe/reader.py`
- Create: `tests/passwordsafe/test_reader.py`
- Create: `tests/passwordsafe/test_reader_fail_closed.py`
- Create: `tests/fixtures/synthetic/passwordsafe/reader-vectors.json`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: `EncryptedSnapshot`, `SecretBuffer`, `TwofishBackend`, schemas, `ResourceLimits`, and Task 4's independent
  `build_spec_vault()` test helper.
- Produces: `OpenedVault` containing an authenticated `VaultDocument`, `VaultCryptoState`, baseline manifest, and
  source snapshot; no object escapes on failure.

- [ ] **Step 1: Write failing successful-open and fail-closed tests**

```python
def test_open_valid_synthetic_vault(reader: PasswordSafeReader, valid_vault: Path) -> None:
    with SecretBuffer.from_bytes(FABRICATED_MASTER_INPUT) as passphrase:
        opened = reader.open(valid_vault, passphrase)
    assert opened.document.version == VERSION_0302
    assert opened.document.semantic_manifest() == EXPECTED_BASE_MANIFEST


@pytest.mark.parametrize("fixture", ["wrong-hmac", "missing-version", "version-length-one", "unsupported-major"])
def test_open_failure_exposes_no_document(reader: PasswordSafeReader, fixture: str) -> None:
    with pytest.raises(PasswordSafeError):
        reader.open(FIXTURES / f"{fixture}.psafe3", fabricated_passphrase())
    assert not reader.has_quarantined_document
```

Build the valid encrypted bytes and each structurally malformed variant in the test process with
`build_spec_vault()`; `reader-vectors.json` contains only expected versions, manifests, and mutation descriptions, not
encrypted output generated by the product reader or writer.

- [ ] **Step 2: Run and observe missing reader failures**

Run: `uv run pytest tests/passwordsafe/test_reader.py tests/passwordsafe/test_reader_fail_closed.py -v`

- [ ] **Step 3: Implement fixed-envelope authentication**

Read and validate the 152-byte prefix, require `PWS3`, reject resource-exceeding iteration counts, derive `P'`, compare
`H(P')` with `hmac.compare_digest`, unwrap K/L, require the final 48 bytes to contain exact EOF plus a 32-byte stored
HMAC, and require the encrypted region length to be a nonzero multiple of 16.

- [ ] **Step 4: Implement the field state machine**

For each decrypted field boundary, decode four-byte length plus one-byte type, compute
`padded_length = ((5 + length + 15) // 16) * 16` without allocating `length`, enforce remaining ciphertext bounds, feed
payload chunks to HMAC, and route header/record END markers.  Count records and fields before creating objects.

- [ ] **Step 5: Quarantine until HMAC and structural validation pass**

Keep all fields in a private builder.  Compare the calculated HMAC only after consuming the final record.  Then validate
Version first and exactly two bytes, supported level, mandatory END markers, and UUID/Title/Password for every record.
Close all payloads, keys, and snapshots on every failure path.

- [ ] **Step 6: Add deferred spans for large/opaque fields**

Inline payloads at or below `limits.max_inline_payload_bytes`.  Store authenticated encrypted span metadata for larger
payloads and verify one full streaming read in the open transaction before exposing the document.

- [ ] **Step 7: Run reader, compatibility-oracle, and memory tests; commit**

Run: `uv run pytest tests/passwordsafe/test_reader.py tests/passwordsafe/test_reader_fail_closed.py -v`

Run: `uv run python -m tools.check_compatibility`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/reader.py tests/passwordsafe/test_reader.py \
  tests/passwordsafe/test_reader_fail_closed.py tests/fixtures/synthetic/passwordsafe/reader-vectors.json
git commit -m "feat: authenticate and parse PasswordSafe vaults"
```

---

### Task 8: Serialize, Reopen, and Compare Encrypted Candidates

**Files:**
- Create: `src/bonobo_core/passwordsafe/writer.py`
- Create: `tests/passwordsafe/test_writer.py`
- Create: `tests/passwordsafe/test_round_trip.py`
- Create: `tests/passwordsafe/test_writer_fail_closed.py`
- Modify: `src/bonobo_core/passwordsafe/reader.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: authenticated `VaultDocument`, `VaultCryptoState`, `TwofishBackend`, `RandomSource`, and binary output.
- Produces: `PasswordSafeReader.reopen_candidate(path: Path, crypto_state: VaultCryptoState) -> OpenedVault` and
  `EncryptedCandidate` with file, SHA-256, exact semantic manifest, fresh keys/IV/padding, and verified reopen result.

- [ ] **Step 1: Write failing no-edit, one-edit, hardening, and fault tests**

```python
def test_no_edit_round_trip_preserves_order_and_unknown_bytes(opened_base: OpenedVault) -> None:
    candidate = writer.write(opened_base.document, opened_base.crypto_state)
    reopened = reader.reopen_candidate(candidate.path, opened_base.crypto_state)
    assert_exact_documents(opened_base.document, reopened.document)


def test_single_title_edit_changes_only_target(opened_base: OpenedVault) -> None:
    revised = replace_text_field(opened_base.document, RECORD_ZERO, TITLE_FIELD, "Alpha Portal Renamed")
    candidate = writer.write(revised, opened_base.crypto_state)
    assert_manifest_delta(candidate.manifest, opened_base.manifest, {(0, TITLE_FIELD)})


@dataclass(frozen=True, slots=True)
class EncryptedCandidate:
    path: Path
    sha256: str
    manifest: SemanticManifest
    reopened_manifest: SemanticManifest
```

- [ ] **Step 2: Run and observe missing writer failures**

Run: `uv run pytest tests/passwordsafe -k "writer or round_trip" -v`

- [ ] **Step 3: Implement preflight and fresh envelope creation**

Validate version/field compatibility before opening output.  Retain ordinary-save salt and approved `P'`; use prepared
hardened material when required.  Generate independent K/L, fresh IV, and padding through `SystemRandomSource`; wrap
exactly B1-B4 and emit the fixed prefix.

- [ ] **Step 4: Stream ordered field frames**

For each field, write little-endian length, type, payload chunks, and exactly enough random padding to a CBC block
boundary.  Feed only declared payload chunks to HMAC.  Never call `bytes()` on an opaque deferred payload.

- [ ] **Step 5: Finish and independently reopen the candidate**

Flush encrypted CBC output, append exact EOF and HMAC, synchronize, reopen using retained derived material, and compare
every section/type/length/payload stream exactly with the intended document.  Destroy the candidate on any mismatch.

- [ ] **Step 6: Exercise every writer fault boundary**

Inject failures after prefix, field header, field payload chunk, padding, EOF, HMAC, flush, reopen, and exact
comparison.
Assert the source snapshot hash never changes and the partial candidate is absent after handled cleanup.

- [ ] **Step 7: Run focused tests and commit**

Run: `uv run pytest tests/passwordsafe -k "writer or round_trip" -v`

Run: `uv run ruff check src tests`

Run: `uv run mypy src tests`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/reader.py src/bonobo_core/passwordsafe/writer.py \
  tests/passwordsafe/test_writer.py \
  tests/passwordsafe/test_round_trip.py tests/passwordsafe/test_writer_fail_closed.py
git commit -m "feat: serialize validated PasswordSafe candidates"
```

---

### Task 9: Implement Revision-Safe Sessions and Explicit Secret Access

**Files:**
- Create: `src/bonobo_core/passwordsafe/session.py`
- Create: `tests/passwordsafe/test_session.py`
- Create: `tests/passwordsafe/test_session_secrets.py`
- Create: `tests/passwordsafe/test_session_protection.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: `OpenedVault`, schemas, `RecordHandle`, `RevisionToken`, payload constructors, and `SecretLease`.
- Produces: `VaultSession`, `NewRecord`, `RecordView`, typed edit union, explicit add, move, delete, protect, and
  unprotect operations, dirty revisions, save snapshots, and lock/discard behavior.

- [ ] **Step 1: Write failing stale, protected, dirty-lock, and secret-lease tests**

```python
def test_stale_patch_is_rejected(session: VaultSession) -> None:
    view = session.records()[0]
    session.apply(view.handle, view.revision, (SetTextField(TITLE_FIELD, "First"),))
    with pytest.raises(StaleRevisionError):
        session.apply(view.handle, view.revision, (SetTextField(TITLE_FIELD, "Second"),))


def test_password_requires_explicit_lease(session: VaultSession) -> None:
    view = session.records()[0]
    assert "fabricated-credential" not in repr(view)
    with session.reveal(view.handle, PASSWORD_FIELD) as lease:
        assert bytes(lease.borrow()) == FABRICATED_PASSWORD
    assert lease.closed
```

- [ ] **Step 2: Run and observe missing session behavior**

Run: `uv run pytest tests/passwordsafe -k "session" -v`

- [ ] **Step 3: Define the exact edit union and immutable views**

```python
RecordEdit = SetTextField | SetSecretField | SetBytesField | SetUInt32Field | SetTimeField | RemoveField


@dataclass(frozen=True, slots=True)
class RecordView:
    handle: RecordHandle = field(repr=False)
    revision: RevisionToken = field(repr=False)
    title: str
    group: str
    username: str
    url: str
    protected: bool


@dataclass(frozen=True, slots=True)
class NewRecord:
    uuid: UUID
    title: str
    password: SecretBuffer = field(repr=False)
    username: str = ""
    group: str = ""
    url: str = ""
```

Validate each edit kind against `RECORD_SCHEMA`; mandatory fields cannot be removed, and opaque fields cannot be edited.
`VaultSession.add(new_record: NewRecord, expected_revision: RevisionToken) -> RecordView` consumes the password buffer,
creates mandatory UUID/Title/Password fields in canonical order, and advances the document revision exactly once.

- [ ] **Step 4: Implement copy-on-write revisions and dirty state**

Serialize mutations under an internal reentrant lock.  Match both handle and expected revision, replace only the named
field occurrence, increment revision, and append an immutable `Change` record.  Return fresh views after mutation.

- [ ] **Step 5: Enforce protection and lifecycle rules**

Reject edits/deletion while protected.  `unprotect()` is a separate revision.  `lock()` rejects dirty state;
`discard_and_lock()` closes the current document and key material explicitly.  `prepare_save()` returns an immutable
document revision and refuses concurrent mutation until `finish_save()` or `abort_save()`.

- [ ] **Step 6: Run focused tests and commit**

Run: `uv run pytest tests/passwordsafe -k "session" -v`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/session.py tests/passwordsafe/test_session.py \
  tests/passwordsafe/test_session_secrets.py tests/passwordsafe/test_session_protection.py
git commit -m "feat: add revision-safe vault sessions"
```

---

### Task 10: Publish Local Files Atomically with Encrypted Recovery

**Files:**
- Create: `src/bonobo_core/passwordsafe/storage.py`
- Create: `tests/passwordsafe/test_storage.py`
- Create: `tests/passwordsafe/test_storage_faults.py`
- Create: `tests/passwordsafe/test_storage_external_change.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: `EncryptedCandidate`, opening `FileBaseline`, private working/recovery directories, and candidate validator.
- Produces: `LocalVaultStore.capture()`, `publish()`, `available_recovery()`, `restore()`, `PublishedFile`, and
  `RecoveryRevision`.

- [ ] **Step 1: Write failing atomicity, recovery, external-change, permission, and symlink tests**

```python
def test_replace_failure_keeps_original(store: LocalVaultStore, source: Path, candidate: EncryptedCandidate) -> None:
    before = sha256_file(source)
    store.faults.raise_at(StorageStage.REPLACE)
    with pytest.raises(StorageError):
        store.publish(source, candidate, baseline_for(source))
    assert sha256_file(source) == before
    assert not store.pending_candidates()


def test_external_change_blocks_publication(
    store: LocalVaultStore,
    source: Path,
    candidate: EncryptedCandidate,
) -> None:
    baseline = baseline_for(source)
    source.write_bytes(OTHER_ENCRYPTED_VAULT)
    with pytest.raises(ExternalModificationError):
        store.publish(source, candidate, baseline)
```

- [ ] **Step 2: Run and observe missing store failure**

Run: `uv run pytest tests/passwordsafe -k "storage" -v`

- [ ] **Step 3: Implement baselines and exclusive private files**

Hash in 64 KiB chunks; record size, device/inode where available, Windows file ID where available, and modification
nanoseconds.  Create candidate/recovery files with exclusive flags and owner-only modes.  Resolve and validate every
private target remains inside the caller-supplied directory before writing.

- [ ] **Step 4: Implement validate-before-publish sequence**

Write and synchronize the candidate in the destination directory, validate it, acquire the platform lock, recalculate
the destination baseline, copy the previous encrypted snapshot to the recovery directory, atomically replace with
`os.replace`, synchronize the directory on POSIX, and verify the published SHA-256.

- [ ] **Step 5: Implement explicit recovery**

Store one prior revision under `sha256(vault_locator || random_nonce)` without a filename extension revealing the
source.  `available_recovery()` returns only timestamp/size/digest metadata.  `restore()` authenticates and validates
the recovery
before running the same baseline-checked publish transaction.

- [ ] **Step 6: Inject every transaction-stage fault**

Exercise create, permission, write, file sync, reopen, compare, lock, baseline recheck, recovery write/sync, replace,
directory sync, published verification, and cleanup.  Assert either the old or completely validated new vault is
authoritative and every recovery artifact remains encrypted.

- [ ] **Step 7: Run platform-focused tests and commit**

Run: `uv run pytest tests/passwordsafe -k "storage" -v`

```bash
git add REUSE.toml src/bonobo_core/passwordsafe/storage.py tests/passwordsafe/test_storage.py \
  tests/passwordsafe/test_storage_faults.py tests/passwordsafe/test_storage_external_change.py
git commit -m "feat: add transactional local vault storage"
```

---

### Task 11: Assemble the Service Facade and Public Package

**Files:**
- Create: `src/bonobo_core/passwordsafe/service.py`
- Modify: `src/bonobo_core/passwordsafe/__init__.py`
- Modify: `src/bonobo_core/__init__.py`
- Create: `tests/passwordsafe/test_service.py`
- Create: `tests/passwordsafe/test_public_api.py`
- Modify: `tests/foundation/test_package_contract.py`

**Interfaces:**
- Consumes: Botan backend, reader, writer, session, and local store.
- Produces: `VaultService.with_botan()`, `create()`, `open()`, `save()`, `change_master_passphrase()`, `export()`,
  `available_recovery()`, `restore()`, and the reviewed public exports.

- [ ] **Step 1: Write failing end-to-end service tests**

```python
def test_create_edit_save_reopen(service: VaultService, tmp_path: Path) -> None:
    path = tmp_path / "fabricated.psafe3"
    session = service.create(path, fabricated_passphrase(), database_name="Synthetic")
    record = session.add(new_fabricated_record())
    service.save(session)
    session.lock()
    reopened = service.open(path, fabricated_passphrase())
    assert reopened.records()[0].handle != record.handle
    assert reopened.records()[0].title == "Alpha Portal"
```

- [ ] **Step 2: Run and observe missing facade failures**

Run: `uv run pytest tests/passwordsafe/test_service.py tests/passwordsafe/test_public_api.py -v`

- [ ] **Step 3: Implement dependency assembly and new-vault creation**

`with_botan()` accepts explicit library, working, and recovery paths.  `create()` generates new salt, `0x0311` Version,
database UUID, header END, and no records; it requires at least `262_144` iterations and publishes only after candidate
reopen.  It returns an authenticated clean session.

- [ ] **Step 4: Implement open/save/passphrase/export/recovery orchestration**

Open captures then authenticates.  Save freezes the session revision, writes/reopens, publishes, and advances the
baseline; failures call `abort_save()`.  Passphrase change/new export require new `SecretBuffer`, salt, and derived key.
Legacy export runs schema compatibility proof before candidate creation.  Restore requires explicit caller invocation.

- [ ] **Step 5: Restrict and document public exports**

Export service/session/view/edit/result types, versions, limits, and safe exception categories.  Do not export raw field
payloads, crypto keys, deterministic randomness, native handles, or transaction fault injectors.  Set package version
to `0.1.0` only after all service tests pass.

- [ ] **Step 6: Run end-to-end and wheel-contract tests; commit**

Run: `uv run pytest tests/passwordsafe tests/foundation -k "service or public_api or package_contract" -v`

Run: `uv build`

Run: `uv run python -m tools.check_wheel dist`

```bash
git add src/bonobo_core tests/passwordsafe tests/foundation/test_package_contract.py
git commit -m "feat: expose lossless PasswordSafe service"
```

---

### Task 12: Add Property, Fuzz-Corpus, Resource, and Large-Vault Proofs

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `tests/passwordsafe/strategies.py`
- Create: `tests/passwordsafe/test_properties.py`
- Create: `tests/passwordsafe/test_resource_limits.py`
- Create: `tests/passwordsafe/test_large_vault.py`
- Create: `tests/passwordsafe/fuzz_target.py`
- Create: `tests/fixtures/synthetic/passwordsafe/fuzz-corpus/`
- Create: `tools/run_passwordsafe_fuzz.py`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`
- Modify: `tools/check_provenance.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: complete reader/writer/service APIs and Hypothesis `>=6.161,<7`.
- Produces: generated valid/malformed documents, `fuzz_one_input(data: bytes)`, deterministic seed-corpus execution,
  and peak-memory assertions.

- [ ] **Step 1: Add Hypothesis and update the lock/provenance tests**

Run: `uv add --group dev "hypothesis>=6.161,<7"`

Record Hypothesis as a direct development dependency under MPL-2.0, not distributed.  Run the provenance checker and
review the complete transitive lock delta before staging it.

- [ ] **Step 2: Write failing property and resource tests**

```python
@given(lossless_documents())
def test_generated_document_round_trip(document: VaultDocument) -> None:
    candidate = deterministic_writer().write_new(document, fabricated_passphrase())
    reopened = deterministic_reader().open(candidate.path, fabricated_passphrase())
    assert_exact_documents(document, reopened.document)


def test_declared_four_gibibyte_field_does_not_allocate() -> None:
    malicious = field_header(length=0xFFFFFFFF, type_code=0xE0) + bytes(11)
    with pytest.raises(MalformedVaultError):
        parse_decrypted_fields(malicious, ResourceLimits())
```

- [ ] **Step 3: Implement typed Hypothesis strategies**

Generate supported versions, ordered known/unknown fields, duplicate optional fields, mandatory records, custom
properties, targeted edits, and bounded binary payloads.  Use only `.example.invalid` URLs and the fixed fabricated UUID
namespace from the compatibility dossier.

- [ ] **Step 4: Implement a dependency-free fuzz target**

```python
def fuzz_one_input(data: bytes) -> None:
    snapshot = MemoryEncryptedSnapshot(data)
    try:
        fuzz_reader().open_snapshot(snapshot, fabricated_passphrase())
    except PasswordSafeError:
        return
```

The runner applies deterministic bit flips, truncations, insertions, length mutations, and corpus replay.  It exits
nonzero for crashes, hangs beyond the per-input deadline, untyped exceptions, or leaked temporary artifacts.

- [ ] **Step 5: Prove bounded memory for opaque content**

Create a sparse synthetic encrypted attachment larger than the inline threshold, measure with `tracemalloc`, and assert
peak Python memory stays below `4 * max_inline_payload_bytes + 8 * io_chunk_bytes` during open/no-edit save.  Verify no
plaintext fragment appears in the temp/recovery directories.

- [ ] **Step 6: Run generative/fuzz/resource suites and commit**

Run: `uv run pytest tests/passwordsafe -k "properties or resource_limits or large_vault" -v`

Run:

```powershell
uv run python -m tools.run_passwordsafe_fuzz `
  --corpus tests/fixtures/synthetic/passwordsafe/fuzz-corpus `
  --iterations 10000
```

```bash
git add pyproject.toml uv.lock REUSE.toml src tests/passwordsafe tools/run_passwordsafe_fuzz.py \
  tools/check_provenance.py docs/legal/dependency-asset-provenance-ledger.md
git commit -m "test: prove PasswordSafe parser resilience"
```

---

### Task 13: Establish Independent Synthetic Interoperability Fixtures

**Files:**
- Create: `tools/verify_passwordsafe_interop.py`
- Create: `tests/passwordsafe/test_interop_manifests.py`
- Create: `tests/fixtures/synthetic/passwordsafe/bonobo-0311.psafe3`
- Create: `tests/fixtures/synthetic/passwordsafe/passwordsafe-current.psafe3`
- Create: `tests/fixtures/synthetic/passwordsafe/gorilla-6728e85.psafe3`
- Create: `tests/fixtures/synthetic/passwordsafe/official-unknown-0302.psafe3`
- Create: `tests/fixtures/synthetic/passwordsafe/*.manifest.json`
- Modify: `docs/compatibility/gorilla/test-oracles.md`
- Modify: `docs/compatibility/gorilla/feature-parity-matrix.md`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`
- Modify: `tools/check_compatibility.py`
- Modify: `tools/check_provenance.py`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: current Password Safe 3.72.1, pinned Gorilla revision `6728e85c05ac25357b8f19f541487b9d26a97402`,
  Bonobo service, an independent official-format fixture authority, and fixed fabricated inputs.
- Produces: independently authored encrypted fixtures, ordered JSON manifests, and automated no-edit/single-edit
  comparisons closing GOR-TEST-003/005/028/029/043/048/051/052 evidence.

- [ ] **Step 1: Write failing manifest and provenance tests before adding vault files**

```python
def test_every_interop_fixture_has_manifest_and_authority() -> None:
    fixtures = sorted(FIXTURE_ROOT.glob("*.psafe3"))
    assert {path.stem for path in fixtures} == {
        "bonobo-0311", "passwordsafe-current", "gorilla-6728e85", "official-unknown-0302"
    }
    for fixture in fixtures:
        manifest = load_manifest(fixture.with_suffix(".manifest.json"))
        assert manifest.authority in {
            "Bonobo", "Password Safe 3.72.1", "Gorilla 6728e85", "Independent PasswordSafe V3 fixture authority"
        }
        assert manifest.encrypted_sha256 == sha256_file(fixture)
```

- [ ] **Step 2: Run and confirm absent fixtures fail**

Run: `uv run pytest tests/passwordsafe/test_interop_manifests.py -v`

- [ ] **Step 3: Implement safe manifest extraction/comparison**

The tool accepts the vault path and reads the fabricated passphrase from standard input, emits section/record/field
ordinal, type, length, and payload SHA-256, and redacts typed values.  `compare` permits only the explicitly named
target
field delta and writer-owned envelope changes.

- [ ] **Step 4: Produce each fixture independently**

Create Bonobo `0x0311`, Password Safe current, and Gorilla's actual `0x0300` output vaults with database UUID
`11111111-1111-4111-8111-111111111111`, record UUID
`22222222-2222-4222-8222-222222222222`, `.example.invalid` URL data, and standard fields accepted by each client.
The pinned Gorilla writer downgrades its saved output to `0x0300`, so its independent seed must contain only fields
legal at that level; record the downgrade instead of weakening Bonobo's unsupported-content handling.
Independently construct `official-unknown-0302.psafe3` from the published V3 format description with the dossier's
fabricated unknown `0xE0/0xE1` bytes; do not call Bonobo product reader/writer code.  Record exact client or independent
authority, version, OS/tooling, encrypted SHA-256, and ordered redacted manifest.

- [ ] **Step 5: Execute cross-client no-edit and one-edit transactions**

Operate only disposable copies.  Confirm current Password Safe and pinned Gorilla open the Bonobo vault where their
declared level permits; confirm Bonobo opens all three externally authored fixtures; perform no-edit and title-only
saves; compare
manifests; remove client-created backups after recording their hashes.

- [ ] **Step 6: Update compatibility/provenance gates and commit**

Run: `uv run pytest tests/passwordsafe/test_interop_manifests.py -v`

Run: `uv run python -m tools.check_compatibility`

Run: `uv run python -m tools.check_provenance`

Run: `git ls-files -z | uv run python -m tools.check_tracked_files`

```bash
git add REUSE.toml tools/verify_passwordsafe_interop.py tools/check_compatibility.py tools/check_provenance.py \
  tests/passwordsafe/test_interop_manifests.py tests/fixtures/synthetic/passwordsafe \
  docs/compatibility/gorilla docs/legal/dependency-asset-provenance-ledger.md
git commit -m "test: qualify PasswordSafe interoperability"
```

---

### Task 14: Add Desktop Integration and Mobile Cross-Build CI Gates

**Files:**
- Modify: `.github/workflows/foundation.yml`
- Modify: `tools/build_botan.py`
- Modify: `tests/foundation/test_botan_build.py`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`
- Modify: `docs/PROJECT_MEMORY.md`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: Task 1 build driver and complete core integration suite.
- Produces: host Botan builds/tests on Windows/macOS/Linux plus Android arm64 and iOS arm64 compile/link smoke gates.

- [ ] **Step 1: Write failing target-command tests**

```python
@pytest.mark.parametrize("target", ["windows-x86_64", "macos-arm64", "linux-x86_64", "android-arm64", "ios-arm64"])
def test_build_target_enables_only_approved_modules(target: str) -> None:
    command = configure_command(target, SOURCE, OUTPUT)
    assert "--minimized-build" in command
    assert "--enable-modules=ffi,twofish" in command
    assert not any("tls" in argument for argument in command)
```

- [ ] **Step 2: Run and observe mobile target failures**

Run: `uv run pytest tests/foundation/test_botan_build.py -v`

- [ ] **Step 3: Complete Android/iOS toolchain discovery**

Android requires `ANDROID_NDK_ROOT`, resolves `aarch64-linux-android28-clang++`, and configures API 28.  iOS runs only
on macOS, resolves `xcrun --sdk iphoneos --find clang++` and SDK path, and supplies arm64 sysroot flags.  Missing tools
raise
a typed build error before extraction or compilation.

- [ ] **Step 4: Extend CI with native integration and cross-build jobs**

```yaml
- id: botan
  shell: pwsh
  run: uv run python -m tools.build_botan --target host --output build/botan --github-output $env:GITHUB_OUTPUT
- run: uv run pytest tests/passwordsafe -v
  env:
    BONOBO_TEST_BOTAN_LIBRARY: ${{ steps.botan.outputs.library }}
```

Add an Ubuntu Android job using the runner's pinned NDK path and a macOS iOS job using the installed Xcode.  Each builds
Botan and links a C smoke program that initializes `Twofish`, sets a 256-bit key, encrypts one block, and destroys the
handle.  `--github-output` writes the resolved absolute shared-library path as `library=<path>` using GitHub's output
protocol; tests never guess a platform-specific filename or build subdirectory.

- [ ] **Step 5: Run local workflow-equivalent gates and commit**

Run: `uv run pytest tests/foundation/test_botan_build.py tests/passwordsafe -v`

Run: `uv run python -m tools.check_provenance`

```bash
git add .github/workflows/foundation.yml REUSE.toml tools/build_botan.py tests/foundation/test_botan_build.py \
  docs/legal/dependency-asset-provenance-ledger.md docs/PROJECT_MEMORY.md
git commit -m "ci: qualify PasswordSafe core platforms"
```

---

### Task 15: Document Operation, Update Durable Memory, and Run Release Gates

**Files:**
- Create: `docs/guides/lossless-passwordsafe-core.md`
- Create: `examples/passwordsafe_core_demo.py`
- Create: `tests/passwordsafe/test_example.py`
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `docs/PROJECT_MEMORY.md`
- Modify: `docs/legal/dependency-asset-provenance-ledger.md`
- Modify: `REUSE.toml`

**Interfaces:**
- Consumes: complete public `VaultService` and all verification evidence.
- Produces: safe runnable example, installation/build/open/save instructions, current project state, and release-quality
  evidence.

- [ ] **Step 1: Write a failing subprocess test for the safe example**

```python
def test_demo_creates_and_reopens_only_synthetic_vault(tmp_path: Path, botan_library: Path) -> None:
    result = subprocess.run(
        [sys.executable, "examples/passwordsafe_core_demo.py", "--directory", str(tmp_path),
         "--botan-library", str(botan_library)],
        input="fabricated-master-input-one\nfabricated-master-input-one\n",
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "created, saved, reopened, and locked synthetic vault" in result.stdout
    assert "fabricated-credential" not in result.stdout + result.stderr
```

- [ ] **Step 2: Run and observe the absent example failure**

Run: `uv run pytest tests/passwordsafe/test_example.py -v`

- [ ] **Step 3: Implement the synthetic demonstration**

The example accepts only an output directory and Botan library path, refuses a preexisting destination, uses fixed
fabricated credentials and a prompted/repeated fabricated master input, creates one record, saves, locks, reopens,
checks only title/count, locks, and prints the safe completion line from the test.

- [ ] **Step 4: Write operator and developer documentation**

Document exact `uv sync --locked --all-groups`, Botan build, environment, test, and example commands for PowerShell and
POSIX shells.  Explain `0x0311` creation, version preservation, opaque attachments/passkeys, recovery location policy,
external-change failures, CPython zeroization limits, and that the core has no production UI yet.

- [ ] **Step 5: Update project memory and status truthfully**

Record the implementing branch/commit range, delivered APIs, Botan pin, verified platforms, interoperability clients,
test counts, coverage, residual risks, and the next approved subproject in `docs/PROJECT_MEMORY.md`.

- [ ] **Step 6: Review canonical Markdown documentation**

Review the new guide and changed memory/legal/compatibility Markdown directly.  Correct broken links, stale paths,
formatting defects, and inaccurate status.  Do not create TeX or PDF derivatives unless the user explicitly requests
them by document.

- [ ] **Step 7: Run the complete release gate**

Run each command separately and stop on the first failure:

```bash
uv run autopep8 --in-place --recursive src tests tools examples
git diff --exit-code -- src tests tools examples
uv run ruff check src tests tools examples
uv run mypy src tests tools examples
uv run python -m pytest
uv run python -m tools.check_python_structure src tests tools examples
uv run python -m tools.check_compatibility
uv run python -m tools.check_provenance
git ls-files -z | uv run python -m tools.check_tracked_files
uv run bandit -c pyproject.toml -r src tools examples
uv run pip-audit
uv run reuse --no-multiprocessing lint
uv build
uv run python -m tools.check_wheel dist
```

- [ ] **Step 8: Review the final diff and commit documentation/delivery evidence**

Confirm no `.psafe3` exists outside the synthetic allowlist, no PDF is tracked, no Gorilla source path is present, and
no test is skipped.  Review `git diff --check`, `git status --short`, and the complete branch diff against the approved
spec.

```bash
git add README.md CONTRIBUTING.md REUSE.toml examples docs src tests tools pyproject.toml uv.lock \
  .github/workflows/foundation.yml .gitignore
git commit -m "docs: deliver lossless PasswordSafe core"
```

---

## Final Spec-Coverage Checklist

- Tasks 2, 5, 6, 7, and 8 implement ordered lossless parsing, validation, preservation, and serialization.
- Tasks 1, 3, and 4 implement the approved Botan-only cryptographic boundary and PasswordSafe construction.
- Task 9 implements revision-safe application behavior, protected records, explicit secret leases, and lifecycle rules.
- Tasks 8 and 10 implement complete candidate validation, atomic publication, external-change detection, and encrypted
  recovery.
- Task 11 exposes creation/open/save/passphrase/export/restore through the typed Python core.
- Task 12 supplies property, fuzz, resource-exhaustion, and bounded-memory evidence.
- Task 13 supplies independent Password Safe/Gorilla interoperability and dossier evidence.
- Task 14 supplies Windows/macOS/Linux integration plus Android/iOS cross-build evidence.
- Task 15 supplies operation documentation, project memory, complete repository gates, and final delivery review.
