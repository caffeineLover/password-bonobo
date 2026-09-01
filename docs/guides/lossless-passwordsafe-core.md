# Lossless PasswordSafe Core Operations

Password Bonobo 0.1.0 provides a typed, local-file-first PasswordSafe V3 core. It can create, authenticate, inspect,
edit, save, rotate, export, and recover vaults through Python APIs. It does not yet provide a production desktop or
mobile user interface. Use only fabricated data with the demonstration below.

## Install the locked development environment

From the repository root, install CPython 3.14 and synchronize every locked group.

PowerShell:

```powershell
uv python install 3.14
uv sync --locked --all-groups
```

POSIX shell:

```sh
uv python install 3.14
uv sync --locked --all-groups
```

## Build and select the pinned Botan library

The build driver downloads Botan 3.13.0 from the pinned HTTPS source, verifies its SHA-256 digest, safely extracts it,
and builds only `ffi,twofish`. It never downloads a library at application runtime. The output protocol avoids guessing
platform filenames or build subdirectories.

PowerShell:

```powershell
$botanOutput = Join-Path $PWD "build/botan-output.txt"
uv run python -m tools.build_botan --target host --output build/botan --github-output $botanOutput
$env:BONOBO_TEST_BOTAN_LIBRARY = (Get-Content $botanOutput | Select-Object -Last 1).Substring(8)
```

POSIX shell:

```sh
botan_output="$(mktemp)"
uv run python -m tools.build_botan --target host --output build/botan --github-output "$botan_output"
export BONOBO_TEST_BOTAN_LIBRARY="$(sed -n 's/^library=//p' "$botan_output" | tail -n 1)"
rm -f "$botan_output"
```

The supported host profiles are Windows x86-64, macOS arm64, and Linux x86-64. CI also compiles and links static Botan
and a raw Twofish FFI probe for Android arm64 at API 28 and iOS arm64. Those mobile jobs are compile/link evidence only;
they do not establish runtime, physical-device, packaging, or distribution qualification.

## Run the safe demonstration

Choose a new or existing output directory that contains none of `synthetic-demo.psafe3`, `.bonobo-working`, or
`.bonobo-recovery`. The script prompts twice without echo on a supported interactive terminal, creates one fixed
fabricated record, saves it, locks it, reopens it, checks only its title and count, locks again, and prints a redacted
completion line. It fails closed when hidden terminal input is unavailable and refuses to replace or reuse any of its
fixed paths.

PowerShell:

```powershell
uv run python examples/passwordsafe_core_demo.py --directory build/demo --botan-library $env:BONOBO_TEST_BOTAN_LIBRARY
```

POSIX shell:

```sh
uv run python examples/passwordsafe_core_demo.py --directory build/demo --botan-library "$BONOBO_TEST_BOTAN_LIBRARY"
```

The demonstration leaves the encrypted vault in the selected directory, uses `.bonobo-working` for private temporary
operations, and retains the prior encrypted revision under `.bonobo-recovery` after a save. Delete those fabricated
demonstration artifacts when finished. Never point the example at a directory containing real credentials.

## Run verification

With `BONOBO_TEST_BOTAN_LIBRARY` set to the resolved host library:

PowerShell:

```powershell
uv run python -m pytest
uv run python -m tools.check_compatibility
uv run python -m tools.check_provenance
```

POSIX shell:

```sh
uv run python -m pytest
uv run python -m tools.check_compatibility
uv run python -m tools.check_provenance
```

The full repository release sequence is maintained in the [README development section](../../README.md#development).

## Format and preservation behavior

New vaults are written at PasswordSafe V3 level `0x0311`. Ordinary saves preserve the authenticated source version
from `0x0300` through `0x0311`; they do not silently upgrade it. A separately requested export may target another
supported version only after preflight proves that every field is representable.

Unknown fields, duplicate fields, ordering, custom properties, and recognized attachment fields `0x25`–`0x29` and
passkey fields `0x2A`–`0x2F` are preserved losslessly. Attachment and passkey payloads remain opaque: this core does not
offer typed editing for them. Large opaque payloads stream from authenticated encrypted snapshots without a plaintext
temporary file.

## Publication, recovery, and concurrent changes

Applications construct `VaultService` with explicit private working and recovery directories. A successful save keeps
one prior, validated encrypted revision in the recovery directory. Recovery discovery returns path-free metadata, and
restoration is explicit, passphrase-authenticated, and bound to the destination vault. Recovery storage is not a backup
service; operators must choose a private local location with an appropriate retention and backup policy.

The service captures the destination identity and digest when opening. If another process or synchronization provider
changes, replaces, or retargets the destination before publication, save fails with `ExternalModificationError` and
does not silently overwrite the external version. The caller must preserve the unsaved session, resolve the conflict,
and retry through an explicit workflow.

## Secret-memory boundary

Secrets enter public operations through `SecretBuffer`, are consumed by ownership transfer, and are exposed only by
explicit bounded leases. Mutable owned buffers, native handles, and temporary block buffers are wiped or closed on the
reviewed paths. CPython, operating systems, native libraries, immutable strings, copies made before ownership transfer,
swap, crash dumps, and hardware remain outside a proof of complete zeroization. The demonstration necessarily receives
an immutable Python string from the terminal before transferring encoded mutable storage; do not treat it as a
hardened credential-entry UI.

## Current boundaries

- There is no production UI, platform credential provider, autofill integration, or synchronization service.
- External contributions remain closed while contributor terms and the potential iOS distribution exception are
  unresolved.
- The checked-in interoperability fixtures contain only fabricated data and are qualified against Password Safe 3.72.1,
  Password Gorilla `6728e85`, and an independent official-format constructor.
- Mobile compile/link gates do not authorize App Store distribution or claim physical-device behavior.
