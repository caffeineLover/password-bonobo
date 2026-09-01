# Dependency and Asset Provenance Ledger

## Scope and review keys

This ledger records the repository's current direct and transitive Python packages, isolated build dependency, native
runtime dependencies, GitHub Actions, documentation tools, and tracked repository assets.  It records observed facts
without treating package metadata as a completed legal review.  The project declares no runtime Python dependencies,
and none of the development or build packages below is bundled in the wheel.

Compact keys keep this source reviewable within the 120-character line limit:

- Relationship: `DB` direct build, `DD` direct development, `DNR` direct native runtime, `DR` direct runtime, and
  `T` transitive.
- Constraint: `N` means not directly declared.  Other values reproduce the declaration in `pyproject.toml`.
- Use: `BT` repository build/test/security tool, `TS` transitive tool support, `CI` hosted workflow, `DG` document
  generation or review, `LT` license text, `FX` structural test fixture, and `TM` typing marker.
- Distribution: `N` not distributed with the package, `S` source repository or source distribution, and `W` wheel;
  `A` platform application artifact, and `+` joins every applicable distribution location.
- Evidence: `P` `pyproject.toml` or a machine-readable source pin, `L` `uv.lock`, `M` installed Core Metadata, `V`
  local version output, `R` tracked REUSE metadata or source, and `W` tracked workflow plus official Git-ref evidence.
- Review: `V` verified repository-owned fact, `MP` metadata expression recorded with compatibility review pending,
  and `P` license or terms review pending.  `NOASSERTION` means the available evidence does not establish the fact.

## Python packages

The lock contains 56 resolved third-party packages.  Hatchling is declared for isolated builds but is not resolved in
`uv.lock`; its exact build version and artifact origin therefore remain `NOASSERTION` pending a build-lock decision.

|Name|Rel|Constraint|Version|Origin|Terms|Use|Dist|Evidence|Review|
|---|---|---|---|---|---|---|---|---|---|
|attrs|T|N|26.1.0|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|autopep8|DD|autopep8>=2.3,<3|2.3.2|https://pypi.org/simple|NOASSERTION|BT|N|L|P|
|bandit|DD|bandit[toml]>=1.8,<2|1.9.4|https://pypi.org/simple|NOASSERTION|BT|N|L|P|
|boolean-py|T|N|5.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|build|DD|build>=1.3,<2|1.5.0|https://pypi.org/simple|MIT|BT|N|L+M|MP|
|cachecontrol|T|N|0.14.4|https://pypi.org/simple|Apache-2.0|TS|N|L+M|MP|
|certifi|T|N|2026.7.22|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|charset-normalizer|T|N|3.5.1|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|click|T|N|8.4.2|https://pypi.org/simple|BSD-3-Clause|TS|N|L+M|MP|
|colorama|T|N|0.4.6|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|coverage|T|N|7.15.4|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|cyclonedx-python-lib|T|N|11.12.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|defusedxml|T|N|0.7.1|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|filelock|T|N|3.32.3|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|hatchling|DB|hatchling>=1.27,<2|`NOASSERTION`|`NOASSERTION`|`NOASSERTION`|BT|N|P|P|
|hypothesis|DD|hypothesis>=6.161,<7|6.167.1|https://pypi.org/simple|MPL-2.0|BT|N|L+M|MP|
|idna|T|N|3.19|https://pypi.org/simple|BSD-3-Clause|TS|N|L+M|MP|
|iniconfig|T|N|2.3.0|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|jinja2|T|N|3.1.6|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|librt|T|N|0.15.0|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|license-expression|T|N|30.4.4|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|markdown-it-py|T|N|4.2.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|markupsafe|T|N|3.0.3|https://pypi.org/simple|BSD-3-Clause|TS|N|L+M|MP|
|mdurl|T|N|0.1.2|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|msgpack|T|N|1.2.1|https://pypi.org/simple|Apache-2.0|TS|N|L+M|MP|
|mypy|DD|mypy>=1.18,<2|1.20.2|https://pypi.org/simple|MIT|BT|N|L+M|MP|
|mypy-extensions|T|N|1.1.0|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|packageurl-python|T|N|0.17.6|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|packaging|T|N|26.3|https://pypi.org/simple|Apache-2.0 OR BSD-2-Clause|TS|N|L+M|MP|
|pathspec|T|N|1.1.1|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|pip|T|N|26.2.1|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|pip-api|T|N|0.0.34|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|pip-audit|DD|pip-audit>=2.9,<3|2.10.1|https://pypi.org/simple|NOASSERTION|BT|N|L|P|
|pip-requirements-parser|T|N|32.0.1|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|platformdirs|T|N|4.11.3|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|pluggy|T|N|1.6.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|py-serializable|T|N|2.1.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|pycodestyle|T|N|2.14.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|pygments|T|N|2.21.0|https://pypi.org/simple|BSD-2-Clause|TS|N|L+M|MP|
|pyparsing|T|N|3.3.2|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|pyproject-hooks|T|N|1.2.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|pytest|DD|pytest>=9.0.3,<10|9.1.1|https://pypi.org/simple|MIT|BT|N|L+M|MP|
|pytest-cov|DD|pytest-cov>=7,<8|7.1.0|https://pypi.org/simple|MIT|BT|N|L+M|MP|
|python-debian|T|N|1.1.1|https://pypi.org/simple|GPL-2.0-or-later|TS|N|L+M|MP|
|python-magic|T|N|0.4.27|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|pyyaml|T|N|6.0.3|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|requests|T|N|2.34.2|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|reuse|DD|reuse>=6.2,<7|6.2.0|https://pypi.org/simple|NOASSERTION|BT|N|L|P|
|rich|T|N|15.0.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|ruff|DD|ruff>=0.12,<1|0.16.4|https://pypi.org/simple|MIT|BT|N|L+M|MP|
|sortedcontainers|T|N|2.4.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|stevedore|T|N|5.9.1|https://pypi.org/simple|Apache-2.0|TS|N|L+M|MP|
|tomli|T|N|2.4.1|https://pypi.org/simple|MIT|TS|N|L+M|MP|
|tomli-w|T|N|1.2.0|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|tomlkit|T|N|0.15.1|https://pypi.org/simple|NOASSERTION|TS|N|L|P|
|typing-extensions|T|N|4.16.0|https://pypi.org/simple|PSF-2.0|TS|N|L+M|MP|
|urllib3|T|N|2.7.0|https://pypi.org/simple|MIT|TS|N|L+M|MP|

## GitHub Actions

Both action revisions were verified against official Git refs on 2026-08-22.  License terms remain pending an
independent distribution review; the actions execute in hosted CI and are not copied into Bonobo distributions.

|Action|Version|Revision|Origin|Terms|Use|Dist|Evidence|Review|
|---|---|---|---|---|---|---|---|---|
|`actions/checkout`|v4.4.0|`11d5960a326750d5838078e36cf38b85af677262`|GitHub|`NOASSERTION`|CI|N|W|P|
|`astral-sh/setup-uv`|v6.8.0|`d0cc045d04ccac9d8b7881df0226f9e82c39688e`|GitHub|`NOASSERTION`|CI|N|W|P|

## Documentation tools

Versions are local observations from 2026-08-22, not repository pins.  The tools generate ignored review artifacts;
they are not copied into the Python wheel or source distribution.  License and platform-package terms remain pending.

|Tool|Version|Origin|Terms|Use|Dist|Evidence|Review|
|---|---|---|---|---|---|---|---|
|pandoc|3.10.2|https://pandoc.org|NOASSERTION|DG|N|V|P|
|xelatex|MiKTeX-XeTeX 4.16|https://miktex.org|NOASSERTION|DG|N|V|P|
|pdfinfo|Poppler 24.04.0|https://poppler.freedesktop.org|NOASSERTION|DG|N|V|P|
|pdftoppm|Poppler 24.04.0|https://poppler.freedesktop.org|NOASSERTION|DG|N|V|P|

## Native dependencies

Botan is the direct native runtime dependency that provides the sole production Twofish implementation.  Its pinned
source archive at `https://botan.randombit.net/releases/Botan-3.13.0.tar.xz` is SHA-256 verified before extraction.
The provenance gate requires this row to match the version, archive filename, digest, and minimized modules in
`tools/botan-source.json`.  Release application artifacts bundle an appropriate shared library; the pure Python wheel
does not.  CI builds minimized `ffi,twofish` profiles for Windows x86-64, macOS arm64, and Linux x86-64 and executes
the core suite against each resulting host shared library.  Android arm64 API 28 and iOS arm64 gates instead build a
static library and compile/link a raw Twofish FFI probe with the platform toolchain.  Those mobile gates establish only
compile/link compatibility; they do not qualify runtime behavior, physical devices, packaging, or distribution terms.

|Name|Fact|Value|Terms|Dist|Evidence|Review|
|---|---|---|---|---|---|---|
|Botan|Relationship|DNR|BSD-2-Clause|A|P+R|P|
|Botan|Version|3.13.0|BSD-2-Clause|A|P+R|P|
|Botan|Source|https://botan.randombit.net/releases/Botan-3.13.0.tar.xz|BSD-2-Clause|A|P+R|P|
|Botan|Archive|Botan-3.13.0.tar.xz|BSD-2-Clause|A|P+R|P|
|Botan|SHA-256|12f5a835 8890bbee 82edfe9d 2e7769b0 a610b6dd 0e0698ae a13d20a6 75d84620|BSD-2-Clause|A|P+R|P|
|Botan|Modules|ffi,twofish|BSD-2-Clause|A|P+R|P|

## Interoperability producer tools

These tools were used only to produce or independently exercise fixed synthetic interoperability evidence. They are
not tracked in the repository or copied into Bonobo distributions. Artifact identities were measured locally before
use. Password Safe's bundled `LICENSE` identifies Artistic License 2.0 terms, and the pinned Gorilla checkout states
GPL version 2 or later. The downloaded Tclkit executable did not establish its aggregate terms, so that terms review
remains explicitly pending.

|Name|Version|Artifact|Identity|Origin|Terms|Use|Dist|Evidence|Review|
|---|---|---|---|---|---|---|---|---|---|
|Password Safe|3.72.1|pwsafe64-3.72.1-bin.zip|2fe5c8e170ffc0c946d8d19b7b09680e965b15b5a8cfbb70d62d4faea1b74f9d|https://github.com/pwsafe/pwsafe/releases/download/3.72.1/pwsafe64-3.72.1-bin.zip|Artistic-2.0|BT|N|V|V|
|Tclkit|8.6.9|tclkit-8.6.9-win64-x86_64.exe|4008f8938ba60edaf9c7c72b1bd5330b4c60c3f4b10d9cd1ef25da0ac06333f1|https://gorilla.dp100.com/downloads/tclkit/tclkit-8.6.9-win64-x86_64.exe|NOASSERTION|BT|N|V|P|
|Gorilla|6728e85|read-only source checkout|6728e85c05ac25357b8f19f541487b9d26a97402|https://github.com/zdia/gorilla.git|GPL-2.0-or-later|BT|N|V|V|

## Repository assets

The checker derives this inventory from tracked paths below `LICENSES/`, `docs/pandoc/`, and `tests/fixtures/`, plus
every tracked `py.typed` marker. No third-party UI asset, font, image, translation, or implementation source from
Gorilla or Password Safe is tracked.

The PasswordSafe cryptographic vector contains only fabricated inputs.  Its expected SHA-256 output was independently
derived from the public PasswordSafe construction without product code and is used for deterministic cryptographic
conformance testing.

The PasswordSafe reader vector contains only fabricated expected metadata, redacted semantic-manifest hashes, and
mutation descriptions.  It contains no encrypted product output and is checked against vaults constructed at test time
by the independent specification helper.

The interoperability fixtures contain only fixed fabricated data. Bonobo produced one fixture through its service;
Password Safe 3.72.1 and pinned Gorilla produced one encrypted output each from Bonobo-authored synthetic seeds; the
fourth was constructed independently from the published V3 format. Their paired manifests contain producer facts,
encrypted hashes, field lengths, and payload hashes but no passphrase or typed field value. The client-produced vaults
are outputs of the fabricated test transaction, not copied client implementation expression.

The interoperability transaction record contains only client/tool versions, distribution and encrypted artifact
hashes, exact-comparison results, and the observation that neither external run left a backup artifact. It contains no
vault path, passphrase, decrypted field value, client binary, or third-party implementation material.

The four PasswordSafe fuzz-corpus seeds are Bonobo-authored hexadecimal encodings of empty, tag-only, hostile declared
length, and fabricated XOR-backend V3 inputs.  They contain no user data or third-party client output and are replayed
and deterministically mutated only by the parser-resilience runner.

|Path|Version|Origin|Terms|Use|Dist|Evidence|Review|
|---|---|---|---|---|---|---|---|
|`LICENSES/GPL-3.0-or-later.txt`|GPL-3.0-or-later|REUSE download|GPL-3.0-or-later|LT|S+W|R|V|
|`docs/pandoc/pdf-header.tex`|Current revision|Bonobo|GPL-3.0-or-later|DG|S|R|V|
|`docs/pandoc/pdf-layout.lua`|Current revision|Bonobo|GPL-3.0-or-later|DG|S|R|V|
|`src/bonobo_core/py.typed`|Current revision|Bonobo|GPL-3.0-or-later|TM|S+W|R|V|
|`tests/fixtures/python_structure/documented.py.txt`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/python_structure/undocumented.py.txt`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/bonobo-0311.manifest.json`|0.1.0 / 0x0311|Bonobo VaultService|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/bonobo-0311.psafe3`|0.1.0 / 0x0311|Bonobo VaultService|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/crypto-vectors.json`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/fuzz-corpus/declared-length.hex`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/fuzz-corpus/empty.hex`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/fuzz-corpus/tag-only.hex`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/fuzz-corpus/valid-xor-v3.hex`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/gorilla-6728e85.manifest.json`|6728e85 / 0x0300|Bonobo synthetic output via Gorilla 6728e85|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/gorilla-6728e85.psafe3`|6728e85 / 0x0300|Bonobo synthetic output via Gorilla 6728e85|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/interop-transactions.json`|2026-09-01|Bonobo cross-client synthetic transactions|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/official-unknown-0302.manifest.json`|formatV3.txt / 0x0302|Bonobo independent PasswordSafe V3 constructor|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/official-unknown-0302.psafe3`|formatV3.txt / 0x0302|Bonobo independent PasswordSafe V3 constructor|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/passwordsafe-current.manifest.json`|3.72.1 / 0x0311|Bonobo synthetic output via Password Safe 3.72.1|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/passwordsafe-current.psafe3`|3.72.1 / 0x0311|Bonobo synthetic output via Password Safe 3.72.1|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/synthetic/passwordsafe/reader-vectors.json`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|

## Distribution conclusions and review status

The wheel declares no runtime Python dependency.  Both wheel and source distribution must carry the GPL text and typing
marker; wheel metadata must also declare the exact GPL text as PEP 639 license content.  Development, build, CI, and
document tools do not enter either artifact.  Botan is bundled only with applicable platform application artifacts, not
the pure Python wheel.  Source-distribution presence does not establish mobile or App Store eligibility.  Every `P` or
`MP` row remains pending for the iOS distribution decision; no row grants an exception, contributor permission, or
permission to copy third-party expression. The runnable core demonstration is Bonobo-authored source, contains only
fixed fabricated values, and does not add a dependency or third-party asset.

Run `uv run python -m tools.check_provenance` after dependency declarations, `uv.lock`, workflow action references,
document-tool commands, or tracked assets change.  The command fails on missing, extra, or stale coverage.
