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

The lock contains 55 resolved third-party packages.  Hatchling is declared for isolated builds but is not resolved in
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
does not.

|Name|Fact|Value|Terms|Dist|Evidence|Review|
|---|---|---|---|---|---|---|
|Botan|Relationship|DNR|BSD-2-Clause|A|P+R|P|
|Botan|Version|3.13.0|BSD-2-Clause|A|P+R|P|
|Botan|Source|https://botan.randombit.net/releases/Botan-3.13.0.tar.xz|BSD-2-Clause|A|P+R|P|
|Botan|Archive|Botan-3.13.0.tar.xz|BSD-2-Clause|A|P+R|P|
|Botan|SHA-256|12f5a835 8890bbee 82edfe9d 2e7769b0 a610b6dd 0e0698ae a13d20a6 75d84620|BSD-2-Clause|A|P+R|P|
|Botan|Modules|ffi,twofish|BSD-2-Clause|A|P+R|P|

## Repository assets

The checker derives this inventory from tracked paths below `LICENSES/`, `docs/pandoc/`, and `tests/fixtures/`, plus
every tracked `py.typed` marker.  No third-party UI asset, font, image, translation, or Gorilla asset is tracked.

|Path|Version|Origin|Terms|Use|Dist|Evidence|Review|
|---|---|---|---|---|---|---|---|
|`LICENSES/GPL-3.0-or-later.txt`|GPL-3.0-or-later|REUSE download|GPL-3.0-or-later|LT|S+W|R|V|
|`docs/pandoc/pdf-header.tex`|Current revision|Bonobo|GPL-3.0-or-later|DG|S|R|V|
|`docs/pandoc/pdf-layout.lua`|Current revision|Bonobo|GPL-3.0-or-later|DG|S|R|V|
|`src/bonobo_core/py.typed`|Current revision|Bonobo|GPL-3.0-or-later|TM|S+W|R|V|
|`tests/fixtures/python_structure/documented.py.txt`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|
|`tests/fixtures/python_structure/undocumented.py.txt`|Current revision|Bonobo|GPL-3.0-or-later|FX|S|R|V|

## Distribution conclusions and review status

The wheel declares no runtime Python dependency.  Both wheel and source distribution must carry the GPL text and typing
marker; wheel metadata must also declare the exact GPL text as PEP 639 license content.  Development, build, CI, and
document tools do not enter either artifact.  Botan is bundled only with applicable platform application artifacts, not
the pure Python wheel.  Source-distribution presence does not establish mobile or App Store eligibility.  Every `P` or
`MP` row remains pending for the iOS distribution decision; no row grants an exception, contributor permission, or
permission to copy third-party expression.

Run `uv run python -m tools.check_provenance` after dependency declarations, `uv.lock`, workflow action references,
document-tool commands, or tracked assets change.  The command fails on missing, extra, or stale coverage.
