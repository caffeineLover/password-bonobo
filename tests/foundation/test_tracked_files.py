"""Verify that generated, upstream, and credential-bearing files cannot be tracked."""

import os
import subprocess
import sys
from pathlib import Path

from tools.check_tracked_files import find_forbidden



REPOSITORY_ROOT = Path(__file__).parents[2]



#### Reject every prohibited tracked-file category.
####
def test_forbidden_categories_are_reported() -> None:
    paths = (
        Path("docs/prompts/AGENTS.md"),
        Path("docs/specs/generated.pdf"),
        Path("tmp/pdfs/page-1.png"),
        Path("research/gorilla/sources/gorilla.tcl"),
        Path("customer.psafe3"),
        Path("logs/bonobo.log"),
    )

    assert tuple(item.path for item in find_forbidden(paths)) == paths



#### Permit Bonobo sources and explicitly synthetic fixtures.
####
def test_safe_paths_are_allowed() -> None:
    paths = (
        Path("src/bonobo_core/__init__.py"),
        Path("docs/compatibility/gorilla/behavior-dossier.md"),
        Path("tests/fixtures/synthetic/minimal.psafe3"),
    )

    assert find_forbidden(paths) == ()



#### Report each vault-like and private-key filename with its specific safe reason.
####
def test_vault_and_private_key_categories_are_reported_with_reasons() -> None:
    paths = (
        Path("vault.psafe"),
        Path("vault.psafe3"),
        Path("vault.dat"),
        Path(".env"),
        Path("service.key"),
        Path("service.pem"),
        Path("id_rsa"),
        Path("id_ed25519"),
    )

    violations = find_forbidden(paths)

    assert tuple(item.path for item in violations) == paths
    assert tuple(item.reason for item in violations) == (
        "vault-like file is outside the synthetic fixture allowlist",
        "vault-like file is outside the synthetic fixture allowlist",
        "vault-like file is outside the synthetic fixture allowlist",
        "secret-bearing filename is prohibited",
        "secret-bearing filename is prohibited",
        "secret-bearing filename is prohibited",
        "private-key filename is prohibited",
        "private-key filename is prohibited",
    )



#### Normalize lexical paths without crossing directory-component boundaries.
####
def test_lexical_normalization_rejects_bypasses_and_preserves_safe_boundaries() -> None:
    paths = (
        Path(".logs/notes.md"),
        Path("docs/compatibility/gorilla/behavior-dossier.md"),
        Path("tests/fixtures/synthetic/minimal.psafe3"),
        Path("tests/fixtures/synthetic/../customer.psafe3"),
        Path("docs/compatibility/gorilla/../../gorilla/upstream.tcl"),
        Path("../outside.psafe3"),
        Path(r"docs\prompts\AGENTS.md"),
        Path("sources/Gorilla/upstream.tcl"),
    )

    violations = find_forbidden(paths)

    assert tuple(item.path for item in violations) == (paths[3], paths[4], paths[5], paths[6], paths[7])
    assert tuple(item.reason for item in violations) == (
        "vault-like file is outside the synthetic fixture allowlist",
        "upstream Gorilla material is prohibited",
        "path escapes repository namespace",
        "path is below prohibited directory 'docs/prompts'",
        "upstream Gorilla material is prohibited",
    )



#### Read NUL-delimited Git paths without changing their order or special characters.
####
def test_cli_reads_nul_delimited_standard_input() -> None:
    result = subprocess.run(
        (sys.executable, "-m", "tools.check_tracked_files"),
        cwd=REPOSITORY_ROOT,
        input='safe/"quoted".txt\x00safe/caf\u00e9.txt\x00notes\nname.pdf\x00vault.psafe\x00'.encode("utf-8"),
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout.decode() == (
        f"notes{os.linesep}name.pdf: generated PDF is prohibited{os.linesep}"
        f"vault.psafe: vault-like file is outside the synthetic fixture allowlist{os.linesep}"
    )
    assert result.stderr == b""



#### Reject line-delimited Git output so quoted paths are never silently accepted.
####
def test_cli_rejects_non_nul_standard_input() -> None:
    result = subprocess.run(
        (sys.executable, "-m", "tools.check_tracked_files"),
        cwd=REPOSITORY_ROOT,
        input=b'"vault\\n.psafe3"\n',
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr.decode() == f"standard input must be NUL-delimited; use 'git ls-files -z'{os.linesep}"



#### Return success without output when a NUL-delimited path stream is safe.
####
def test_cli_accepts_safe_nul_delimited_standard_input() -> None:
    result = subprocess.run(
        (sys.executable, "-m", "tools.check_tracked_files"),
        cwd=REPOSITORY_ROOT,
        input=b"src/bonobo_core/__init__.py\x00",
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
