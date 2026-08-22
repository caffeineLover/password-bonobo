"""Reject generated, upstream, and credential-bearing repository paths.

The command examines path names only and never opens a possible vault or secret-bearing file.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast



#### Describe one forbidden path without reading or exposing its contents.
####
@dataclass(frozen=True, slots=True)
class ForbiddenPath:
    path: Path
    reason: str



#### Canonicalize one repository-relative path without opening it.
####
def _normalize_repository_path(path: Path) -> tuple[PurePosixPath | None, str | None]:
    # Treat both separator styles as components before collapsing lexical dot
    # segments.  This keeps policy behavior identical on Windows and POSIX.
    raw_path = path.as_posix().replace("\\", "/")
    if raw_path.startswith("/") or (len(raw_path) >= 2 and raw_path[0].isalpha() and raw_path[1] == ":"):
        return None, "path is not repository-relative"

    components: list[str] = []
    for component in raw_path.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            # Stop at the repository boundary so an allowlist cannot be
            # reached by paths that escape the tracked-file namespace.
            if not components:
                return None, "path escapes repository namespace"
            components.pop()
            continue
        components.append(component)

    if not components:
        return None, "path is not repository-relative"

    return PurePosixPath(*components), None



#### Return a safe rejection reason for one normalized repository path.
####
def _forbidden_reason(path: Path) -> str | None:
    normalized_path, normalization_error = _normalize_repository_path(path)
    if normalization_error is not None:
        return normalization_error
    if normalized_path is None:
        raise RuntimeError("path normalization returned neither a path nor an error")

    lowered = normalized_path.as_posix().lower()
    parts = tuple(component.lower() for component in normalized_path.parts)

    # Apply directory policy before extension and filename policy so the first
    # reported reason stays deterministic for paths matching multiple rules.
    for prefix in ("docs/prompts", "tmp", "logs", "research"):
        if lowered == prefix or lowered.startswith(f"{prefix}/"):
            return f"path is below prohibited directory '{prefix}'"

    allowed_gorilla_docs = lowered == "docs/compatibility/gorilla" or lowered.startswith(
        "docs/compatibility/gorilla/"
    )
    if "gorilla" in parts and not allowed_gorilla_docs:
        return "upstream Gorilla material is prohibited"

    if normalized_path.suffix.lower() == ".pdf":
        return "generated PDF is prohibited"

    synthetic_fixture = lowered.startswith("tests/fixtures/synthetic/")
    if normalized_path.suffix.lower() in {".psafe", ".psafe3", ".dat"} and not synthetic_fixture:
        return "vault-like file is outside the synthetic fixture allowlist"

    filename = normalized_path.name.lower()
    if filename == ".env" or filename.endswith((".key", ".pem")):
        return "secret-bearing filename is prohibited"
    if filename in {"id_rsa", "id_ed25519"}:
        return "private-key filename is prohibited"

    return None



#### Return prohibited repository paths in input order without reading them.
####
def find_forbidden(paths: Iterable[Path]) -> tuple[ForbiddenPath, ...]:
    violations: list[ForbiddenPath] = []
    for path in paths:
        reason = _forbidden_reason(path)
        if reason is not None:
            violations.append(ForbiddenPath(path, reason))
    return tuple(violations)



#### Read NUL-delimited Git path records from redirected standard input.
####
def _read_nul_delimited_standard_input() -> tuple[Path, ...] | None:
    # Git -z framing preserves Unicode, quotes, escapes, and embedded newlines
    # that make line-delimited Git output ambiguous.
    path_bytes = sys.stdin.buffer.read()
    if not path_bytes:
        return ()
    if not path_bytes.endswith(b"\0"):
        print("standard input must be NUL-delimited; use 'git ls-files -z'", file=sys.stderr)
        return None

    records = path_bytes[:-1].split(b"\0")
    if any(not record for record in records):
        print("standard input contains an empty path record", file=sys.stderr)
        return None

    return tuple(Path(record.decode("utf-8", errors="surrogateescape")) for record in records)



#### Read path arguments or standard input, print safe findings, and return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    arguments = parser.parse_args(argv)
    paths = tuple(cast(list[Path], arguments.paths))
    if not paths and not sys.stdin.isatty():
        # Positional arguments remain convenient for local checks.  Redirected
        # standard input uses only Git's unambiguous NUL-delimited framing.
        standard_input_paths = _read_nul_delimited_standard_input()
        if standard_input_paths is None:
            # Distinguish malformed input from a valid policy violation so CI
            # cannot mistake a broken pipeline for a clean repository.
            return 2
        paths = standard_input_paths

    violations = find_forbidden(paths)
    for violation in violations:
        print(f"{violation.path}: {violation.reason}")
    return 1 if violations else 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
