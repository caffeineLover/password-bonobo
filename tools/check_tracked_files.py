"""Reject generated, upstream, and credential-bearing repository paths.

The command examines path names only and never opens a possible vault or secret-bearing file.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast



#### Describe one forbidden path without reading or exposing its contents.
####
@dataclass(frozen=True, slots=True)
class ForbiddenPath:
    path: Path
    reason: str



#### Return a safe rejection reason for one normalized repository path.
####
def _forbidden_reason(path: Path) -> str | None:
    normalized = path.as_posix().lstrip("./")
    lowered = normalized.lower()
    parts = lowered.split("/")

    for prefix in ("docs/prompts", "tmp", "logs", "research"):
        if lowered == prefix or lowered.startswith(f"{prefix}/"):
            return f"path is below prohibited directory '{prefix}'"

    allowed_gorilla_docs = lowered == "docs/compatibility/gorilla" or lowered.startswith(
        "docs/compatibility/gorilla/"
    )
    if "gorilla" in parts and not allowed_gorilla_docs:
        return "upstream Gorilla material is prohibited"

    if path.suffix.lower() == ".pdf":
        return "generated PDF is prohibited"

    synthetic_fixture = lowered.startswith("tests/fixtures/synthetic/")
    if path.suffix.lower() in {".psafe", ".psafe3", ".dat"} and not synthetic_fixture:
        return "vault-like file is outside the synthetic fixture allowlist"

    filename = path.name.lower()
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



#### Read path arguments or standard input, print safe findings, and return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    arguments = parser.parse_args(argv)
    paths = tuple(cast(list[Path], arguments.paths))
    if not paths:
        paths = tuple(Path(line.strip()) for line in sys.stdin if line.strip())

    violations = find_forbidden(paths)
    for violation in violations:
        print(f"{violation.path}: {violation.reason}")
    return 1 if violations else 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
