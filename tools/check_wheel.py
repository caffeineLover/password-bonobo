"""Verify PEP 639 GPL metadata and license bytes in a built Password Bonobo wheel.

The release gate opens only the local build artifact and compares its declared license file with the tracked canonical
text.  It does not inspect or modify external research content.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from zipfile import BadZipFile, ZipFile



LICENSE_EXPRESSION = "License-Expression: GPL-3.0-or-later"
LICENSE_FILE_DECLARATION = "License-File: LICENSES/GPL-3.0-or-later.txt"
LICENSE_MEMBER_SUFFIX = ".dist-info/licenses/LICENSES/GPL-3.0-or-later.txt"



#### Describe one wheel-content or metadata contract failure.
####
@dataclass(frozen=True, slots=True)
class WheelViolation:
    message: str



#### Return all PEP 639 metadata and embedded-license violations in one wheel.
####
def check_wheel(wheel_path: Path, license_path: Path) -> tuple[WheelViolation, ...]:
    violations: list[WheelViolation] = []
    expected_license_bytes = license_path.read_bytes()
    try:
        with ZipFile(wheel_path) as archive:
            names = tuple(archive.namelist())
            metadata_names = tuple(name for name in names if name.endswith(".dist-info/METADATA"))
            if len(metadata_names) != 1:
                violations.append(WheelViolation("wheel must contain exactly one .dist-info/METADATA file"))
                metadata = ""
            else:
                metadata = archive.read(metadata_names[0]).decode("utf-8")

            metadata_lines = set(metadata.splitlines())
            if LICENSE_EXPRESSION not in metadata_lines:
                violations.append(WheelViolation(f"METADATA must declare {LICENSE_EXPRESSION}"))
            if LICENSE_FILE_DECLARATION not in metadata_lines:
                violations.append(WheelViolation(f"METADATA must declare {LICENSE_FILE_DECLARATION}"))

            license_members = tuple(name for name in names if name.endswith(LICENSE_MEMBER_SUFFIX))
            if len(license_members) != 1:
                violations.append(WheelViolation("wheel must contain the declared GPL license file exactly once"))
            elif archive.read(license_members[0]) != expected_license_bytes:
                violations.append(
                    WheelViolation("embedded GPL license bytes differ from the repository license artifact")
                )
    except BadZipFile:
        violations.append(WheelViolation("wheel is not a readable ZIP archive"))
    return tuple(violations)



#### Resolve exactly one wheel from a file or distribution directory.
####
def _resolve_wheel(path: Path) -> tuple[Path | None, tuple[WheelViolation, ...]]:
    if path.is_file():
        return path, ()
    wheels = tuple(sorted(path.glob("*.whl"))) if path.is_dir() else ()
    if len(wheels) != 1:
        return None, (WheelViolation(f"expected exactly one wheel below {path}, found {len(wheels)}"),)
    return wheels[0], ()



#### Parse build paths, report wheel findings, and return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel_or_directory", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument(
        "--license",
        type=Path,
        default=Path("LICENSES/GPL-3.0-or-later.txt"),
    )
    arguments = parser.parse_args(argv)
    wheel_path, resolution_violations = _resolve_wheel(arguments.wheel_or_directory)
    violations = list(resolution_violations)
    if wheel_path is not None:
        violations.extend(check_wheel(wheel_path, arguments.license))
    for violation in violations:
        print(violation.message)
    return 1 if violations else 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
