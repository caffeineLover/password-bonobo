"""Verify that built wheels carry the complete declared GPL license artifact."""

from pathlib import Path
from zipfile import ZipFile

from tools.check_wheel import check_wheel



#### Write one synthetic wheel with independently supplied metadata and license bytes.
####
def _write_wheel(path: Path, metadata: str, license_bytes: bytes | None) -> None:
    with ZipFile(path, "w") as archive:
        archive.writestr("password_bonobo-0.0.0.dist-info/METADATA", metadata)
        if license_bytes is not None:
            archive.writestr(
                "password_bonobo-0.0.0.dist-info/licenses/LICENSES/GPL-3.0-or-later.txt",
                license_bytes,
            )



#### Accept a wheel whose PEP 639 metadata and embedded license match the repository artifact.
####
def test_wheel_with_matching_gpl_license_passes(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    wheel_path = tmp_path / "password_bonobo-0.0.0-py3-none-any.whl"
    _write_wheel(
        wheel_path,
        "Metadata-Version: 2.4\n"
        "Name: password-bonobo\n"
        "License-Expression: GPL-3.0-or-later\n"
        "License-File: LICENSES/GPL-3.0-or-later.txt\n",
        license_path.read_bytes(),
    )

    assert check_wheel(wheel_path, license_path) == ()



#### Reject absent, altered, or undeclared wheel license content.
####
def test_wheel_without_exact_declared_gpl_license_fails(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    wheel_path = tmp_path / "password_bonobo-0.0.0-py3-none-any.whl"
    _write_wheel(
        wheel_path,
        "Metadata-Version: 2.4\nName: password-bonobo\n",
        b"altered text",
    )

    messages = tuple(violation.message for violation in check_wheel(wheel_path, license_path))

    assert messages == (
        "METADATA must declare License-Expression: GPL-3.0-or-later",
        "METADATA must declare License-File: LICENSES/GPL-3.0-or-later.txt",
        "embedded GPL license bytes differ from the repository license artifact",
    )
