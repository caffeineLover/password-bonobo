"""Verify that built wheels carry the complete declared GPL license artifact."""

import tarfile
from pathlib import Path
from zipfile import ZipFile

from tools.check_wheel import check_wheel, main



#### Write one synthetic wheel with independently supplied metadata and license bytes.
####
def _write_wheel(
    path: Path,
    metadata: str,
    license_bytes: bytes | None,
    *,
    include_typing_marker: bool,
) -> None:
    with ZipFile(path, "w") as archive:
        archive.writestr("password_bonobo-0.0.0.dist-info/METADATA", metadata)
        if license_bytes is not None:
            archive.writestr(
                "password_bonobo-0.0.0.dist-info/licenses/LICENSES/GPL-3.0-or-later.txt",
                license_bytes,
            )
        if include_typing_marker:
            archive.writestr("bonobo_core/py.typed", b"")



#### Write one synthetic source distribution with independently selected required members.
####
def _write_sdist(
    path: Path,
    license_bytes: bytes | None,
    *,
    include_typing_marker: bool,
) -> None:
    root = "password_bonobo-0.0.0"
    with tarfile.open(path, "w:gz") as archive:
        if license_bytes is not None:
            _add_tar_bytes(archive, f"{root}/LICENSES/GPL-3.0-or-later.txt", license_bytes)
        if include_typing_marker:
            _add_tar_bytes(archive, f"{root}/src/bonobo_core/py.typed", b"")



#### Add one exact byte payload to a synthetic tar archive.
####
def _add_tar_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    import io

    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))



#### Return complete synthetic PEP 639 metadata.
####
def _complete_metadata() -> str:
    return (
        "Metadata-Version: 2.4\n"
        "Name: password-bonobo\n"
        "License-Expression: GPL-3.0-or-later\n"
        "License-File: LICENSES/GPL-3.0-or-later.txt\n"
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
        include_typing_marker=True,
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
        include_typing_marker=True,
    )

    messages = tuple(violation.message for violation in check_wheel(wheel_path, license_path))

    assert messages == (
        "METADATA must declare License-Expression: GPL-3.0-or-later",
        "METADATA must declare License-File: LICENSES/GPL-3.0-or-later.txt",
        "embedded GPL license bytes differ from the repository license artifact",
    )



#### Reject a wheel that omits the GPL archive member entirely.
####
def test_wheel_without_gpl_member_fails(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    wheel_path = tmp_path / "password_bonobo-0.0.0-py3-none-any.whl"
    _write_wheel(
        wheel_path,
        _complete_metadata(),
        None,
        include_typing_marker=True,
    )

    messages = tuple(violation.message for violation in check_wheel(wheel_path, license_path))

    assert "wheel must contain the declared GPL license file exactly once" in messages



#### Reject a wheel that omits the package typing marker.
####
def test_wheel_without_typing_marker_fails(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    wheel_path = tmp_path / "password_bonobo-0.0.0-py3-none-any.whl"
    _write_wheel(
        wheel_path,
        _complete_metadata(),
        license_path.read_bytes(),
        include_typing_marker=False,
    )

    messages = tuple(violation.message for violation in check_wheel(wheel_path, license_path))

    assert "wheel must contain bonobo_core/py.typed exactly once" in messages



#### Reject a source distribution that omits the GPL archive member.
####
def test_sdist_without_gpl_member_fails(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    _write_complete_wheel(tmp_path, license_path)
    _write_sdist(
        tmp_path / "password_bonobo-0.0.0.tar.gz",
        None,
        include_typing_marker=True,
    )

    assert main([str(tmp_path), "--license", str(license_path)]) == 1



#### Reject a source distribution that omits the package typing marker.
####
def test_sdist_without_typing_marker_fails(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    _write_complete_wheel(tmp_path, license_path)
    _write_sdist(
        tmp_path / "password_bonobo-0.0.0.tar.gz",
        license_path.read_bytes(),
        include_typing_marker=False,
    )

    assert main([str(tmp_path), "--license", str(license_path)]) == 1



#### Accept complete wheel and source-distribution archive membership together.
####
def test_complete_distribution_artifacts_pass(tmp_path: Path) -> None:
    license_path = tmp_path / "GPL-3.0-or-later.txt"
    license_path.write_bytes(b"fabricated complete GPL text")
    _write_complete_wheel(tmp_path, license_path)
    _write_sdist(
        tmp_path / "password_bonobo-0.0.0.tar.gz",
        license_path.read_bytes(),
        include_typing_marker=True,
    )

    assert main([str(tmp_path), "--license", str(license_path)]) == 0



#### Write the complete wheel half of one synthetic distribution set.
####
def _write_complete_wheel(directory: Path, license_path: Path) -> None:
    _write_wheel(
        directory / "password_bonobo-0.0.0-py3-none-any.whl",
        _complete_metadata(),
        license_path.read_bytes(),
        include_typing_marker=True,
    )
