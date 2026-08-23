"""Verify the verified Botan source pin, archive extraction boundary, and build profiles."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from tools.build_botan import (
    BotanBuildError,
    configure_command,
    extract_verified_archive,
    load_source_pin,
)



REPOSITORY_ROOT = Path(__file__).parents[2]



#### Create a small xz-compressed archive with exact synthetic member payloads.
####
#### The helper keeps archive construction in the test boundary so extraction tests
#### exercise the production tar-file validation rather than a mocked archive API.
####
def create_tar_xz(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:xz") as archive:
        for name, payload in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return path



#### Preserve the approved Botan release identity and required minimized modules.
####
#### A changed version, digest, or module selection would make the resulting native
#### build ineligible for the approved production Twofish boundary.
####
def test_botan_source_pin_matches_approved_release() -> None:
    pin = load_source_pin(REPOSITORY_ROOT / "tools" / "botan-source.json")

    assert pin.version == "3.13.0"
    assert pin.sha256 == "12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620"
    assert pin.modules == ("ffi", "twofish")



#### Reject a source pin that could direct verified acquisition to a local or non-HTTPS scheme.
####
#### The pin is repository-controlled, but restricting its endpoint to HTTPS keeps a
#### malformed review update from widening the build tool's URL-opening capability.
####
def test_botan_source_pin_rejects_non_https_source(tmp_path: Path) -> None:
    malformed_pin = tmp_path / "botan-source.json"
    source = (REPOSITORY_ROOT / "tools" / "botan-source.json").read_text(encoding="utf-8")
    malformed_pin.write_text(source.replace("https://", "file://", 1), encoding="utf-8")

    with pytest.raises(BotanBuildError, match="Botan source pin is invalid"):
        load_source_pin(malformed_pin)



#### Refuse an archive member that would escape the dedicated extraction directory.
####
#### An untrusted upstream archive must never be able to overwrite a neighboring
#### checkout file through a parent-directory traversal member name.
####
def test_extract_rejects_parent_escape(tmp_path: Path) -> None:
    archive = create_tar_xz(tmp_path / "bad.tar.xz", {"../outside": b"forbidden"})

    with pytest.raises(BotanBuildError, match="unsafe archive member"):
        extract_verified_archive(archive, tmp_path / "output")



#### Generate the approved compiler, operating-system, and CPU profile for every target.
####
#### A profile substitution can silently produce an unusable binary or omit the
#### intended platform architecture, so each configured target is asserted literally.
####
@pytest.mark.parametrize(
    ("target", "expected_profile"),
    (
        ("windows", ("--cc=msvc", "--os=windows", "--cpu=x86_64")),
        ("macos", ("--cc=clang", "--os=darwin")),
        ("linux", ("--cc=gcc", "--os=linux")),
        ("android", ("--cc=clang", "--os=android", "--cpu=arm64")),
        ("ios", ("--cc=clang", "--os=ios", "--cpu=arm64")),
    ),
)
def test_configure_command_uses_approved_target_profile(
    target: str,
    expected_profile: tuple[str, ...],
) -> None:
    command = configure_command(
        target,
        Path("C:/synthetic/botan-source"),
        Path("C:/synthetic/botan-output"),
    )

    assert all(option in command for option in expected_profile)
    assert "--minimized-build" in command
    assert "--enable-modules=ffi,twofish" in command
    assert "--build-targets=shared" in command
