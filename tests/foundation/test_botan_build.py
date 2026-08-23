"""Verify the verified Botan source pin, archive extraction boundary, and build profiles."""

from __future__ import annotations

import hashlib
import io
import json
import platform
import tarfile
from pathlib import Path

import pytest
import tools.build_botan as botan_build
from tools.build_botan import (
    BotanBuildError,
    BotanSourcePin,
    build_botan,
    configure_command,
    extract_fresh_verified_source,
    extract_verified_archive,
    load_source_pin,
    main,
    windows_toolchain_path,
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



#### Build a complete synthetic source pin for a local archive without network behavior.
####
#### Tests use this independent digest to confirm that cache selection follows the
#### verified archive bytes rather than an existing extracted-source directory.
####
def source_pin_for_archive(archive: Path) -> BotanSourcePin:
    return BotanSourcePin(
        version="3.13.0",
        archive=archive.name,
        source="https://example.invalid/Botan-3.13.0.tar.xz",
        signature="https://example.invalid/Botan-3.13.0.tar.xz.asc",
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        modules=("ffi", "twofish"),
    )



#### Write one valid source-pin document for a controlled local build setup.
####
#### This helper only redirects the module's pin lookup in the output-directory
#### failure test; archive extraction and all filesystem operations stay real.
####
def write_source_pin(path: Path, pin: BotanSourcePin) -> None:
    path.write_text(
        json.dumps(
            {
                "archive": pin.archive,
                "modules": list(pin.modules),
                "sha256": pin.sha256,
                "signature": pin.signature,
                "source": pin.source,
                "version": pin.version,
            }
        ),
        encoding="utf-8",
    )



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



#### Re-extract verified bytes into a fresh digest-bound directory despite a poisoned old cache.
####
#### A reused extracted tree can contain partial, modified, or symlinked files even
#### when the cached archive is valid, so compilation must receive only fresh bytes.
####
def test_fresh_verified_source_ignores_poisoned_extraction_cache(tmp_path: Path) -> None:
    archive = create_tar_xz(
        tmp_path / "Botan-3.13.0.tar.xz",
        {"Botan-3.13.0/configure.py": b"verified configure source"},
    )
    pin = source_pin_for_archive(archive)
    cache_directory = tmp_path / "cache"
    poisoned_source = cache_directory / "source" / "Botan-3.13.0"
    poisoned_source.mkdir(parents=True)
    (poisoned_source / "configure.py").write_bytes(b"poisoned configure source")

    with extract_fresh_verified_source(archive, pin, cache_directory) as source_directory:
        assert source_directory != poisoned_source
        assert source_directory.parent.name.startswith(f"source-{pin.sha256}-")
        assert (source_directory / "configure.py").read_bytes() == b"verified configure source"

    assert not source_directory.parent.exists()



#### Translate an unusable extraction destination into the build failure taxonomy.
####
#### A filesystem object at the destination prevents directory creation.  The caller
#### must receive a concise typed failure instead of the platform's path-bearing error.
####
def test_extract_reports_destination_creation_failure(tmp_path: Path) -> None:
    archive = create_tar_xz(tmp_path / "good.tar.xz", {"Botan-3.13.0/configure.py": b"safe"})
    destination = tmp_path / "not-a-directory"
    destination.write_text("blocking file", encoding="utf-8")

    with pytest.raises(BotanBuildError, match="Botan archive extraction failed"):
        extract_verified_archive(archive, destination)



#### Report a cache-directory creation failure through the CLI without a traceback or path.
####
#### The command boundary catches expected typed build failures and must never leak a
#### caller-selected cache path when the filesystem rejects directory creation.
####
def test_main_reports_cache_creation_failure_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_path = tmp_path / "not-a-directory"
    cache_path.write_text("blocking file", encoding="utf-8")

    result = main(["--target", "host", "--output", str(tmp_path / "output"), "--cache", str(cache_path)])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "Botan cache preparation failed\n"
    assert str(cache_path) not in captured.err
    assert "Traceback" not in captured.err



#### Translate output-directory creation failure before configuring the verified source.
####
#### The output boundary is caller selected.  A blocking file must produce a typed
#### failure and never advance to compiler execution with an ambiguous output location.
####
def test_build_reports_output_creation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_directory = tmp_path / "cache"
    cache_directory.mkdir()
    archive = create_tar_xz(
        cache_directory / "Botan-3.13.0.tar.xz",
        {"Botan-3.13.0/configure.py": b"verified configure source"},
    )
    pin = source_pin_for_archive(archive)
    pin_path = tmp_path / "botan-source.json"
    write_source_pin(pin_path, pin)
    monkeypatch.setattr(botan_build, "PIN_PATH", pin_path)
    output_directory = tmp_path / "not-a-directory"
    output_directory.write_text("blocking file", encoding="utf-8")

    with pytest.raises(BotanBuildError, match="Botan output directory preparation failed"):
        build_botan("linux", output_directory, cache_directory)



#### Convert an existing Windows build path with spaces before handing it to NMake tooling.
####
#### Botan's generated NMake dependencies do not quote repository paths reliably,
#### so the Windows boundary must use the operating system's equivalent short path.
####
@pytest.mark.skipif(platform.system() != "Windows", reason="Windows short paths are platform specific")
def test_windows_toolchain_path_removes_spaces(tmp_path: Path) -> None:
    source_directory = tmp_path / "source with spaces"
    source_directory.mkdir()

    converted_path = windows_toolchain_path(source_directory)

    assert converted_path.is_dir()
    assert " " not in str(converted_path)



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
