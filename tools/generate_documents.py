"""Generate and verify explicitly selected Markdown, LaTeX, and review-PDF documents.

Pandoc always receives the repository header and Lua filter.  Verification writes a temporary candidate LaTeX file,
compares it exactly after line-ending normalization, and compiles the tracked source at least twice without modifying
it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast



XELATEX_PASSES = 2
MAXIMUM_XELATEX_PASSES = 3
LATEX_RERUN_WARNING = re.compile(
    r"undefined references|Rerun to get cross-references right|Label\(s\) may\s+have changed",
    re.IGNORECASE,
)
LATEX_WARNING = re.compile(
    r"Overfull \\[hv]box|Missing character:|undefined references|Rerun to get cross-references right|"
    r"Label\(s\) may\s+have changed",
    re.IGNORECASE,
)
MISSING_TEX_MESSAGE = "Markdown document has no same-basename repository-owned LaTeX source"
MISSING_MARKDOWN_MESSAGE = "LaTeX document has no same-basename repository-owned Markdown source"
MARKDOWN_ONLY_DOCUMENTS = frozenset({Path("docs/PROJECT_MEMORY.md")})
MARKDOWN_ONLY_DOCUMENT_DIRECTORIES = frozenset({
    Path("docs/compatibility/gorilla"),
    Path("docs/legal"),
    Path("docs/specs"),
})



#### Describe one substantive document and all of its stable repository paths.
####
@dataclass(frozen=True, slots=True)
class DocumentSpec:
    markdown_relative_path: Path
    tex_relative_path: Path
    pdf_relative_path: Path
    title: str



#### Describe one document-coverage or exact-generation failure.
####
@dataclass(frozen=True, slots=True)
class DocumentViolation:
    path: Path
    message: str



#### Record one completed generation result for release evidence and visual review.
####
@dataclass(frozen=True, slots=True)
class DocumentManifestEntry:
    source: str
    tex: str
    pdf: str
    tex_sha256: str
    pdf_sha256: str
    pages: int
    xelatex_passes: int
    rendered_pages: int
    verified_tex: bool



#### Return whether a LaTeX path is a generated document rather than a shared Pandoc support asset.
####
def _is_document_tex(relative_path: Path) -> bool:
    return relative_path.parent != Path("docs/pandoc")



#### Return whether one source participates in exact LaTeX and review-PDF generation.
####
#### The live project-memory checkpoint is intentionally Markdown-only because agents update it throughout active work.
####
def _is_generated_document_source(repository_root: Path, source_path: Path) -> bool:
    relative_path = source_path.relative_to(repository_root)
    return relative_path.with_suffix(".md") not in MARKDOWN_ONLY_DOCUMENTS



#### Return Git-owned and non-ignored untracked paths, failing closed when repository metadata requires Git.
####
def _git_document_source_paths(repository_root: Path) -> tuple[Path, ...] | None:
    git_metadata_path = repository_root / ".git"
    has_git_metadata = git_metadata_path.is_file() or git_metadata_path.is_dir()
    try:
        root_result = subprocess.run(  # nosec B603 B607
            ("git", "-C", str(repository_root), "rev-parse", "--show-toplevel"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        if has_git_metadata:
            raise RuntimeError(
                f"Git executable is unavailable for repository document discovery at {repository_root}; "
                ".git metadata is present, so filesystem fallback is disabled.  Install Git or repair PATH."
            ) from error
        return None
    if root_result.returncode != 0:
        if has_git_metadata:
            raise RuntimeError(
                f"Git could not confirm the exact repository root at {repository_root} "
                f"(rev-parse status {root_result.returncode}); .git metadata is present, so filesystem fallback is "
                "disabled.  Repair the repository metadata or Git configuration."
            )
        return None
    discovered_root = Path(os.fsdecode(root_result.stdout).strip()).resolve()
    if discovered_root != repository_root.resolve():
        if has_git_metadata:
            raise RuntimeError(
                f"Git resolved {discovered_root} instead of the supplied repository root {repository_root}; "
                ".git metadata is present, so filesystem fallback is disabled.  Repair the repository metadata "
                "or Git configuration."
            )
        return None
    try:
        path_result = subprocess.run(  # nosec B603 B607
            (
                "git",
                "-C",
                str(repository_root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "docs",
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(
            f"Git executable is unavailable while listing repository-owned documents at {repository_root}; "
            "filesystem fallback is disabled for a confirmed Git repository.  Restore Git and retry."
        ) from error
    if path_result.returncode != 0:
        raise RuntimeError(
            f"Git could not list repository-owned documents at {repository_root} "
            f"(ls-files status {path_result.returncode}); repair the repository or Git configuration and retry."
        )
    relative_paths = (
        Path(os.fsdecode(raw_path))
        for raw_path in path_result.stdout.split(b"\0")
        if raw_path
    )
    return tuple(
        repository_root / relative_path
        for relative_path in sorted(relative_paths)
        if relative_path.suffix in {".md", ".tex"}
    )



#### Return document source paths through Git, with filesystem fallback only for metadata-free synthetic roots.
####
def _document_source_paths(repository_root: Path) -> tuple[Path, ...]:
    git_paths = _git_document_source_paths(repository_root)
    if git_paths is not None:
        return tuple(
            path
            for path in git_paths
            if path.is_file()
            if _is_generated_document_source(repository_root, path)
        )
    docs_root = repository_root / "docs"
    if not docs_root.is_dir():
        return ()
    return tuple(
        path
        for path in sorted((*docs_root.rglob("*.md"), *docs_root.rglob("*.tex")))
        if _is_generated_document_source(repository_root, path)
    )



#### Restrict source discovery to validated, explicitly selected Markdown documents and their existing LaTeX peers.
####
def _selected_document_source_paths(
    repository_root: Path,
    document_paths: Sequence[Path] | None,
) -> tuple[Path, ...]:
    source_paths = _document_source_paths(repository_root)
    if document_paths is None:
        return source_paths
    repository_root = repository_root.resolve()
    source_by_relative_path = {
        path.relative_to(repository_root): path
        for path in source_paths
    }
    selected_paths: list[Path] = []
    selected_relative_paths: set[Path] = set()
    for requested_path in document_paths:
        candidate_path = requested_path if requested_path.is_absolute() else repository_root / requested_path
        try:
            relative_path = candidate_path.resolve().relative_to(repository_root)
        except ValueError:
            raise RuntimeError(f"selected document is outside the repository: {requested_path}") from None
        if relative_path.suffix != ".md" or relative_path.parent == Path(".") or relative_path.parts[0] != "docs":
            raise RuntimeError(f"selected document must be a Markdown source below docs: {requested_path}")
        if relative_path in MARKDOWN_ONLY_DOCUMENTS or any(
            relative_path.is_relative_to(directory)
            for directory in MARKDOWN_ONLY_DOCUMENT_DIRECTORIES
        ):
            raise RuntimeError(f"selected document is Markdown-only: {relative_path}")
        markdown_path = source_by_relative_path.get(relative_path)
        if markdown_path is None:
            raise RuntimeError(f"selected document is unavailable or ignored: {relative_path}")
        if relative_path in selected_relative_paths:
            continue
        selected_relative_paths.add(relative_path)
        selected_paths.append(markdown_path)
        tex_path = source_by_relative_path.get(relative_path.with_suffix(".tex"))
        if tex_path is not None:
            selected_paths.append(tex_path)
    return tuple(selected_paths)



#### Return every unpaired selected Markdown or LaTeX path.
####
def check_document_coverage(
    repository_root: Path,
    document_paths: Sequence[Path] | None = None,
) -> tuple[DocumentViolation, ...]:
    violations: list[DocumentViolation] = []
    source_paths = _selected_document_source_paths(repository_root, document_paths)
    markdown_paths = tuple(path for path in source_paths if path.suffix == ".md")
    tex_paths = tuple(
        path
        for path in source_paths
        if path.suffix == ".tex"
        if _is_document_tex(path.relative_to(repository_root))
    )
    markdown_path_set = frozenset(markdown_paths)
    tex_path_set = frozenset(tex_paths)
    for markdown_path in markdown_paths:
        if markdown_path.with_suffix(".tex") not in tex_path_set:
            violations.append(
                DocumentViolation(
                    markdown_path.relative_to(repository_root),
                    MISSING_TEX_MESSAGE,
                )
            )
    for tex_path in tex_paths:
        if tex_path.with_suffix(".md") not in markdown_path_set:
            violations.append(
                DocumentViolation(
                    tex_path.relative_to(repository_root),
                    MISSING_MARKDOWN_MESSAGE,
                )
            )
    return tuple(sorted(violations, key=lambda violation: violation.path.as_posix()))



#### Discover each explicitly selected Markdown document and its generated output paths in stable order.
####
def discover_document_specs(
    repository_root: Path,
    document_paths: Sequence[Path] | None = None,
) -> tuple[DocumentSpec, ...]:
    specs: list[DocumentSpec] = []
    for markdown_path in _selected_document_source_paths(repository_root, document_paths):
        if markdown_path.suffix != ".md":
            continue
        tex_path = markdown_path.with_suffix(".tex")
        first_line = markdown_path.read_text(encoding="utf-8").splitlines()[0]
        title = re.sub(r"^#\s+", "", first_line)
        markdown_relative_path = markdown_path.relative_to(repository_root)
        specs.append(
            DocumentSpec(
                markdown_relative_path,
                tex_path.relative_to(repository_root),
                markdown_relative_path.with_suffix(".pdf"),
                title,
            )
        )
    return tuple(specs)



#### Build the exact Pandoc command for one same-basename generated LaTeX source.
####
def build_pandoc_command(spec: DocumentSpec, repository_root: Path, output_path: Path) -> tuple[str, ...]:
    return (
        "pandoc",
        str(repository_root / spec.markdown_relative_path),
        "--from=gfm",
        "--to=latex",
        "--standalone",
        "--toc",
        "--listings",
        "--wrap=auto",
        "--columns=120",
        f"--include-in-header={repository_root / 'docs' / 'pandoc' / 'pdf-header.tex'}",
        f"--lua-filter={repository_root / 'docs' / 'pandoc' / 'pdf-layout.lua'}",
        f"--metadata=title={spec.title}",
        "--variable=papersize:letter",
        "--variable=geometry:margin=0.8in",
        f"--output={output_path}",
    )



#### Build one deterministic XeLaTeX pass against the tracked LaTeX source.
####
def build_xelatex_command(
    spec: DocumentSpec,
    repository_root: Path,
    build_directory: Path,
) -> tuple[str, ...]:
    return (
        "xelatex",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-file-line-error",
        f"-output-directory={build_directory}",
        str(repository_root / spec.tex_relative_path),
    )



#### Compare generated and tracked LaTeX after normalizing only physical line endings.
####
def verify_generated_tex(tracked_path: Path, candidate_path: Path) -> tuple[DocumentViolation, ...]:
    tracked = tracked_path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    candidate = candidate_path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if tracked == candidate:
        return ()
    return (DocumentViolation(tracked_path, "generated LaTeX differs from the tracked source"),)



#### Create one empty output directory so stale compiler state cannot affect a new build.
####
def prepare_output_directory(output_directory: Path) -> None:
    if output_directory.is_dir():
        shutil.rmtree(output_directory)
    output_directory.mkdir(parents=True)



#### Return whether a compiler log requests another bounded stabilization pass.
####
def latex_requires_rerun(compiler_log_source: str) -> bool:
    return LATEX_RERUN_WARNING.search(compiler_log_source) is not None



#### Run one external document command and preserve its complete combined output as a log.
####
def _run_command(command: tuple[str, ...], repository_root: Path, log_path: Path) -> str:
    # Every command is constructed by this module as an argument tuple, and shell expansion remains disabled.
    result = subprocess.run(  # nosec B603
        command,
        cwd=repository_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(result.stdout)
    output = result.stdout.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(f"document command failed with status {result.returncode}; see {log_path}")
    return output



#### Return the SHA-256 digest of one generated source or review artifact.
####
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()



#### Parse the page total from Poppler's machine-readable summary.
####
def _page_count(pdfinfo_output: str, pdf_path: Path) -> int:
    match = re.search(r"(?m)^Pages:\s+(\d+)\s*$", pdfinfo_output)
    if match is None:
        raise RuntimeError(f"pdfinfo did not report a page count for {pdf_path}")
    return int(match.group(1))



#### Convert one manifest entry into JSON-compatible release evidence.
####
def _manifest_record(entry: DocumentManifestEntry) -> dict[str, str | int | bool]:
    return {
        "source": entry.source,
        "tex": entry.tex,
        "pdf": entry.pdf,
        "tex_sha256": entry.tex_sha256,
        "pdf_sha256": entry.pdf_sha256,
        "pages": entry.pages,
        "xelatex_passes": entry.xelatex_passes,
        "rendered_pages": entry.rendered_pages,
        "verified_tex": entry.verified_tex,
    }



#### Generate or verify selected documents, compile two passes, and emit a detailed ignored manifest.
####
def generate_documents(
    repository_root: Path,
    *,
    document_paths: Sequence[Path],
    write_tex: bool,
    render: bool,
    manifest_path: Path,
) -> tuple[DocumentManifestEntry, ...]:
    coverage_violations = check_document_coverage(repository_root, document_paths)
    if write_tex:
        coverage_violations = tuple(
            violation
            for violation in coverage_violations
            if violation.message != MISSING_TEX_MESSAGE
        )
    if coverage_violations:
        details = "; ".join(f"{item.path}: {item.message}" for item in coverage_violations)
        raise RuntimeError(details)

    temporary_root = repository_root / "tmp" / "pdfs"
    generated_root = temporary_root / "generated"
    build_root = temporary_root / "build"
    render_root = temporary_root / "rendered"
    log_root = temporary_root / "logs"
    entries: list[DocumentManifestEntry] = []
    for spec in discover_document_specs(repository_root, document_paths):
        relative_stem = spec.markdown_relative_path.with_suffix("")
        tracked_tex_path = repository_root / spec.tex_relative_path
        candidate_path = tracked_tex_path if write_tex else generated_root / spec.tex_relative_path
        candidate_path.parent.mkdir(parents=True, exist_ok=True)
        pandoc_log = log_root / relative_stem / "pandoc.log"
        _run_command(build_pandoc_command(spec, repository_root, candidate_path), repository_root, pandoc_log)
        verified_tex = write_tex
        if not write_tex:
            verification_violations = verify_generated_tex(tracked_tex_path, candidate_path)
            if verification_violations:
                raise RuntimeError(f"{tracked_tex_path}: generated LaTeX differs; see {pandoc_log}")
            verified_tex = True

        document_build_root = build_root / relative_stem
        prepare_output_directory(document_build_root)
        xelatex_command = build_xelatex_command(spec, repository_root, document_build_root)
        compiler_log = document_build_root / f"{tracked_tex_path.stem}.log"
        passes_completed = 0
        for pass_number in range(1, MAXIMUM_XELATEX_PASSES + 1):
            _run_command(
                xelatex_command,
                repository_root,
                log_root / relative_stem / f"xelatex-pass-{pass_number}.log",
            )
            passes_completed = pass_number
            if pass_number >= XELATEX_PASSES and not latex_requires_rerun(
                compiler_log.read_text(encoding="utf-8", errors="replace")
            ):
                break

        if LATEX_WARNING.search(compiler_log.read_text(encoding="utf-8", errors="replace")) is not None:
            raise RuntimeError(f"LaTeX stabilization or layout warning found in {compiler_log}")
        built_pdf = document_build_root / f"{tracked_tex_path.stem}.pdf"
        pdf_path = repository_root / spec.pdf_relative_path
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built_pdf, pdf_path)

        pdfinfo_output = _run_command(
            ("pdfinfo", str(pdf_path)),
            repository_root,
            log_root / relative_stem / "pdfinfo.log",
        )
        pages = _page_count(pdfinfo_output, pdf_path)
        rendered_pages = 0
        if render:
            document_render_root = render_root / relative_stem
            prepare_output_directory(document_render_root)
            render_prefix = document_render_root / "page"
            _run_command(
                ("pdftoppm", "-png", "-r", "110", str(pdf_path), str(render_prefix)),
                repository_root,
                log_root / relative_stem / "pdftoppm.log",
            )
            rendered_pages = len(tuple(document_render_root.glob("page-*.png")))
            if rendered_pages != pages:
                raise RuntimeError(
                    f"rendered-page mismatch for {spec.markdown_relative_path}: "
                    f"PDF={pages}, rendered={rendered_pages}"
                )

        entries.append(
            DocumentManifestEntry(
                spec.markdown_relative_path.as_posix(),
                spec.tex_relative_path.as_posix(),
                spec.pdf_relative_path.as_posix(),
                _sha256(tracked_tex_path),
                _sha256(pdf_path),
                pages,
                passes_completed,
                rendered_pages,
                verified_tex,
            )
        )
        print(
            f"{spec.markdown_relative_path.as_posix()} pages={pages} "
            f"passes={passes_completed} rendered={rendered_pages}"
        )

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps([_manifest_record(entry) for entry in entries], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"manifest={manifest_path}")
    return tuple(entries)



#### Parse document mode and output options, then return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="regenerate tracked same-basename LaTeX sources")
    mode.add_argument("--verify", action="store_true", help="verify tracked LaTeX without modifying it")
    parser.add_argument(
        "--document",
        action="append",
        type=Path,
        required=True,
        help="explicit Markdown document to process; repeat for additional documents",
    )
    parser.add_argument("--render", action="store_true", help="render each selected final PDF page to PNG")
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=Path("tmp/pdfs/manifest.json"))
    arguments = parser.parse_args(argv)
    repository_root = cast(Path, arguments.repository_root).resolve()
    manifest_path = cast(Path, arguments.manifest)
    if not manifest_path.is_absolute():
        manifest_path = repository_root / manifest_path
    write_tex = cast(bool, arguments.write)
    generate_documents(
        repository_root,
        document_paths=cast(list[Path], arguments.document),
        write_tex=write_tex,
        render=cast(bool, arguments.render),
        manifest_path=manifest_path,
    )
    return 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
