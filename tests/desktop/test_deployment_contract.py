"""Qualify deterministic desktop deployment and hosted-job dependency boundaries.

The tests parse the deployment and workflow artifacts as configuration so CI
cannot silently widen Qt modules, omit packaged QML, or install desktop
dependencies in mobile cross-build jobs.
"""

from __future__ import annotations

import configparser
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import cast

# PyYAML is a locked transitive development dependency without bundled type
# information.  Values are narrowed to closed mappings immediately after load.
import yaml  # type: ignore[import-untyped]



REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_SPEC = REPOSITORY_ROOT / "pysidedeploy.spec"
FOUNDATION_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "foundation.yml"



#### Represent only the deployment settings Password Bonobo commits as its native-build contract.
####
@dataclass(frozen=True, slots=True)
class DeploymentSpec:
    title: str
    project_dir: str
    input_file: str
    exec_directory: str
    qml_files: tuple[str, ...]
    modules: tuple[str, ...]



#### Narrow one parsed YAML object to a string-keyed mapping used by the workflow helpers.
####
def _mapping(value: object, context: str) -> dict[str, object]:
    assert isinstance(value, dict), f"{context} must be a mapping"
    assert all(isinstance(key, str) for key in value), f"{context} keys must be strings"
    return cast(dict[str, object], value)



#### Narrow one parsed YAML object to a sequence used by the workflow helpers.
####
def _sequence(value: object, context: str) -> list[object]:
    assert isinstance(value, list), f"{context} must be a sequence"
    return cast(list[object], value)



#### Read the checked-in PySide deployment configuration without invoking the deploy tool.
####
#### Parsing the public configuration contract independently keeps literal
#### expectations separate from PySide's implementation and reports absent
#### required settings before a platform build begins.
####
def read_deployment_spec() -> DeploymentSpec:
    parser = configparser.ConfigParser(interpolation=None)
    loaded = parser.read(DEPLOYMENT_SPEC, encoding="utf-8")
    assert loaded == [str(DEPLOYMENT_SPEC)], "pysidedeploy.spec is absent"

    qml_files = tuple(part for part in parser.get("qt", "qml_files").split(",") if part)
    modules = tuple(part for part in parser.get("qt", "modules").split(",") if part)
    return DeploymentSpec(
        title=parser.get("app", "title"),
        project_dir=parser.get("app", "project_dir"),
        input_file=parser.get("app", "input_file"),
        exec_directory=parser.get("app", "exec_directory"),
        qml_files=qml_files,
        modules=modules,
    )



#### Load the hosted workflow as structured data rather than matching source substrings.
####
def load_foundation_workflow() -> dict[str, object]:
    parsed: object = yaml.load(FOUNDATION_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    return _mapping(parsed, "foundation workflow")



#### Return one named workflow job from the parsed hosted configuration.
####
def _job(workflow: dict[str, object], name: str) -> dict[str, object]:
    jobs = _mapping(workflow.get("jobs"), "workflow jobs")
    return _mapping(jobs.get(name), f"workflow job {name}")



#### Return the structured run steps for one hosted job.
####
def _run_steps(job: dict[str, object]) -> tuple[dict[str, object], ...]:
    steps = _sequence(job.get("steps"), "job steps")
    return tuple(_mapping(step, "workflow step") for step in steps if "run" in _mapping(step, "workflow step"))



#### Return shell tokens for each run command in one hosted job.
####
def _commands(job: dict[str, object]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(shlex.split(str(step["run"]), posix=True)) for step in _run_steps(job))



#### Return the explicitly selected extras and groups from one job's single sync command.
####
def _dependency_selection(job: dict[str, object]) -> tuple[frozenset[str], frozenset[str]]:
    sync_commands = tuple(command for command in _commands(job) if command[:2] == ("uv", "sync"))
    assert len(sync_commands) == 1, "each job must have exactly one uv sync command"
    command = sync_commands[0]
    assert "--locked" in command
    assert "--no-default-groups" in command
    assert "--all-groups" not in command

    extras = frozenset(command[index + 1] for index, token in enumerate(command[:-1]) if token == "--extra")
    groups = frozenset(command[index + 1] for index, token in enumerate(command[:-1]) if token == "--group")
    return extras, groups



#### Require one exact command and, optionally, its environment in a hosted job.
####
def _step_for_command(job: dict[str, object], expected: tuple[str, ...]) -> dict[str, object]:
    matches = tuple(step for step in _run_steps(job) if tuple(shlex.split(str(step["run"]), posix=True)) == expected)
    assert len(matches) == 1, f"job must run exactly one {' '.join(expected)} step"
    return matches[0]



#### Pin the native deployment entry point, output location, app name, and exact Qt module closure.
####
def test_deployment_spec_names_only_required_qt_modules() -> None:
    spec = read_deployment_spec()

    assert spec.title == "Password Bonobo"
    assert spec.project_dir == "."
    assert spec.input_file == "src/bonobo_desktop/main.py"
    assert spec.exec_directory == "dist/desktop"
    assert spec.modules == ("Core", "Gui", "Qml", "Quick", "QuickControls2")



#### Pin every QML source consumed by deployment and require the packaged module descriptor beside it.
####
def test_deployment_spec_names_all_packaged_qml_resources() -> None:
    spec = read_deployment_spec()
    expected = (
        "src/bonobo_desktop/qml/DecisionDialog.qml",
        "src/bonobo_desktop/qml/Main.qml",
        "src/bonobo_desktop/qml/RecordEditor.qml",
        "src/bonobo_desktop/qml/UnlockView.qml",
        "src/bonobo_desktop/qml/VaultView.qml",
        "src/bonobo_desktop/qml/WelcomeView.qml",
    )

    assert spec.qml_files == expected
    assert all((REPOSITORY_ROOT / relative).is_file() for relative in spec.qml_files)
    assert (REPOSITORY_ROOT / "src/bonobo_desktop/qml/qmldir").is_file()



#### Require every native matrix leg to install desktop dependencies and exercise QML plus deployment offscreen.
####
def test_desktop_ci_installs_extra_and_runs_offscreen_smoke() -> None:
    workflow = load_foundation_workflow()
    quality = _job(workflow, "quality")
    strategy = _mapping(quality.get("strategy"), "quality strategy")
    matrix = _mapping(strategy.get("matrix"), "quality matrix")

    assert _sequence(matrix.get("os"), "quality operating systems") == [
        "windows-latest",
        "macos-latest",
        "ubuntu-latest",
    ]
    assert _dependency_selection(quality) == (frozenset({"desktop"}), frozenset({"dev", "desktop-test"}))

    test_step = _step_for_command(quality, ("uv", "run", "python", "-m", "pytest", "tests/desktop", "-q"))
    environment = _mapping(test_step.get("env"), "desktop test environment")
    assert environment.get("QT_QPA_PLATFORM") == "offscreen"
    _step_for_command(quality, ("uv", "run", "pyside6-deploy", "--dry-run", "-c", "pysidedeploy.spec"))



#### Keep mobile compile/link jobs on the base project plus development tools only.
####
def test_mobile_ci_excludes_desktop_dependencies() -> None:
    workflow = load_foundation_workflow()

    for name in ("android-cross", "ios-cross"):
        mobile = _job(workflow, name)
        assert _dependency_selection(mobile) == (frozenset(), frozenset({"dev"}))
        flattened = tuple(token for command in _commands(mobile) for token in command)
        assert "desktop" not in flattened
        assert "desktop-test" not in flattened
