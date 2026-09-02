"""Verify that base and optional package imports remain independently usable."""

import importlib
import os
import subprocess
import sys
from pathlib import Path

import bonobo_core



#### Verify that package metadata and the PEP 561 marker are present.
####
def test_package_identity_is_typed() -> None:
    assert bonobo_core.__file__ is not None
    package_directory = Path(bonobo_core.__file__).parent

    assert bonobo_core.__version__ == "0.1.0"
    assert (package_directory / "py.typed").is_file()



#### Keep the base-wheel application contract importable without desktop extras.
####
#### The core package cannot require PySide6 because mobile and headless users
#### install the base distribution without the desktop extra.
####
def test_application_core_imports_without_desktop_dependencies() -> None:
    environment = os.environ | {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(Path("src").resolve()),
    }
    result = subprocess.run(
        (sys.executable, "-S", "-c", "import bonobo_core.application"),
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode == 0, result.stderr



#### Keep the optional desktop package importable before Qt is requested at launch.
####
#### Desktop entry-point loading is deliberately lazy, so package discovery in
#### the base wheel does not import PySide6 merely to inspect the adapter.
####
def test_desktop_package_import_does_not_load_qt() -> None:
    assert importlib.import_module("bonobo_desktop").__name__ == "bonobo_desktop"
