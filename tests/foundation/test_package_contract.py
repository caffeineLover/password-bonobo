"""Verify that the reviewed typed package identity remains consistent."""

from pathlib import Path

import bonobo_core



#### Verify that package metadata and the PEP 561 marker are present.
####
def test_package_identity_is_typed() -> None:
    assert bonobo_core.__file__ is not None
    package_directory = Path(bonobo_core.__file__).parent

    assert bonobo_core.__version__ == "0.1.0"
    assert (package_directory / "py.typed").is_file()
