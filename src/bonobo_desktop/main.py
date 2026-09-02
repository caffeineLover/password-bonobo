"""Compose the optional PySide6 desktop process around the reusable vault facade.

Qt imports stay inside launch functions so installing the base wheel never
requires desktop bindings.  QML workflows and controller bindings are deferred
to later desktop tasks; this module owns only startup, safe failed startup, and
shutdown ordering.
"""

from __future__ import annotations

from contextlib import suppress
from ctypes.util import find_library
from pathlib import Path
from sys import argv as process_argv
from typing import TYPE_CHECKING

from bonobo_core.application import VaultApplication
from bonobo_core.passwordsafe import VaultService, VaultSession

from . import resources



if TYPE_CHECKING:
    from collections.abc import Sequence



#### Create the dedicated private directories required by the PasswordSafe service.
####
#### Qt selects one user-local application-data root after the organization and
#### application names have been configured.  The two directories remain
#### separate because working snapshots and recovery artifacts have distinct
#### ownership and retention rules in the core service.
####
def _private_directories(application_data_directory: str) -> tuple[Path, Path]:
    root = Path(application_data_directory)
    working_directory = root / "working"
    recovery_directory = root / "recovery"
    for directory in (working_directory, recovery_directory):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    return working_directory, recovery_directory



#### Resolve the platform loader name for the existing Botan shared-library contract.
####
#### The desktop package never downloads or builds Botan at runtime.  It asks
#### the operating-system loader for the already-provisioned native dependency
#### and fails startup safely when no compatible installed library is visible.
####
def _botan_library_path() -> Path | None:
    library = find_library("botan-3") or find_library("botan")
    return None if library is None else Path(library)



#### Request a terminal facade lock during GUI teardown without masking shutdown.
####
#### The facade owns the authenticated session and dirty-suspension lifecycle.
#### Unlike the interactive close command, terminal lock suspends dirty state
#### before the engine is destroyed.  Failures remain best effort here because
#### the skeleton has no QML error-recovery workflow yet.
####
def _request_shutdown_lock(application: VaultApplication[VaultSession]) -> None:
    with suppress(Exception):
        application.lock(application.snapshot.generation)



#### Start the optional Qt Quick desktop shell and return its process status.
####
#### PySide6 is imported only after the `desktop` extra has selected this entry
#### point.  Startup fails closed when the packaged QML root, Botan library, or
#### private service workspace is unavailable; it never enters the event loop
#### without a loaded root object.
####
def main(argv: Sequence[str] | None = None) -> int:
    from PySide6.QtCore import QStandardPaths
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine

    arguments = list(process_argv if argv is None else argv)
    qt_application = QGuiApplication(arguments)
    qt_application.setOrganizationName("Password Bonobo")
    qt_application.setApplicationName("Password Bonobo")

    engine = QQmlApplicationEngine()
    qml_url = resources.main_qml_url()
    if qml_url.isEmpty():
        return 1
    engine.load(qml_url)
    if not engine.rootObjects():
        return 1

    botan_library = _botan_library_path()
    if botan_library is None:
        return 1
    try:
        application_data_directory = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.AppLocalDataLocation
        )
        working_directory, recovery_directory = _private_directories(application_data_directory)
        service = VaultService.with_botan(botan_library, working_directory, recovery_directory)
    except Exception:
        return 1
    application = VaultApplication(service)
    try:
        return qt_application.exec()
    finally:
        _request_shutdown_lock(application)
        engine.deleteLater()
