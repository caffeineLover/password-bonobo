"""Provide the executable source wrapper consumed by native PySide deployment.

The wrapper uses an absolute package import so direct script execution and the
deployment analyzer resolve the same lazy, core-safe desktop entry boundary.
"""

from bonobo_desktop.main import main



# Return the desktop composition status when the deployment input runs directly.
if __name__ == "__main__":
    raise SystemExit(main())
