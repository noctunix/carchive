"""Entry point for `python -m carchive`."""

from __future__ import annotations

import sys

from carchive.cli import main

if __name__ == "__main__":
    sys.exit(main())
