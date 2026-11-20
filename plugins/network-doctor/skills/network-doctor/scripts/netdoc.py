#!/usr/bin/env python3
"""network-doctor CLI. Run `python3 netdoc.py --help`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netdoc.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
