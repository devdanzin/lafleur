#!/usr/bin/env python3
import re
from pathlib import Path
import sys


def bump_version(new_version):
    # Update pyproject.toml
    pyproject = Path("pyproject.toml")
    content = pyproject.read_text()
    content = re.sub(r'^version = ".+"$', f'version = "{new_version}"', content, flags=re.MULTILINE)
    pyproject.write_text(content)

    # Optionally, update __init__.py if version is stored there
    init_file = Path("lafleur/__init__.py")
    if init_file.exists():
        content = init_file.read_text()
        content = re.sub(r'__version__ = "[^"]+"', f'__version__ = "{new_version}"', content)
        init_file.write_text(content)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <new_version>")
        sys.exit(1)
    bump_version(sys.argv[1])
