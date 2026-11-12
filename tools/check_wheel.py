#!/usr/bin/env python3
"""Release checks the workflows run.

    python tools/check_wheel.py dist/disconet_collector-0.2.0-py3-none-any.whl
    python tools/check_wheel.py --tag v0.2.0

The first checks that a wheel holds the allowlist and neither the tests nor
the tools. The second checks that a tag names the version in
netstate/__init__.py, so a tag cannot publish a version the package does not
report. Exit 0 when the check holds, 1 when it does not.
"""

from __future__ import annotations

import ast
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def package_version() -> str:
    tree = ast.parse((ROOT / "netstate" / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "__version__" for t in node.targets):
            return node.value.value
    raise SystemExit("netstate/__init__.py sets no __version__")


def wheel_problems(path: Path) -> list[str]:
    names = zipfile.ZipFile(path).namelist()
    problems = []
    if "netstate/commands.yaml" not in names:
        problems.append("the allowlist netstate/commands.yaml is missing")
    if "netstate/cli.py" not in names:
        problems.append("netstate/cli.py is missing")
    stray = [name for name in names if name.startswith(("tests/", "tools/"))]
    if stray:
        problems.append(f"tests or tools in the wheel: {', '.join(stray[:5])}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--tag":
        expected = f"v{package_version()}"
        if argv[1] != expected:
            print(f"tag {argv[1]} does not name the package's version; expected {expected}")
            return 1
        print(f"tag {argv[1]} names version {package_version()}")
        return 0
    if not argv:
        print(__doc__)
        return 1
    failed = 0
    for name in argv:
        problems = wheel_problems(Path(name))
        for problem in problems:
            print(f"{name}: {problem}")
        failed |= bool(problems)
        if not problems:
            print(f"{name}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
