#!/usr/bin/env bash
# Regenerate constraints/py<version>.txt: every package a clean install of the
# Collector resolves to, pinned exactly, one file per supported Python. Run it
# on Linux (pyATS has no Windows wheels) from the repository root, with
# python3.11 and python3.12 on PATH:
#
#     tools/lock_dependencies.sh            # both versions
#     tools/lock_dependencies.sh 3.12       # one
#
# Each run builds a throwaway venv, installs from pyproject.toml's ranges
# without the old constraints, and writes what pip resolved. Commit the
# result only once the offline suite passes on it:
#
#     pip install -c constraints/py3.12.txt -e .
#     python -m unittest discover -s tests -t .
#
# pip, setuptools and wheel are left out: they are the installer, not the
# Collector's dependencies, and CI upgrades them before installing.
set -euo pipefail

cd "$(dirname "$0")/.."
versions=("$@")
[ ${#versions[@]} -eq 0 ] && versions=(3.11 3.12)
mkdir -p constraints

for version in "${versions[@]}"; do
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    "python${version}" -m venv "$work/venv"
    "$work/venv/bin/python" -m pip install --quiet --upgrade pip setuptools wheel
    "$work/venv/bin/python" -m pip install --quiet -e .
    out="constraints/py${version}.txt"
    {
        echo "# Exact dependency set for the Collector on Python ${version} (Linux), as resolved"
        echo "# from pyproject.toml's ranges by a clean install of '.'."
        echo "# Install with:  pip install -c ${out} -e ."
        echo "# Regenerate with: tools/lock_dependencies.sh ${version}  (see the header there)"
        "$work/venv/bin/python" -m pip freeze --exclude-editable --all \
            | grep -viE '^(pip|setuptools|wheel)==' \
            | LC_ALL=C sort -f
    } > "$out"
    rm -rf "$work"
    trap - EXIT
    echo "wrote $out ($(grep -vc '^#' "$out") packages)"
done
