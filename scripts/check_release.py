"""Validate release metadata before publishing."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path


def validate_release(
    pyproject: Path,
    tag: str | None = None,
    package_init: Path | None = None,
) -> str:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data["project"]
    name = str(project["name"])
    version = str(project["version"])
    if name != "mcpguard-ci":
        raise ValueError("distribution name must be mcpguard-ci")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("version must be a stable X.Y.Z release")
    init_path = package_init or pyproject.parent / "mcpguard" / "__init__.py"
    init_source = init_path.read_text(encoding="utf-8")
    match = re.search(
        r'^__version__\s*=\s*["\']([^"\']+)["\']',
        init_source,
        re.MULTILINE,
    )
    if match is None:
        raise ValueError(f"package version is missing from {init_path}")
    if match.group(1) != version:
        raise ValueError(
            f"package version {match.group(1)!r} does not match "
            f"project version {version!r}"
        )
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} does not match version v{version}")
    return version


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--tag")
    args = parser.parse_args()
    version = validate_release(args.pyproject, args.tag)
    print(f"release metadata valid: mcpguard-ci {version}")


if __name__ == "__main__":
    main()
