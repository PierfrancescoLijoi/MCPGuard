from pathlib import Path

import pytest

from scripts.check_release import validate_release


def test_repository_release_metadata_matches_tag() -> None:
    root = Path(__file__).parents[1]
    pyproject = root / "pyproject.toml"
    version = validate_release(pyproject)
    assert validate_release(pyproject, f"v{version}") == version


def test_release_rejects_mismatched_tag(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    package_init = tmp_path / "__init__.py"
    pyproject.write_text('[project]\nname="mcpguard-ci"\nversion="1.2.3"\n')
    package_init.write_text('__version__ = "1.2.3"\n')
    with pytest.raises(ValueError, match="does not match"):
        validate_release(pyproject, "v1.2.4", package_init)


def test_release_rejects_mismatched_package_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    package_init = tmp_path / "__init__.py"
    pyproject.write_text('[project]\nname="mcpguard-ci"\nversion="1.2.3"\n')
    package_init.write_text('__version__ = "1.2.2"\n')

    with pytest.raises(ValueError, match="package version.*does not match"):
        validate_release(pyproject, "v1.2.3", package_init)
