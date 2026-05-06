from __future__ import annotations

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_NAMES = [
    "install.ps1",
    "install-ida-plugin.ps1",
    "install-x64dbg-plugin.ps1",
    "build-x64dbg-plugin.ps1",
    "doctor.ps1",
]


def test_install_scripts_exist() -> None:
    for name in SCRIPT_NAMES:
        assert (REPO_ROOT / "scripts" / name).is_file()


def test_install_scripts_are_powershell_parse_valid() -> None:
    for name in SCRIPT_NAMES:
        path = REPO_ROOT / "scripts" / name
        command = f"$null = [scriptblock]::Create((Get-Content -Raw -LiteralPath '{path}'))"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"{name} failed to parse: {result.stderr}"


def test_readme_uses_public_install_paths() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Fast Install" in text
    assert "C:\\Users\\" not in text
    assert "giornodjawana" not in text
    assert "GitHub Releases" in text
    assert "scripts\\install.ps1" in text


def test_gitignore_excludes_local_reverse_engineering_artifacts() -> None:
    text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")

    for pattern in [
        ".venv/",
        "state/",
        "release/",
        "dist/",
        "build/",
        "IDA PRO 9.1/",
        "*.dmp",
        "*.sqlite3",
        "*.jsonl",
        "*.i64",
        "*.idb",
        "*.dp64",
    ]:
        assert pattern in text
