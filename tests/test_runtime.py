from __future__ import annotations

import os
from pathlib import Path

from ix64mcp.runtime import SingleInstanceLock, is_process_running, runtime_diagnostics


def test_is_process_running_detects_current_process() -> None:
    assert is_process_running(os.getpid()) is True


def test_is_process_running_rejects_invalid_pid() -> None:
    assert is_process_running(-1) is False


def test_runtime_diagnostics_reports_stopped_daemon(tmp_path: Path) -> None:
    lock = SingleInstanceLock(tmp_path / "ix64mcp.server.lock")

    result = runtime_diagnostics(lock, "127.0.0.1", 1, "127.0.0.1", 2)

    assert result["running"] is False
    assert result["ok"] is False
    assert result["bridge"]["busy"] is False
    assert result["api"]["busy"] is False
