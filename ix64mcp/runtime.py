from __future__ import annotations

import atexit
import logging
import os
import signal
import socket
import subprocess
from pathlib import Path

import msvcrt


class SingleInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.pid_path = path.with_suffix(path.suffix + ".pid")
        self._handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a+", encoding="utf-8")
        try:
            msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self._handle.close()
            self._handle = None
            return False
        self._handle.seek(0)
        self._handle.truncate()
        self._handle.write(str(os.getpid()))
        self._handle.flush()
        self.pid_path.write_text(str(os.getpid()), encoding="utf-8")
        atexit.register(self.release)
        return True

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            self._handle.seek(0)
            self._handle.truncate()
            msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            self._handle.close()
            self._handle = None
            try:
                self.pid_path.unlink()
            except OSError:
                pass

    def read_pid(self) -> int | None:
        if self.pid_path.exists():
            try:
                raw = self.pid_path.read_text(encoding="utf-8").strip()
            except OSError:
                raw = ""
            if raw.isdigit():
                return int(raw)
        if not self.path.exists():
            return None
        try:
            raw = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not raw.isdigit():
            return None
        return int(raw)


def setup_logging(log_file: Path | None, level: str) -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def is_port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            sock.bind((host, port))
        except OSError:
            return True
        return False


def is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
        return f'"{pid}"' in result.stdout or f",{pid}," in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_process(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True, check=False)
        return result.returncode == 0
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def runtime_diagnostics(
    lock: SingleInstanceLock,
    bridge_host: str,
    bridge_port: int,
    api_host: str,
    api_port: int,
) -> dict[str, object]:
    pid = lock.read_pid()
    running = bool(pid and is_process_running(pid))
    bridge_busy = is_port_in_use(bridge_host, bridge_port)
    api_busy = is_port_in_use(api_host, api_port)
    issues: list[str] = []
    if bridge_busy and not running:
        issues.append("bridge port is busy but the lock PID is missing or not running")
    if api_busy and not running:
        issues.append("daemon API port is busy but the lock PID is missing or not running")
    if running and not bridge_busy:
        issues.append("lock PID is running but bridge port is not listening")
    if running and not api_busy:
        issues.append("lock PID is running but daemon API port is not listening; daemon may be legacy or partially started")
    return {
        "pid": pid,
        "running": running,
        "bridge": {"host": bridge_host, "port": bridge_port, "busy": bridge_busy},
        "api": {"host": api_host, "port": api_port, "busy": api_busy},
        "lock": {"path": str(lock.path), "pid_path": str(lock.pid_path)},
        "issues": issues,
        "ok": running and bridge_busy and api_busy and not issues,
    }
