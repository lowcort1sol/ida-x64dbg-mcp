from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any

from .protocol import parse_address
from .session import AnalysisSession, TimelineEvent


class SessionStore:
    def __init__(self, database_path: Path, timeline_dir: Path) -> None:
        self.database_path = database_path
        self.timeline_dir = timeline_dir
        self._lock = Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeline_dir.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with sqlite3.connect(self.database_path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    sample_id TEXT,
                    source TEXT NOT NULL,
                    type TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    sample_id TEXT PRIMARY KEY,
                    file_path TEXT,
                    file_sha256 TEXT,
                    architecture TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    sample_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    ida_base INTEGER NOT NULL,
                    runtime_base INTEGER NOT NULL,
                    size INTEGER,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(sample_id, name)
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS breakpoints (
                    sample_id TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(sample_id, address)
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS suggestions (
                    id TEXT PRIMARY KEY,
                    sample_id TEXT,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    current_value TEXT,
                    suggested_value TEXT NOT NULL,
                    reason TEXT,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
                """
            )

    def attach(self, session: AnalysisSession) -> None:
        session.event_sinks.append(self.record_event)

    def record_session(self, session: AnalysisSession) -> None:
        if not session.sample_id:
            return
        with self._lock, sqlite3.connect(self.database_path) as db:
            db.execute(
                """
                INSERT INTO sessions(sample_id, file_path, file_sha256, architecture, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(sample_id) DO UPDATE SET
                    file_path=excluded.file_path,
                    file_sha256=excluded.file_sha256,
                    architecture=excluded.architecture,
                    updated_at=excluded.updated_at
                """,
                (session.sample_id, session.file_path, session.file_sha256, session.architecture),
            )
            self._record_snapshot_locked(db, session)

    def record_event(self, event: TimelineEvent, session: AnalysisSession) -> None:
        event_json = event.as_json()
        payload_json = json.dumps(event.payload, sort_keys=True)
        with self._lock:
            with sqlite3.connect(self.database_path) as db:
                db.execute(
                    """
                    INSERT INTO events(timestamp, sample_id, source, type, payload_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (event.timestamp, session.sample_id, event.source, event.type, payload_json),
                )
            with self._timeline_path(session).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event_json, sort_keys=True) + "\n")
        if session.sample_id:
            self.record_session(session)

    def restore_session(self, session: AnalysisSession, sample_id: str | None = None, file_sha256: str | None = None) -> bool:
        with self._lock, sqlite3.connect(self.database_path) as db:
            row = None
            if sample_id:
                row = db.execute(
                    """
                    SELECT sample_id, file_path, file_sha256, architecture
                    FROM sessions
                    WHERE sample_id = ?
                    """,
                    (sample_id,),
                ).fetchone()
            if row is None and file_sha256:
                row = db.execute(
                    """
                    SELECT sample_id, file_path, file_sha256, architecture
                    FROM sessions
                    WHERE file_sha256 = ?
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (file_sha256,),
                ).fetchone()
            if row is None:
                row = db.execute(
                    """
                    SELECT sample_id, file_path, file_sha256, architecture
                    FROM sessions
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """
                ).fetchone()
            if row is None:
                return False
            session.sample_id, session.file_path, session.file_sha256, session.architecture = row
            mappings = db.execute(
                """
                SELECT name, ida_base, runtime_base, size
                FROM mappings
                WHERE sample_id = ?
                ORDER BY name
                """,
                (session.sample_id,),
            ).fetchall()
            breakpoints = db.execute(
                """
                SELECT address
                FROM breakpoints
                WHERE sample_id = ? AND enabled = 1
                ORDER BY address
                """,
                (session.sample_id,),
            ).fetchall()
        session.mappings.clear()
        for name, ida_base, runtime_base, size in mappings:
            session.upsert_mapping(str(name), ida_base=int(ida_base), runtime_base=int(runtime_base), size=None if size is None else int(size))
        session.breakpoints = {parse_address(row[0]) for row in breakpoints}
        return True

    def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 200))
        with self._lock, sqlite3.connect(self.database_path) as db:
            rows = db.execute(
                """
                SELECT sample_id, file_path, file_sha256, architecture, updated_at
                FROM sessions
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
        return [
            {
                "sample_id": row[0],
                "file_path": row[1],
                "file_sha256": row[2],
                "architecture": row[3],
                "updated_at": row[4],
            }
            for row in rows
        ]

    def latest_events(self, limit: int = 200, sample_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self.database_path) as db:
            if sample_id:
                rows = db.execute(
                    """
                    SELECT timestamp, sample_id, source, type, payload_json
                    FROM events
                    WHERE sample_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (sample_id, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    """
                    SELECT timestamp, sample_id, source, type, payload_json
                    FROM events
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [
            {
                "timestamp": row[0],
                "sample_id": row[1],
                "source": row[2],
                "type": row[3],
                "payload": json.loads(row[4]),
            }
            for row in reversed(rows)
        ]

    def record_suggestion(self, session: AnalysisSession, suggestion: dict[str, Any]) -> None:
        with self._lock, sqlite3.connect(self.database_path) as db:
            db.execute(
                """
                INSERT INTO suggestions(
                    id, sample_id, kind, target, current_value, suggested_value,
                    reason, source, status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    sample_id=excluded.sample_id,
                    kind=excluded.kind,
                    target=excluded.target,
                    current_value=excluded.current_value,
                    suggested_value=excluded.suggested_value,
                    reason=excluded.reason,
                    source=excluded.source,
                    status=excluded.status,
                    updated_at=excluded.updated_at
                """,
                (
                    suggestion["id"],
                    session.sample_id,
                    suggestion["kind"],
                    suggestion["target"],
                    suggestion.get("current_value"),
                    suggestion["suggested_value"],
                    suggestion.get("reason"),
                    suggestion.get("source", "codex"),
                    suggestion["status"],
                    suggestion["created_at"],
                    suggestion.get("updated_at"),
                ),
            )

    def load_suggestions(self, sample_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self.database_path) as db:
            if sample_id:
                rows = db.execute(
                    """
                    SELECT id, kind, target, current_value, suggested_value, reason, source, status, created_at, updated_at
                    FROM suggestions
                    WHERE sample_id = ?
                    ORDER BY created_at
                    """,
                    (sample_id,),
                ).fetchall()
            else:
                rows = db.execute(
                    """
                    SELECT id, kind, target, current_value, suggested_value, reason, source, status, created_at, updated_at
                    FROM suggestions
                    ORDER BY created_at
                    """
                ).fetchall()
        return [
            {
                "id": row[0],
                "kind": row[1],
                "target": row[2],
                "current_value": row[3],
                "suggested_value": row[4],
                "reason": row[5],
                "source": row[6],
                "status": row[7],
                "created_at": row[8],
                "updated_at": row[9],
            }
            for row in rows
        ]

    def _timeline_path(self, session: AnalysisSession) -> Path:
        name = session.sample_id or session.file_sha256 or "default"
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        return self.timeline_dir / f"{safe}.jsonl"

    def _record_snapshot_locked(self, db: sqlite3.Connection, session: AnalysisSession) -> None:
        if not session.sample_id:
            return
        db.execute("DELETE FROM mappings WHERE sample_id = ?", (session.sample_id,))
        db.execute("DELETE FROM breakpoints WHERE sample_id = ?", (session.sample_id,))
        db.executemany(
            """
            INSERT INTO mappings(sample_id, name, ida_base, runtime_base, size, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            [
                (session.sample_id, mapping.name, mapping.ida_base, mapping.runtime_base, mapping.size)
                for mapping in session.mappings
            ],
        )
        db.executemany(
            """
            INSERT INTO breakpoints(sample_id, address, enabled, updated_at)
            VALUES (?, ?, 1, datetime('now'))
            """,
            [(session.sample_id, address) for address in sorted(session.breakpoints)],
        )
