import json
import sqlite3

from ix64mcp.session import AnalysisSession
from ix64mcp.store import SessionStore


def test_store_persists_events_to_sqlite_and_jsonl(tmp_path) -> None:
    store = SessionStore(tmp_path / "ix64mcp.sqlite3", tmp_path / "timeline")
    session = AnalysisSession(sample_id="sample.exe")
    store.attach(session)

    session.add_event("analysis.note", "codex", {"address": "0x401000", "text": "entry"})

    with sqlite3.connect(tmp_path / "ix64mcp.sqlite3") as db:
        rows = db.execute("SELECT source, type, payload_json FROM events").fetchall()
    assert rows == [("codex", "analysis.note", '{"address": "0x401000", "text": "entry"}')]

    lines = (tmp_path / "timeline" / "sample.exe.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["type"] == "analysis.note"


def test_store_restores_latest_mapping_and_breakpoints(tmp_path) -> None:
    store = SessionStore(tmp_path / "ix64mcp.sqlite3", tmp_path / "timeline")
    session = AnalysisSession(sample_id="sample.exe", file_path="C:/samples/sample.exe", architecture="x64")
    store.attach(session)
    session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    session.breakpoints.add(0x7FF700001000)
    session.add_event("analysis.snapshot", "test", {})

    restored = AnalysisSession()
    assert store.restore_session(restored)
    assert restored.sample_id == "sample.exe"
    assert restored.mapping_by_name("main").runtime_base == 0x7FF700000000
    assert restored.breakpoints == {0x7FF700001000}


def test_store_persists_suggestions(tmp_path) -> None:
    store = SessionStore(tmp_path / "ix64mcp.sqlite3", tmp_path / "timeline")
    session = AnalysisSession(sample_id="sample.exe")
    suggestion = {
        "id": "s1",
        "kind": "name",
        "target": "0x140001000",
        "current_value": None,
        "suggested_value": "check_password",
        "reason": "compares input",
        "source": "codex",
        "status": "pending",
        "created_at": "2026-05-02T00:00:00+00:00",
        "updated_at": None,
    }

    store.record_suggestion(session, suggestion)

    assert store.load_suggestions("sample.exe") == [suggestion]
