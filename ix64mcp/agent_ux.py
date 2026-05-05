from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .context_budget import with_context_budget
from .malware import behavior_report, load_workspace_by_hash
from .patch import plan_patches
from .protocol import hex_address, parse_address
from .session import AnalysisSession, TimelineEvent


STRCMP_NAMES = ("strcmp", "strncmp", "stricmp", "strcmpi", "memcmp", "lstrcmp", "lstrcmpa", "lstrcmpw", "comparestring")


def current_location(session: AnalysisSession) -> dict[str, Any]:
    ida_ea = session.active_ida_ea
    runtime = session.active_runtime_address
    if ida_ea is None and runtime is not None:
        ida_ea = session.runtime_to_ida(runtime)
    if runtime is None and ida_ea is not None:
        runtime = session.ida_to_runtime(ida_ea)
    return {
        "ida_ea": hex_address(ida_ea),
        "runtime_address": hex_address(runtime),
        "has_location": ida_ea is not None or runtime is not None,
    }


def timeline_summary(events: list[TimelineEvent] | list[dict[str, Any]], limit: int | str | None = 200, profile: str | None = None) -> dict[str, Any]:
    bounded = max(1, min(int(limit or 200), 1000))
    selected = [_event_json(event) for event in events[-bounded:]]
    grouped: dict[str, dict[str, Any]] = {}
    address_counter: Counter[str] = Counter()
    api_counter: Counter[str] = Counter()
    for event in selected:
        payload = event.get("payload", {})
        key = f"{event.get('source')}:{event.get('type')}"
        item = grouped.setdefault(
            key,
            {
                "source": event.get("source"),
                "type": event.get("type"),
                "count": 0,
                "latest_timestamp": None,
                "sample_payload": {},
            },
        )
        item["count"] += 1
        item["latest_timestamp"] = event.get("timestamp")
        item["sample_payload"] = _small_payload(payload)
        for address in _payload_addresses(payload):
            address_counter[address] += 1
        for api in _payload_apis(payload):
            api_counter[api] += 1
    result = {
        "limit": bounded,
        "total_seen": len(selected),
        "groups": sorted(grouped.values(), key=lambda row: (-row["count"], str(row["type"]))),
        "hot_addresses": [{"address": address, "count": count} for address, count in address_counter.most_common(20)],
        "hot_apis": [{"api": api, "count": count} for api, count in api_counter.most_common(20)],
        "latest": [_small_payload(event) for event in selected[-10:]],
    }
    return with_context_budget(result, profile, next_resource="analysis://timeline?limit=N", recommended_followup="Increase limit/profile only when raw event context is required.")


def hot_functions(session: AnalysisSession, suggestions: list[dict[str, Any]], limit: int | str | None = 50) -> dict[str, Any]:
    bounded = max(1, min(int(limit or 50), 200))
    rows: dict[str, dict[str, Any]] = {}
    for event in session.timeline:
        payload = event.payload
        for address_text in _payload_addresses(payload):
            address = parse_address(address_text)
            ida_ea = session.runtime_to_ida(address) or address
            key = hex(ida_ea)
            item = rows.setdefault(key, {"ida_ea": key, "runtime_address": hex_address(session.ida_to_runtime(ida_ea)), "score": 0, "events": Counter()})
            item["score"] += 1
            item["events"][event.type] += 1
    for suggestion in suggestions:
        try:
            key = hex(parse_address(str(suggestion.get("target"))))
        except Exception:
            continue
        item = rows.setdefault(key, {"ida_ea": key, "runtime_address": hex_address(session.ida_to_runtime(parse_address(key))), "score": 0, "events": Counter()})
        item["score"] += 2
        item.setdefault("suggestions", []).append(suggestion)
    selected = sorted(rows.values(), key=lambda row: (-row["score"], row["ida_ea"]))[:bounded]
    for row in selected:
        row["events"] = dict(row["events"])
    return {"limit": bounded, "functions": selected}


def patch_reports(state_dir: Path, session: AnalysisSession, limit: int | str | None = 50) -> dict[str, Any]:
    bounded = max(1, min(int(limit or 50), 200))
    roots = []
    workspace = load_workspace_by_hash(state_dir, session.file_sha256)
    if workspace and workspace.get("workspace_dir"):
        roots.append(Path(workspace["workspace_dir"]))
    if session.file_path:
        roots.append(Path(session.file_path).resolve().parent)
    reports = []
    seen = set()
    for root in roots:
        if not root.exists():
            continue
        for path in root.glob("*.ix64patch.json"):
            if path in seen:
                continue
            seen.add(path)
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                report = {"path": str(path), "error": str(exc)}
            reports.append(report | {"report_path": str(path)})
            if len(reports) >= bounded:
                break
    plan: dict[str, Any] | None = None
    if session.file_path and Path(session.file_path).exists():
        try:
            plan = plan_patches(session.file_path, limit=min(bounded, 50))
        except Exception as exc:
            plan = {"error": str(exc), "path": session.file_path}
    return {"limit": bounded, "patch_plan": plan, "applied_reports": reports[:bounded]}


def analysis_report(state_dir: Path, session: AnalysisSession, suggestions: dict[str, Any], connected: dict[str, bool], profile: str | None = None) -> dict[str, Any]:
    workspace = load_workspace_by_hash(state_dir, session.file_sha256)
    result = {
        "current": {"session": session.summary(connected), "location": current_location(session)},
        "workspace": workspace or {},
        "timeline_summary": timeline_summary(session.timeline, 300, profile),
        "behavior": behavior_report(session, session.timeline, workspace),
        "suggestions": suggestions,
        "patches": patch_reports(state_dir, session, 50),
    }
    return with_context_budget(result, profile, next_resource="analysis://report?profile=deep", recommended_followup="Use deep/forensic profile only for report drafting or final review.")


def find_password_candidates(
    ida_strings: list[dict[str, Any]],
    patch_plan: dict[str, Any] | None,
    triage_result: dict[str, Any] | None,
    limit: int | str | None = 20,
) -> dict[str, Any]:
    bounded = max(1, min(int(limit or 20), 100))
    candidates = []
    password_words = ("pass", "password", "wrong", "correct", "valid", "invalid", "success", "fail", "denied", "accepted")
    for row in ida_strings:
        text = str(row.get("text") or row.get("value") or row.get("string") or "")
        if any(word in text.lower() for word in password_words):
            candidates.append({"source": "ida.string", "score": 80, "item": row, "reason": "password/success/failure-like string"})
    if patch_plan:
        for row in patch_plan.get("strings", [])[:bounded]:
            candidates.append({"source": "patch.string", "score": 70, "item": row, "reason": "patch planner found success/failure string"})
        for row in patch_plan.get("candidates", [])[:bounded]:
            candidates.append({"source": "patch.branch", "score": 60, "item": row, "reason": "nearby compare/conditional branch"})
    if triage_result:
        for row in triage_result.get("suspicious_strings", [])[:bounded]:
            text = str(row.get("text", ""))
            if any(word in text.lower() for word in password_words):
                candidates.append({"source": "triage.string", "score": 50, "item": row, "reason": "triage string resembles password check text"})
    return {"limit": bounded, "candidates": sorted(candidates, key=lambda row: -row["score"])[:bounded]}


def strcmp_imports(imports: dict[str, Any], limit: int | str | None = 20) -> list[dict[str, Any]]:
    bounded = max(1, min(int(limit or 20), 100))
    rows = []
    for item in imports.get("imports", []):
        name = str(item.get("name") or "").lower()
        if any(candidate in name for candidate in STRCMP_NAMES):
            rows.append(item)
            if len(rows) >= bounded:
                break
    return rows


def _event_json(event: TimelineEvent | dict[str, Any]) -> dict[str, Any]:
    return event.as_json() if isinstance(event, TimelineEvent) else event


def _small_payload(payload: Any) -> Any:
    if isinstance(payload, str):
        return payload[:200]
    if isinstance(payload, list):
        return [_small_payload(item) for item in payload[:5]]
    if isinstance(payload, dict):
        return {str(key)[:80]: _small_payload(value) for key, value in list(payload.items())[:12]}
    return payload


def _payload_addresses(payload: Any) -> list[str]:
    rows = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered = str(key).lower()
            if any(name in lowered for name in ("address", "ea", "rip", "eip", "cip")) and value is not None:
                try:
                    rows.append(hex(parse_address(str(value))))
                except Exception:
                    pass
            rows.extend(_payload_addresses(value))
    elif isinstance(payload, list):
        for item in payload[:100]:
            rows.extend(_payload_addresses(item))
    return rows


def _payload_apis(payload: Any) -> list[str]:
    rows = []
    if isinstance(payload, dict):
        for key in ("api", "name", "function"):
            if payload.get(key):
                rows.append(str(payload[key]))
        for value in payload.values():
            rows.extend(_payload_apis(value))
    elif isinstance(payload, list):
        for item in payload[:100]:
            rows.extend(_payload_apis(item))
    return rows
