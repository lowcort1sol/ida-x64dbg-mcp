from __future__ import annotations

import json
from copy import deepcopy
from typing import Any


PROFILES: dict[str, dict[str, int]] = {
    "quick": {"max_bytes": 12_000, "max_events": 50, "max_items": 25, "max_string": 300},
    "compact": {"max_bytes": 32_000, "max_events": 150, "max_items": 75, "max_string": 700},
    "deep": {"max_bytes": 96_000, "max_events": 500, "max_items": 200, "max_string": 2_000},
    "forensic": {"max_bytes": 256_000, "max_events": 1_000, "max_items": 500, "max_string": 4_000},
}


def profile_limits(profile: str | None = None) -> dict[str, int | str]:
    name = (profile or "compact").strip().lower()
    if name not in PROFILES:
        name = "compact"
    return {"profile": name, **PROFILES[name]}


def with_context_budget(
    value: dict[str, Any],
    profile: str | None = None,
    next_resource: str | None = None,
    recommended_followup: str | None = None,
) -> dict[str, Any]:
    limits = profile_limits(profile)
    body = _cap(deepcopy(value), limits)
    encoded = json.dumps(body, sort_keys=True, default=str)
    truncated = False
    if len(encoded.encode("utf-8")) > int(limits["max_bytes"]):
        body = _coarse_cap(body, limits)
        encoded = json.dumps(body, sort_keys=True, default=str)
        truncated = True
    budget = {
        "profile": limits["profile"],
        "estimated_bytes": len(encoded.encode("utf-8")),
        "max_bytes": limits["max_bytes"],
        "truncated": truncated,
        "next_resource": next_resource,
        "recommended_followup": recommended_followup,
    }
    if isinstance(body, dict):
        body["context_budget"] = budget
        return body
    return {"value": body, "context_budget": budget}


def _cap(value: Any, limits: dict[str, int | str]) -> Any:
    max_items = int(limits["max_items"])
    max_events = int(limits["max_events"])
    max_string = int(limits["max_string"])
    if isinstance(value, str):
        return value[:max_string] + ("..." if len(value) > max_string else "")
    if isinstance(value, list):
        capped = [_cap(item, limits) for item in value[:max_items]]
        if len(value) > max_items:
            capped.append({"truncated_items": len(value) - max_items})
        return capped
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in {"timeline", "timeline_tail", "latest"} and isinstance(item, list):
                result[key] = [_cap(row, limits) for row in item[-max_events:]]
                if len(item) > max_events:
                    result[f"{key}_truncated"] = len(item) - max_events
            else:
                result[key] = _cap(item, limits)
        return result
    return value


def _coarse_cap(value: Any, limits: dict[str, int | str]) -> Any:
    coarse_limits = dict(limits)
    coarse_limits["max_items"] = max(10, int(limits["max_items"]) // 2)
    coarse_limits["max_events"] = max(20, int(limits["max_events"]) // 2)
    coarse_limits["max_string"] = max(160, int(limits["max_string"]) // 2)
    return _cap(value, coarse_limits)
