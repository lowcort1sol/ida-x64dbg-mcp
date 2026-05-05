from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

SuggestionKind = Literal["name", "comment", "decompiler_comment", "type"]
SuggestionStatus = Literal["pending", "applied", "rejected"]


@dataclass(slots=True)
class Suggestion:
    kind: SuggestionKind
    target: str
    suggested_value: str
    reason: str = ""
    source: str = "codex"
    current_value: str | None = None
    status: SuggestionStatus = "pending"
    id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "current_value": self.current_value,
            "suggested_value": self.suggested_value,
            "reason": self.reason,
            "source": self.source,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def mark(self, status: SuggestionStatus) -> None:
        self.status = status
        self.updated_at = datetime.now(UTC).isoformat()


class SuggestionStore:
    def __init__(self) -> None:
        self._items: dict[str, Suggestion] = {}

    def add(self, suggestion: Suggestion) -> Suggestion:
        self._items[suggestion.id] = suggestion
        return suggestion

    def get(self, suggestion_id: str) -> Suggestion:
        try:
            return self._items[suggestion_id]
        except KeyError as exc:
            raise KeyError(f"suggestion not found: {suggestion_id}") from exc

    def list(self, status: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        bounded_limit = max(1, min(int(limit), 500))
        bounded_offset = max(0, int(offset))
        rows = list(self._items.values())
        if status:
            rows = [item for item in rows if item.status == status]
        rows.sort(key=lambda item: item.created_at)
        selected = rows[bounded_offset : bounded_offset + bounded_limit]
        return {
            "status": status,
            "offset": bounded_offset,
            "limit": bounded_limit,
            "total": len(rows),
            "suggestions": [item.as_json() for item in selected],
        }

    def restore(self, rows: list[dict[str, Any]]) -> None:
        self._items.clear()
        for row in rows:
            suggestion = Suggestion(
                id=str(row["id"]),
                kind=row["kind"],
                target=str(row["target"]),
                current_value=row.get("current_value"),
                suggested_value=str(row["suggested_value"]),
                reason=str(row.get("reason") or ""),
                source=str(row.get("source") or "codex"),
                status=row.get("status", "pending"),
                created_at=str(row["created_at"]),
                updated_at=row.get("updated_at"),
            )
            self._items[suggestion.id] = suggestion
