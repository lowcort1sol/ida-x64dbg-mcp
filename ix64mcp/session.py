from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable

from .protocol import BridgeRole, hex_address, parse_address


@dataclass(slots=True)
class ModuleMapping:
    name: str
    ida_base: int
    runtime_base: int
    size: int | None = None

    def contains_runtime(self, address: int) -> bool:
        if address < self.runtime_base:
            return False
        return self.size is None or address < self.runtime_base + self.size

    def contains_ida(self, address: int) -> bool:
        if address < self.ida_base:
            return False
        return self.size is None or address < self.ida_base + self.size


@dataclass(slots=True)
class TimelineEvent:
    type: str
    source: str
    payload: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "type": self.type,
            "payload": self.payload,
        }


@dataclass(slots=True)
class AnalysisSession:
    sample_id: str | None = None
    file_path: str | None = None
    file_sha256: str | None = None
    architecture: str | None = None
    active_ida_ea: int | None = None
    active_runtime_address: int | None = None
    registers: dict[str, Any] = field(default_factory=dict)
    breakpoints: set[int] = field(default_factory=set)
    names: dict[int, str] = field(default_factory=dict)
    comments: dict[int, str] = field(default_factory=dict)
    mappings: list[ModuleMapping] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    event_sinks: list[Callable[[TimelineEvent, "AnalysisSession"], None]] = field(default_factory=list, repr=False)

    def merge_hello(self, role: BridgeRole, session: dict[str, Any], metadata: dict[str, Any] | None = None) -> None:
        self.sample_id = session.get("sample_id", self.sample_id)
        self.file_path = session.get("file_path", self.file_path)
        self.file_sha256 = session.get("file_sha256", self.file_sha256)
        self.architecture = session.get("architecture", self.architecture)
        if role == "ida" and session.get("image_base") is not None:
            ida_base = parse_address(session["image_base"])
            main = self.mapping_by_name("main")
            if main is None:
                self.upsert_mapping("main", ida_base=ida_base, runtime_base=ida_base)
            else:
                main.ida_base = ida_base
        payload: dict[str, Any] = {"session": session}
        if metadata:
            payload["metadata"] = metadata
        self.add_event("bridge.connected", role, payload)

    def upsert_mapping(
        self,
        name: str,
        ida_base: int,
        runtime_base: int,
        size: int | None = None,
    ) -> ModuleMapping:
        lowered = name.lower()
        for mapping in self.mappings:
            if mapping.name.lower() == lowered:
                mapping.ida_base = ida_base
                mapping.runtime_base = runtime_base
                mapping.size = size
                return mapping
        mapping = ModuleMapping(name=name, ida_base=ida_base, runtime_base=runtime_base, size=size)
        self.mappings.append(mapping)
        return mapping

    def mapping_by_name(self, name: str) -> ModuleMapping | None:
        lowered = name.lower()
        for mapping in self.mappings:
            if mapping.name.lower() == lowered:
                return mapping
        return None

    def runtime_to_ida(self, address: int) -> int | None:
        best = self._best_runtime_mapping(address)
        if best is None:
            return None
        return best.ida_base + (address - best.runtime_base)

    def ida_to_runtime(self, address: int) -> int | None:
        best = self._best_ida_mapping(address)
        if best is None:
            return None
        return best.runtime_base + (address - best.ida_base)

    def add_event(self, event_type: str, source: str, payload: dict[str, Any]) -> TimelineEvent:
        event = TimelineEvent(type=event_type, source=source, payload=payload)
        self.timeline.append(event)
        for sink in list(self.event_sinks):
            sink(event, self)
        return event

    def summary(self, connected: dict[str, bool]) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "file_path": self.file_path,
            "file_sha256": self.file_sha256,
            "architecture": self.architecture,
            "connected": connected,
            "active_ida_ea": hex_address(self.active_ida_ea),
            "active_runtime_address": hex_address(self.active_runtime_address),
            "breakpoints": [hex_address(value) for value in sorted(self.breakpoints)],
            "mappings": [
                {
                    "name": mapping.name,
                    "ida_base": hex_address(mapping.ida_base),
                    "runtime_base": hex_address(mapping.runtime_base),
                    "size": None if mapping.size is None else hex(mapping.size),
                }
                for mapping in self.mappings
            ],
            "timeline_events": len(self.timeline),
        }

    def _best_runtime_mapping(self, address: int) -> ModuleMapping | None:
        candidates = [mapping for mapping in self.mappings if mapping.contains_runtime(address)]
        if not candidates:
            return None
        return max(candidates, key=lambda mapping: mapping.runtime_base)

    def _best_ida_mapping(self, address: int) -> ModuleMapping | None:
        candidates = [mapping for mapping in self.mappings if mapping.contains_ida(address)]
        if not candidates:
            return None
        return max(candidates, key=lambda mapping: mapping.ida_base)
