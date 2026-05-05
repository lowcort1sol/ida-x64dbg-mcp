from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import uuid4

BridgeRole = Literal["ida", "x64dbg"]


def parse_address(value: int | str) -> int:
    if isinstance(value, int):
        return value
    text = value.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 0)


def hex_address(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


@dataclass(slots=True)
class RpcRequest:
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex)

    def as_json(self) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": self.id,
            "method": self.method,
            "params": self.params,
        }


@dataclass(slots=True)
class BridgeHello:
    role: BridgeRole
    session: dict[str, Any] = field(default_factory=dict)

