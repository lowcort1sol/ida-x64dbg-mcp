from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_VERSION = "0.1"
SERVER_VERSION = "0.1.0"
DEFAULT_STATE_DIR = Path(__file__).resolve().parents[1] / "state"


@dataclass(frozen=True, slots=True)
class IX64Config:
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 8765
    state_dir: Path = DEFAULT_STATE_DIR
    token: str = ""

    @classmethod
    def from_env(cls) -> "IX64Config":
        state_dir = Path(os.environ.get("IX64MCP_STATE_DIR", str(DEFAULT_STATE_DIR))).expanduser()
        return cls(
            bridge_host=os.environ.get("IX64MCP_BRIDGE_HOST", "127.0.0.1"),
            bridge_port=int(os.environ.get("IX64MCP_BRIDGE_PORT", "8765")),
            state_dir=state_dir,
            token=os.environ.get("IX64MCP_TOKEN", ""),
        )

    @property
    def database_path(self) -> Path:
        return self.state_dir / "ix64mcp.sqlite3"

    @property
    def timeline_dir(self) -> Path:
        return self.state_dir / "timeline"
