from __future__ import annotations

import asyncio
import json
from pathlib import PureWindowsPath
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import websockets
from websockets.exceptions import ConnectionClosed
from websockets.server import WebSocketServerProtocol

from .protocol import BridgeRole, RpcRequest, parse_address
from .session import AnalysisSession
from .config import PROTOCOL_VERSION


def _module_key(value: str | None) -> str:
    if not value:
        return ""
    name = PureWindowsPath(value).name.lower()
    for suffix in (".exe", ".dll", ".sys"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


@dataclass(slots=True)
class BridgeClient:
    role: BridgeRole
    websocket: WebSocketServerProtocol
    protocol_version: str = ""
    bridge_version: str = ""
    capabilities: list[str] = field(default_factory=list)
    connected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    pending: dict[str, asyncio.Future[dict[str, Any]]] = field(default_factory=dict)


class BridgeRegistry:
    def __init__(self, session: AnalysisSession, token: str = "") -> None:
        self.session = session
        self.token = token
        self.clients: dict[BridgeRole, BridgeClient] = {}
        self._lock = asyncio.Lock()

    def connected(self) -> dict[str, bool]:
        return {
            "ida": "ida" in self.clients,
            "x64dbg": "x64dbg" in self.clients,
        }

    async def serve(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        async with websockets.serve(self._handle_socket, host, port, ping_interval=None):
            await asyncio.Future()

    async def request(self, role: BridgeRole, method: str, params: dict[str, Any] | None = None) -> Any:
        client = self.clients.get(role)
        if client is None:
            raise RuntimeError(f"{role} bridge is not connected")

        request = RpcRequest(method=method, params=params or {}, id=uuid4().hex)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        client.pending[request.id] = future
        await client.websocket.send(json.dumps(request.as_json()))
        response = await asyncio.wait_for(future, timeout=10)
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        return response.get("result")

    async def _handle_socket(self, websocket: WebSocketServerProtocol) -> None:
        role: BridgeRole | None = None
        try:
            hello = json.loads(await websocket.recv())
            if hello.get("method") != "hello":
                await websocket.close(code=1002, reason="first message must be hello")
                return
            params = hello.get("params", {})
            role = params.get("role")
            if role not in ("ida", "x64dbg"):
                await websocket.close(code=1002, reason="unknown role")
                return
            if not self._token_valid(params.get("token")):
                await websocket.close(code=1008, reason="invalid IX64MCP token")
                return
            protocol_version = str(params.get("protocol_version", ""))
            if protocol_version and protocol_version != PROTOCOL_VERSION:
                self.session.add_event(
                    "bridge.protocol_mismatch",
                    str(role),
                    {"bridge_protocol": protocol_version, "server_protocol": PROTOCOL_VERSION},
                )
            client = BridgeClient(
                role=role,
                websocket=websocket,
                protocol_version=protocol_version,
                bridge_version=str(params.get("bridge_version", "")),
                capabilities=[str(value) for value in params.get("capabilities", []) if isinstance(value, str)],
            )
            async with self._lock:
                replaced = role in self.clients
                self.clients[role] = client
                self.session.merge_hello(
                    role,
                    params.get("session", {}),
                    metadata={
                        "protocol_version": client.protocol_version,
                        "bridge_version": client.bridge_version,
                        "capabilities": client.capabilities,
                        "connected_at": client.connected_at,
                        "reconnected": replaced,
                    },
                )
                if role == "ida":
                    self._promote_sample_mapping()
            await websocket.send(json.dumps({"jsonrpc": "2.0", "id": hello.get("id"), "result": {"ok": True}}))
            recovery_task = asyncio.create_task(self._recover_client(role))

            try:
                async for raw_message in websocket:
                    try:
                        await self._handle_message(client, json.loads(raw_message))
                    except json.JSONDecodeError as exc:
                        self.session.add_event("bridge.invalid_json", role, {"error": str(exc)})
                    except Exception as exc:
                        self.session.add_event("bridge.message_error", role, {"error": str(exc)})
            except ConnectionClosed:
                pass
            finally:
                recovery_task.cancel()
        finally:
            if role is not None and self.clients.get(role, None) is not None:
                current = self.clients.get(role)
                if current is not None and current.websocket is websocket:
                    for future in current.pending.values():
                        if not future.done():
                            future.set_exception(RuntimeError(f"{role} bridge disconnected"))
                    current.pending.clear()
                    self.clients.pop(role, None)
                    self.session.add_event("bridge.disconnected", role, {})

    def _token_valid(self, token: Any) -> bool:
        if not self.token:
            return True
        return isinstance(token, str) and token == self.token

    async def _recover_client(self, role: BridgeRole) -> None:
        if role != "x64dbg" or not self.session.breakpoints:
            return
        restored: list[str] = []
        for address in sorted(self.session.breakpoints):
            try:
                await self.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(address)})
                restored.append(hex(address))
            except Exception as exc:
                self.session.add_event(
                    "bridge.recovery_error",
                    role,
                    {"action": "restore_breakpoint", "address": hex(address), "error": str(exc)},
                )
        if restored:
            self.session.add_event("bridge.recovered", role, {"breakpoints": restored})

    def _promote_sample_mapping(self) -> None:
        sample_key = _module_key(self.session.file_path or self.session.sample_id)
        main = self.session.mapping_by_name("main")
        if not sample_key or main is None:
            return
        for mapping in self.session.mappings:
            if mapping.name == "main":
                continue
            if _module_key(mapping.name) == sample_key:
                main.runtime_base = mapping.runtime_base
                main.size = mapping.size
                self.session.add_event(
                    "analysis.mapping_promoted",
                    "bridge",
                    {
                        "module": mapping.name,
                        "ida_base": hex(main.ida_base),
                        "runtime_base": hex(main.runtime_base),
                    },
                )
                return

    def _mapping_by_module_key(self, name: str):
        key = _module_key(name)
        for mapping in self.session.mappings:
            if _module_key(mapping.name) == key:
                return mapping
        return None

    async def _handle_message(self, client: BridgeClient, message: dict[str, Any]) -> None:
        if "id" in message and ("result" in message or "error" in message):
            future = client.pending.pop(str(message["id"]), None)
            if future is not None and not future.done():
                future.set_result(message)
            return

        method = message.get("method")
        params = message.get("params", {})
        if not isinstance(params, dict):
            params = {}
        if method == "event":
            self._apply_event(client.role, params)

    def _apply_event(self, role: BridgeRole, params: dict[str, Any]) -> None:
        event_type = str(params.get("type", "unknown"))
        payload = params.get("payload", {})
        if not isinstance(payload, dict):
            payload = {"value": payload}

        if event_type in {
            "cursor.changed",
            "ida.cursor.changed",
            "function.renamed",
            "comment.changed",
            "ida.name.changed",
            "ida.comment.changed",
            "ida.function.created",
            "ida.function.updated",
            "ida.function.deleted",
        } and payload.get("ea") is not None:
            ea = parse_address(payload["ea"])
            self.session.active_ida_ea = ea
            if event_type in {"function.renamed", "ida.name.changed"} and payload.get("name"):
                self.session.names[ea] = str(payload["name"])
            if event_type in {"comment.changed", "ida.comment.changed"} and payload.get("text") is not None:
                self.session.comments[ea] = str(payload["text"])

        if event_type in {"debug.paused", "step", "breakpoint.hit", "breakpoint.hit.snapshot"} and payload.get("address") is not None:
            address = parse_address(payload["address"])
            self.session.active_runtime_address = address
            mapped = self.session.runtime_to_ida(address)
            if mapped is not None:
                self.session.active_ida_ea = mapped
                payload = {**payload, "ida_ea": hex(mapped)}
            if isinstance(payload.get("registers"), dict):
                self.session.registers = payload["registers"]
        if event_type == "module.loaded":
            name = str(payload.get("name", "module"))
            runtime_base = parse_address(payload["runtime_base"])
            existing_main = self.session.mapping_by_name("main")
            is_main = bool(payload.get("main"))
            if payload.get("ida_base") is not None:
                ida_base = parse_address(payload["ida_base"])
            elif is_main and existing_main is not None:
                ida_base = existing_main.ida_base
            elif is_main and payload.get("image_base") is not None:
                ida_base = parse_address(payload["image_base"])
            else:
                ida_base = runtime_base
            size = parse_address(payload["size"]) if payload.get("size") is not None else None
            if size is not None and size <= 0x1000:
                size = None
            sample_key = _module_key(self.session.file_path or self.session.sample_id)
            is_sample_module = bool(sample_key and _module_key(name) == sample_key)
            mapping_name = "main" if is_main or is_sample_module else name
            if is_sample_module and existing_main is not None:
                ida_base = existing_main.ida_base
            existing = self.session.mapping_by_name(mapping_name) or self._mapping_by_module_key(mapping_name)
            if existing is not None and existing.runtime_base == runtime_base and existing.size == size:
                return
            if existing is not None and mapping_name != "main":
                mapping_name = existing.name
            self.session.upsert_mapping(mapping_name, ida_base=ida_base, runtime_base=runtime_base, size=size)
        if event_type == "module.unloaded" and payload.get("runtime_base") is not None:
            runtime_base = parse_address(payload["runtime_base"])
            self.session.mappings = [mapping for mapping in self.session.mappings if mapping.runtime_base != runtime_base]

        self.session.add_event(event_type, role, payload)
