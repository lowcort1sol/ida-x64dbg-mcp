from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any
from uuid import uuid4

import websockets


class SimulatedBridge:
    def __init__(self, role: str, uri: str) -> None:
        self.role = role
        self.uri = uri

    async def run(self) -> None:
        async with websockets.connect(self.uri) as socket:
            await self._send(
                socket,
                {
                    "jsonrpc": "2.0",
                    "id": uuid4().hex,
                    "method": "hello",
                    "params": {
                        "role": self.role,
                        "session": {
                            "sample_id": "simulated",
                            "file_path": "C:/samples/benign.exe",
                            "architecture": "x64",
                            "image_base": "0x140000000",
                        },
                    },
                },
            )
            print(await socket.recv())
            if self.role == "ida":
                await self._emit(socket, "cursor.changed", {"ea": "0x140001000"})
            else:
                await self._emit(
                    socket,
                    "module.loaded",
                    {"name": "benign.exe", "runtime_base": "0x7ff700000000", "ida_base": "0x140000000", "size": "0x200000"},
                )
                await self._emit(socket, "breakpoint.hit", {"address": "0x7ff700001000"})

            async for raw in socket:
                request = json.loads(raw)
                result = self._handle(request.get("method"), request.get("params", {}))
                await self._send(socket, {"jsonrpc": "2.0", "id": request.get("id"), "result": result})

    def _handle(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method in {"ida.get_function", "ida.get_xrefs"}:
            return {"method": method, "params": params, "name": "simulated_function", "start_ea": params.get("ea")}
        if method == "x64dbg.read_registers":
            return {"rip": "0x7ff700001000", "rsp": "0x12ff00"}
        if method == "x64dbg.read_memory":
            return {"address": params.get("address"), "bytes": "9090c3"}
        return {"ok": True, "method": method, "params": params}

    async def _emit(self, socket: websockets.WebSocketClientProtocol, event_type: str, payload: dict[str, Any]) -> None:
        await self._send(socket, {"jsonrpc": "2.0", "method": "event", "params": {"type": event_type, "payload": payload}})

    @staticmethod
    async def _send(socket: websockets.WebSocketClientProtocol, message: dict[str, Any]) -> None:
        await socket.send(json.dumps(message))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["ida", "x64dbg"], required=True)
    parser.add_argument("--uri", default="ws://127.0.0.1:8765")
    args = parser.parse_args()
    asyncio.run(SimulatedBridge(args.role, args.uri).run())


if __name__ == "__main__":
    main()

