from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable
from uuid import uuid4

import websockets


JsonHandler = Callable[[str, dict[str, Any]], Awaitable[Any]]


async def serve_daemon_api(handler: JsonHandler, host: str = "127.0.0.1", port: int = 8766) -> None:
    async def handle_socket(websocket) -> None:
        async for raw in websocket:
            try:
                message = json.loads(raw)
                method = str(message.get("method", ""))
                params = message.get("params", {})
                if not isinstance(params, dict):
                    params = {}
                result = await handler(method, params)
                await websocket.send(json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": result}, default=str))
            except Exception as exc:
                await websocket.send(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"type": type(exc).__name__, "message": str(exc)},
                        },
                        default=str,
                    )
                )

    async with websockets.serve(handle_socket, host, port, ping_interval=None):
        await asyncio.Future()


async def daemon_request(method: str, params: dict[str, Any] | None = None, host: str = "127.0.0.1", port: int = 8766) -> Any:
    uri = f"ws://{host}:{port}"
    async with websockets.connect(uri, ping_interval=None) as websocket:
        request_id = uuid4().hex
        await websocket.send(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}))
        response = json.loads(await websocket.recv())
    if "error" in response:
        error = response["error"]
        if isinstance(error, dict):
            raise RuntimeError(f"{error.get('type', 'Error')}: {error.get('message', error)}")
        raise RuntimeError(str(error))
    return response.get("result")
