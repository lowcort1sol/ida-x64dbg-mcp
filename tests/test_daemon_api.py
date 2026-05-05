from __future__ import annotations

import asyncio
import socket

import pytest

from ix64mcp.daemon_api import daemon_request, serve_daemon_api
from ix64mcp.server import IX64MCP, proxy_resource_definitions, proxy_tool_definitions
from ix64mcp.config import IX64Config


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.asyncio
async def test_daemon_api_roundtrip() -> None:
    async def handler(method, params):
        if method == "echo":
            return {"params": params}
        raise ValueError("bad method")

    port = free_port()
    task = asyncio.create_task(serve_daemon_api(handler, port=port))
    try:
        for _ in range(50):
            try:
                result = await daemon_request("echo", {"ok": True}, port=port)
                break
            except OSError:
                await asyncio.sleep(0.02)
        else:
            raise AssertionError("daemon API did not start")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert result == {"params": {"ok": True}}


@pytest.mark.asyncio
async def test_ix64_daemon_api_exposes_mcp_surface(tmp_path) -> None:
    app = IX64MCP(IX64Config(state_dir=tmp_path))

    health = await app.daemon_api("daemon.health", {})
    tools = await app.daemon_api("mcp.list_tools", {})
    resources = await app.daemon_api("mcp.list_resources", {})
    policy = await app.daemon_api("mcp.call_tool", {"name": "analysis.policy_status", "arguments": {}})
    summary = await app.daemon_api("mcp.read_resource", {"uri": "ida://session/summary"})

    assert health["ok"] is True
    assert "workflow.generate_analysis_report" in {tool["name"] for tool in tools}
    assert "analysis://current" in {resource["uri"] for resource in resources}
    assert "workflow.follow_debugger" in policy["safe_actions"]
    assert "connected" in summary


def test_proxy_surface_has_expected_phase8_tools() -> None:
    tool_names = {tool.name for tool in proxy_tool_definitions()}
    resource_uris = {str(resource.uri) for resource in proxy_resource_definitions()}

    assert "analysis.session_resume" in tool_names
    assert "workflow.explain_current_function" in tool_names
    assert "analysis://report" in resource_uris
