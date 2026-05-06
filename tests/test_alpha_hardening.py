from __future__ import annotations

import asyncio
import json
import socket

import pytest
import websockets

from ix64mcp.agent_ux import timeline_summary
from ix64mcp.bridge import BridgeRegistry
from ix64mcp.config import IX64Config
from ix64mcp.context_budget import profile_limits, with_context_budget
from ix64mcp.daemon_api import daemon_request, serve_daemon_api
from ix64mcp.protocol import parse_address
from ix64mcp.server import IX64MCP, proxy_tool_definitions
from ix64mcp.session import AnalysisSession


class FakeBridges:
    def __init__(self, connected: dict[str, bool] | None = None) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.responses: dict[str, object] = {}
        self._connected = connected or {"ida": True, "x64dbg": True}

    def connected(self) -> dict[str, bool]:
        return dict(self._connected)

    async def request(self, role: str, method: str, params: dict | None = None):
        self.calls.append((role, method, params or {}))
        response = self.responses.get(method)
        if callable(response):
            return response(params or {})
        if response is not None:
            return response
        return {"ok": True, "role": role, "method": method, "params": params or {}}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def make_app(tmp_path) -> IX64MCP:
    return IX64MCP(IX64Config(state_dir=tmp_path))


def test_best_runtime_mapping_prefers_most_specific_module() -> None:
    session = AnalysisSession()
    session.upsert_mapping("wide", ida_base=0x10000000, runtime_base=0x50000000, size=0x100000)
    session.upsert_mapping("inner", ida_base=0x20000000, runtime_base=0x50080000, size=0x10000)

    assert session.runtime_to_ida(0x50081234) == 0x20001234


def test_best_ida_mapping_prefers_most_specific_module() -> None:
    session = AnalysisSession()
    session.upsert_mapping("wide", ida_base=0x10000000, runtime_base=0x50000000, size=0x100000)
    session.upsert_mapping("inner", ida_base=0x10080000, runtime_base=0x60000000, size=0x10000)

    assert session.ida_to_runtime(0x10081234) == 0x60001234


def test_unknown_size_mapping_is_open_ended_current_behavior() -> None:
    session = AnalysisSession()
    session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=None)

    assert session.runtime_to_ida(0x7FF800000000) == 0x240000000


def test_x64dbg_event_without_mapping_does_not_set_ida_address() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    registry._apply_event("x64dbg", {"type": "breakpoint.hit", "payload": {"address": "0x401000"}})

    assert session.active_runtime_address == 0x401000
    assert session.active_ida_ea is None


def test_non_dict_event_payload_is_wrapped() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    registry._apply_event("ida", {"type": "custom.event", "payload": "raw"})

    assert session.timeline[-1].payload == {"value": "raw"}


def test_empty_comment_event_is_preserved() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    registry._apply_event("ida", {"type": "ida.comment.changed", "payload": {"ea": "0x140001000", "text": ""}})

    assert session.comments[0x140001000] == ""


def test_small_module_size_is_treated_as_unknown() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    registry._apply_event("x64dbg", {"type": "module.loaded", "payload": {"name": "tiny", "runtime_base": "0x70000000", "size": "0x1000"}})

    assert session.mapping_by_name("tiny").size is None


def test_module_unload_only_removes_matching_runtime_base() -> None:
    session = AnalysisSession()
    session.upsert_mapping("a", ida_base=0x1000, runtime_base=0x5000, size=0x100)
    session.upsert_mapping("b", ida_base=0x2000, runtime_base=0x6000, size=0x100)
    registry = BridgeRegistry(session)

    registry._apply_event("x64dbg", {"type": "module.unloaded", "payload": {"runtime_base": "0x5000"}})

    assert session.mapping_by_name("a") is None
    assert session.mapping_by_name("b") is not None


def test_parse_address_accepts_decimal_and_hex() -> None:
    assert parse_address("4096") == 4096
    assert parse_address("0x1000") == 4096


def test_context_budget_unknown_profile_falls_back_to_compact() -> None:
    assert profile_limits("made-up")["profile"] == "compact"


def test_context_budget_truncates_large_payload() -> None:
    value = {"items": [{"text": "A" * 2000} for _ in range(200)]}

    result = with_context_budget(value, "quick")

    assert result["context_budget"]["estimated_bytes"] <= result["context_budget"]["max_bytes"]
    assert len(result["items"]) <= 26


def test_timeline_summary_groups_repeated_events() -> None:
    session = AnalysisSession()
    for _ in range(3):
        session.add_event("trace.api_call", "x64dbg", {"api": "GetProcAddress", "address": "0x401000"})

    summary = timeline_summary(session.timeline, limit=10, profile="quick")

    assert summary["groups"][0]["type"] == "trace.api_call"
    assert summary["groups"][0]["count"] == 3
    assert summary["hot_apis"][0]["api"] == "GetProcAddress"


@pytest.mark.asyncio
async def test_sync_from_ida_moves_x64dbg_when_mapped(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)

    result = await app.call_tool("analysis.sync_address", {"source": "ida", "address": "0x140001000"})

    assert result["runtime_address"] == "0x7ff700001000"
    assert ("x64dbg", "x64dbg.goto", {"address": "0x7ff700001000"}) in fake.calls


@pytest.mark.asyncio
async def test_sync_from_ida_unmapped_does_not_call_debugger(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    result = await app.call_tool("analysis.sync_address", {"source": "ida", "address": "0x140001000"})

    assert result["runtime_address"] is None
    assert fake.calls == []


@pytest.mark.asyncio
async def test_sync_rejects_unknown_source(tmp_path) -> None:
    app = make_app(tmp_path)

    with pytest.raises(ValueError):
        await app.call_tool("analysis.sync_address", {"source": "windbg", "address": "0x401000"})


@pytest.mark.asyncio
async def test_wait_for_event_uses_existing_event_when_no_after_index(tmp_path) -> None:
    app = make_app(tmp_path)
    app.session.add_event("breakpoint.hit", "x64dbg", {"address": "0x401000"})

    event = await app.call_tool("analysis.wait_for_event", {"type": "breakpoint.hit", "address": "0x401000", "timeout": 1})

    assert event["payload"]["address"] == "0x401000"


@pytest.mark.asyncio
async def test_wait_for_event_address_mismatch_times_out(tmp_path) -> None:
    app = make_app(tmp_path)
    app.session.add_event("breakpoint.hit", "x64dbg", {"address": "0x401000"})

    with pytest.raises(asyncio.TimeoutError):
        await app.call_tool("analysis.wait_for_event", {"type": "breakpoint.hit", "address": "0x402000", "timeout": 0.1})


@pytest.mark.asyncio
async def test_temporary_breakpoint_defaults_to_temporary_group(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    result = await app.call_tool("x64dbg.set_temporary_breakpoint", {"address": "0x401000"})

    assert result["group"] == "temporary"
    assert result["breakpoint"]["one_shot"] is True
    assert "temporary" in app.breakpoint_groups


@pytest.mark.asyncio
async def test_hardware_breakpoint_group_uses_hardware_methods(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    await app.call_tool("x64dbg.breakpoint_group_add", {"name": "hw", "addresses": ["0x401000"], "kind": "hardware"})
    await app.call_tool("x64dbg.remove_breakpoint_group", {"name": "hw"})

    assert ("x64dbg", "x64dbg.set_hardware_breakpoint", {"address": "0x401000"}) in fake.calls
    assert ("x64dbg", "x64dbg.remove_hardware_breakpoint", {"address": "0x401000"}) in fake.calls


@pytest.mark.asyncio
async def test_memory_breakpoint_group_uses_memory_methods(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    await app.call_tool("x64dbg.breakpoint_group_add", {"name": "mem", "addresses": ["0x401000"], "kind": "memory"})
    await app.call_tool("x64dbg.remove_breakpoint_group", {"name": "mem"})

    assert ("x64dbg", "x64dbg.set_memory_breakpoint", {"address": "0x401000"}) in fake.calls
    assert ("x64dbg", "x64dbg.remove_memory_breakpoint", {"address": "0x401000"}) in fake.calls


@pytest.mark.asyncio
async def test_remove_missing_breakpoint_group_errors(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    with pytest.raises(ValueError):
        await app.call_tool("x64dbg.remove_breakpoint_group", {"name": "missing"})


@pytest.mark.asyncio
async def test_breakpoint_group_caps_addresses_to_128(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake
    addresses = [hex(0x401000 + index) for index in range(150)]

    result = await app.call_tool("x64dbg.breakpoint_group_add", {"name": "many", "addresses": addresses, "kind": "software"})

    assert len(result["breakpoints"]) == 128


@pytest.mark.asyncio
async def test_trace_recipe_enable_skips_bridge_when_disconnected(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges({"ida": False, "x64dbg": False})

    result = await app.call_tool("trace.recipe_enable", {"name": "LoadLibrary", "options": {"wide": True}})

    assert result["enabled"] is True
    assert result["bridge"] == {}


@pytest.mark.asyncio
async def test_trace_batch_caps_nested_strings(tmp_path) -> None:
    app = make_app(tmp_path)
    app._queue_trace_event({"api": "A" * 900, "args": ["B" * 900]})
    await app._flush_trace_events()

    event = app.trace_batches[-1]["events"][0]
    assert len(event["api"]) == 512
    assert len(event["args"][0]) == 512


@pytest.mark.asyncio
async def test_runtime_history_counts_exceptions_threads_and_modules(tmp_path) -> None:
    app = make_app(tmp_path)
    app.session.add_event("thread.created", "x64dbg", {"thread_id": "0x10"})
    app.session.add_event("exception.hit", "x64dbg", {"code": "0x80000003"})
    app.session.add_event("module.loaded", "x64dbg", {"name": "kernel32.dll"})

    result = await app.call_tool("analysis.runtime_history", {"limit": 50})

    assert result["event_counts"]["thread.created"] == 1
    assert result["recent_exceptions"][0]["code"] == "0x80000003"
    assert result["recent_modules"][0]["name"] == "kernel32.dll"


@pytest.mark.asyncio
async def test_detect_anti_debug_finds_nested_api_name(tmp_path) -> None:
    app = make_app(tmp_path)
    app.session.add_event("trace.api_call", "x64dbg", {"nested": {"api": "IsDebuggerPresent"}})

    result = await app.call_tool("analysis.detect_anti_debug", {"limit": 10})

    assert result["hints"][0]["api"] == "IsDebuggerPresent"


@pytest.mark.asyncio
async def test_correlate_runtime_static_uses_active_ida_when_no_runtime(tmp_path) -> None:
    app = make_app(tmp_path)
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    app.session.active_ida_ea = 0x140001000
    app.bridges = FakeBridges({"ida": False, "x64dbg": False})

    result = await app.call_tool("analysis.correlate_runtime_static", {"include_summary": "false"})

    assert result["runtime_address"] == "0x7ff700001000"
    assert result["ida_ea"] == "0x140001000"


@pytest.mark.asyncio
async def test_policy_approval_allows_file_patch_then_clear_blocks(tmp_path) -> None:
    app = make_app(tmp_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x75\x05")

    await app.call_tool("analysis.policy_approve", {"action": "patch.apply_file", "reason": "unit test"})
    patched = await app.call_tool("patch.apply_file", {"path": str(sample), "file_offset": "0x0", "expected_hex": "75", "patch_hex": "74"})
    await app.call_tool("analysis.policy_clear", {"action": "patch.apply_file"})

    assert patched["sha256_after"]
    with pytest.raises(PermissionError):
        await app.call_tool("patch.apply_file", {"path": str(sample), "file_offset": "0x0", "expected_hex": "74", "patch_hex": "75"})


@pytest.mark.asyncio
async def test_apply_suggestion_rejects_already_rejected_item(tmp_path) -> None:
    app = make_app(tmp_path)
    created = await app.call_tool("analysis.suggest_name", {"target": "0x401000", "suggested_value": "name"})
    await app.call_tool("analysis.reject_suggestion", {"id": created["id"], "reason": "no"})

    with pytest.raises(ValueError):
        await app.call_tool("analysis.apply_suggestion", {"id": created["id"]})


@pytest.mark.asyncio
async def test_panel_update_is_skipped_when_ida_disconnected(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges({"ida": False, "x64dbg": True})
    app.bridges = fake

    await app.call_tool("analysis.suggest_name", {"target": "0x401000", "suggested_value": "name"})

    assert fake.calls == []


@pytest.mark.asyncio
async def test_analysis_current_degrades_when_ida_summary_fails(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["ida.function_summary"] = RuntimeError("boom")

    def raise_summary(_params):
        raise RuntimeError("boom")

    fake.responses["ida.function_summary"] = raise_summary
    app.bridges = fake
    app.session.active_ida_ea = 0x140001000

    result = await app._analysis_current(5)

    assert result["function_summary"]["error"] == "boom"


@pytest.mark.asyncio
async def test_daemon_api_malformed_json_returns_error() -> None:
    port = free_port()

    async def handler(method, params):
        return {"ok": True, "method": method, "params": params}

    task = asyncio.create_task(serve_daemon_api(handler, port=port))
    try:
        for _ in range(50):
            try:
                async with websockets.connect(f"ws://127.0.0.1:{port}", ping_interval=None) as socket:
                    await socket.send("not-json")
                    response = json.loads(await socket.recv())
                    break
            except OSError:
                await asyncio.sleep(0.02)
        else:
            raise AssertionError("daemon API did not start")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert response["error"]["type"] == "JSONDecodeError"


@pytest.mark.asyncio
async def test_daemon_api_non_dict_params_are_normalized() -> None:
    port = free_port()

    async def handler(method, params):
        return {"method": method, "params": params}

    task = asyncio.create_task(serve_daemon_api(handler, port=port))
    try:
        for _ in range(50):
            try:
                async with websockets.connect(f"ws://127.0.0.1:{port}", ping_interval=None) as socket:
                    await socket.send(json.dumps({"jsonrpc": "2.0", "id": "x", "method": "echo", "params": []}))
                    response = json.loads(await socket.recv())
                    break
            except OSError:
                await asyncio.sleep(0.02)
        else:
            raise AssertionError("daemon API did not start")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert response["result"] == {"method": "echo", "params": {}}


@pytest.mark.asyncio
async def test_daemon_api_exposes_runtime_history_resource(tmp_path) -> None:
    app = make_app(tmp_path)

    resources = await app.daemon_api("mcp.list_resources", {})

    assert "analysis://runtime-history" in {resource["uri"] for resource in resources}


@pytest.mark.asyncio
async def test_daemon_api_proxy_tool_surface_has_no_duplicates(tmp_path) -> None:
    app = make_app(tmp_path)

    tools = await app.daemon_api("mcp.list_tools", {})
    names = [tool["name"] for tool in tools]

    assert len(names) == len(set(names))
    assert len(names) >= 90


def test_proxy_tool_definitions_are_generic_for_adapter_surface() -> None:
    tool = next(tool for tool in proxy_tool_definitions() if tool.name == "ida.goto")

    assert tool.inputSchema["additionalProperties"] is True


@pytest.mark.asyncio
async def test_disconnected_bridge_tool_reports_clear_error(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = app.bridges.__class__(app.session)

    with pytest.raises(RuntimeError, match="bridge is not connected"):
        await app.call_tool("ida.get_function", {"ea": "0x401000"})


@pytest.mark.asyncio
async def test_unknown_tool_is_blocked_by_policy_before_dispatch(tmp_path) -> None:
    app = make_app(tmp_path)

    with pytest.raises(PermissionError):
        await app.call_tool("unknown.tool", {})


@pytest.mark.asyncio
async def test_read_resource_unknown_uri_errors(tmp_path) -> None:
    app = make_app(tmp_path)

    with pytest.raises(ValueError):
        await app._read_resource_value("analysis://does-not-exist")


@pytest.mark.asyncio
async def test_session_resume_unknown_sample_errors(tmp_path) -> None:
    app = make_app(tmp_path)

    with pytest.raises(ValueError):
        await app.call_tool("analysis.session_resume", {"sample_id": "missing.exe"})
