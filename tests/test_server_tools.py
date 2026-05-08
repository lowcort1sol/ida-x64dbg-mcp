import asyncio
from pathlib import Path

import pytest

from ix64mcp.config import IX64Config
from ix64mcp.server import IX64MCP, _parse_pe_entry


class FakeBridges:
    def __init__(self) -> None:
        self.calls = []
        self.responses = {}

    def connected(self):
        return {"ida": True, "x64dbg": True}

    async def request(self, role, method, params=None):
        self.calls.append((role, method, params or {}))
        if method in self.responses:
            response = self.responses[method]
            return response(params or {}) if callable(response) else response
        return {"ok": True, "role": role, "method": method, "params": params or {}}


def make_app(tmp_path) -> IX64MCP:
    return IX64MCP(IX64Config(state_dir=tmp_path))


@pytest.mark.asyncio
async def test_sync_from_x64dbg_moves_ida_when_mapped(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake
    app.session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)

    result = await app.call_tool("analysis.sync_address", {"source": "x64dbg", "address": "0x7ff700001000"})

    assert result == {"runtime_address": "0x7ff700001000", "ida_ea": "0x140001000"}
    assert fake.calls == [("ida", "ida.goto", {"ea": "0x140001000"})]


@pytest.mark.asyncio
async def test_breakpoint_tool_records_local_state(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    await app.call_tool("x64dbg.set_breakpoint", {"address": "0x401000"})

    assert 0x401000 in app.session.breakpoints
    assert app.session.timeline[-1].type == "tool.called"


@pytest.mark.asyncio
async def test_link_dynamic_static_validates_required_addresses(tmp_path) -> None:
    app = make_app(tmp_path)

    with pytest.raises(ValueError, match="analysis.link_dynamic_static requires argument 'runtime_address'"):
        await app.call_tool("analysis.link_dynamic_static", {"ida_ea": "0x140001000"})
    with pytest.raises(ValueError, match="analysis.link_dynamic_static requires argument 'ida_ea'"):
        await app.call_tool("analysis.link_dynamic_static", {"runtime_address": "0x7ff700001000"})


@pytest.mark.asyncio
async def test_runtime_snapshot_collects_registers_memory_stack_threads(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["x64dbg.read_registers"] = {"ok": True, "cip": "0x401000", "csp": "0x500000", "rax": "0x1"}
    fake.responses["x64dbg.breakpoint_snapshot"] = {"ok": True, "address": "0x401000", "args": ["0x1"]}
    fake.responses["x64dbg.read_memory"] = lambda params: {"ok": True, "address": params["address"], "bytes": "aa" * int(params["size"])}
    fake.responses["x64dbg.call_stack"] = {"ok": True, "frames": [{"return": "0x402000"}], "total": 1}
    fake.responses["x64dbg.threads"] = {"ok": True, "threads": [{"id": "0x1", "current": True}]}
    fake.responses["x64dbg.exceptions"] = {"ok": True, "exceptions": [], "total": 0}
    app.bridges = fake

    result = await app.call_tool("x64dbg.runtime_snapshot", {"memory_preview": 4, "stack_preview": 8, "call_stack_limit": 2})

    assert result["address"] == "0x401000"
    assert result["stack_pointer"] == "0x500000"
    assert result["registers"]["rax"] == "0x1"
    assert result["snapshot"]["args"] == ["0x1"]
    assert result["memory"]["address"] == "0x401000"
    assert result["stack"]["address"] == "0x500000"
    assert result["call_stack"]["total"] == 1
    assert result["threads"]["threads"][0]["current"] is True
    assert result["degraded"] is False


@pytest.mark.asyncio
async def test_runtime_snapshot_returns_degraded_errors_for_partial_bridge_data(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["x64dbg.read_registers"] = {"ok": True, "cip": "0x401000", "csp": "0x500000"}
    def fail_call_stack(params):
        raise RuntimeError("stack unavailable")

    fake.responses["x64dbg.call_stack"] = fail_call_stack
    app.bridges = fake

    result = await app.call_tool("x64dbg.runtime_snapshot", {"memory_preview": 0, "stack_preview": 0, "call_stack_limit": 8})

    assert result["degraded"] is True
    assert result["errors"]["call_stack"] == "stack unavailable"
    assert result["address"] == "0x401000"


@pytest.mark.asyncio
async def test_runtime_snapshot_builds_fallback_call_stack_from_stack_memory(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["x64dbg.read_registers"] = {"ok": True, "cip": "0x401000", "csp": "0x500000"}
    fake.responses["x64dbg.read_memory"] = lambda params: {
        "ok": True,
        "address": params["address"],
        "bytes": (0x401234).to_bytes(8, "little").hex() + (0x402000).to_bytes(8, "little").hex(),
    }
    fake.responses["x64dbg.call_stack"] = {"ok": True, "frames": [], "total": 0}
    app.bridges = fake
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x400000, size=0x100000)

    result = await app.call_tool("x64dbg.runtime_snapshot", {"memory_preview": 0, "stack_preview": 16, "call_stack_limit": 8})

    assert result["call_stack"]["total"] == 0
    assert result["fallback_call_stack"]["total"] == 2
    assert result["fallback_call_stack"]["frames"][0]["return_address"] == "0x401234"
    assert result["fallback_call_stack"]["frames"][0]["ida_ea"] == "0x140001234"


@pytest.mark.asyncio
async def test_switch_thread_is_forwarded_and_required(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    with pytest.raises(ValueError, match="x64dbg.switch_thread requires argument 'thread_id'"):
        await app.call_tool("x64dbg.switch_thread", {})
    result = await app.call_tool("x64dbg.switch_thread", {"thread_id": "0x1234"})

    assert result["ok"] is True
    assert ("x64dbg", "x64dbg.switch_thread", {"thread_id": "0x1234"}) in app.bridges.calls


@pytest.mark.asyncio
async def test_run_until_breakpoint_timeout_includes_runtime_diagnostic(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["x64dbg.read_registers"] = {"ok": True, "cip": "0x401010", "csp": "0x500000"}
    fake.responses["x64dbg.read_memory"] = {"ok": True, "address": "0x500000", "bytes": ""}
    fake.responses["x64dbg.call_stack"] = {"ok": True, "frames": [], "total": 0}
    fake.responses["x64dbg.threads"] = {"ok": True, "threads": [{"id": "0x1", "current": True}]}
    fake.responses["x64dbg.exceptions"] = {"ok": True, "exceptions": [], "total": 0}
    app.bridges = fake
    app.session.breakpoints.add(0x401000)

    with pytest.raises(TimeoutError) as excinfo:
        await app.call_tool("x64dbg.run_until_breakpoint", {"address": "0x401000", "timeout": 0.1})

    message = str(excinfo.value)
    assert '"error": "timeout"' in message
    assert '"active_breakpoints": ["0x401000"]' in message
    assert "runtime_snapshot" in message


@pytest.mark.asyncio
async def test_capture_compare_context_collects_argument_candidates(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["x64dbg.read_registers"] = {"ok": True, "cip": "0x401000", "csp": "0x500000", "cax": "0x600000", "ccx": "0x7"}
    fake.responses["x64dbg.read_memory"] = lambda params: {
        "ok": True,
        "address": params["address"],
        "bytes": (0x601000).to_bytes(8, "little").hex() + (0x20).to_bytes(8, "little").hex(),
    }
    fake.responses["x64dbg.call_stack"] = {"ok": True, "frames": [], "total": 0}
    app.bridges = fake

    result = await app.call_tool("workflow.capture_compare_context", {"memory_preview": 0, "stack_preview": 16})

    assert result["workflow"] == "workflow.capture_compare_context"
    assert {"register": "cax", "value": "0x600000", "kind": "register"} in result["argument_candidates"]
    assert result["argument_candidates"][1]["kind"] in {"register", "stack_pointer"}


def make_pe64_header(entry_rva: int = 0x1234, image_base: int = 0x140000000) -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff + 16 : coff + 18] = (0xF0).to_bytes(2, "little")
    opt = coff + 20
    data[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    data[opt + 16 : opt + 20] = entry_rva.to_bytes(4, "little")
    data[opt + 24 : opt + 32] = image_base.to_bytes(8, "little")
    return bytes(data)


def test_parse_pe_entry_pe32_plus() -> None:
    parsed = _parse_pe_entry(make_pe64_header())

    assert parsed == {"entry_rva": 0x1234, "image_base": 0x140000000, "bitness": 64}


@pytest.mark.asyncio
async def test_break_on_entry_sets_breakpoint_from_main_mapping(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    header = make_pe64_header(entry_rva=0x1C64, image_base=0x140000000)
    fake.responses["x64dbg.read_memory"] = {"ok": True, "bytes": header.hex()}
    app.bridges = fake
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=None)

    result = await app.call_tool("analysis.break_on_entry", {})

    assert result["payload"]["runtime_entry"] == "0x7ff700001c64"
    assert result["payload"]["ida_entry"] == "0x140001c64"
    assert 0x7FF700001C64 in app.session.breakpoints
    assert ("x64dbg", "x64dbg.set_breakpoint", {"address": "0x7ff700001c64"}) in fake.calls


@pytest.mark.asyncio
async def test_policy_blocks_unknown_risky_tool(tmp_path) -> None:
    app = make_app(tmp_path)

    with pytest.raises(PermissionError):
        await app.call_tool("x64dbg.patch_memory", {"address": "0x401000", "bytes": "90"})


@pytest.mark.asyncio
async def test_policy_status_is_safe(tmp_path) -> None:
    app = make_app(tmp_path)

    result = await app.call_tool("analysis.policy_status", {})

    assert result["mode"] == "analysis-safe"
    assert "x64dbg.patch_memory" in result["risky_actions"]


@pytest.mark.asyncio
async def test_ida_phase2_tools_are_forwarded_with_limits(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    await app.call_tool("ida.list_strings", {"query": "pass", "limit": 50, "offset": 0})
    await app.call_tool("ida.get_string_xrefs", {"address": "0x140002000", "limit": 25})
    await app.call_tool("ida.function_summary", {"ea": "0x140001000", "detail": "compact", "max_pseudocode_chars": 0})

    assert fake.calls == [
        ("ida", "ida.list_strings", {"query": "pass", "limit": 50, "offset": 0}),
        ("ida", "ida.get_string_xrefs", {"address": "0x140002000", "limit": 25}),
        ("ida", "ida.function_summary", {"ea": "0x140001000", "detail": "compact", "max_pseudocode_chars": 0}),
    ]


@pytest.mark.asyncio
async def test_ida_phase3_pseudocode_tools_are_forwarded(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    await app.call_tool("ida.pseudocode", {"ea": "0x140001000", "max_chars": 12000, "offset": 0})
    await app.call_tool("ida.refresh_decompiler", {"ea": "0x140001000"})
    await app.call_tool("ida.set_decompiler_comment", {"ea": "0x140001000", "text": "checked"})

    assert fake.calls == [
        ("ida", "ida.pseudocode", {"ea": "0x140001000", "max_chars": 12000, "offset": 0}),
        ("ida", "ida.refresh_decompiler", {"ea": "0x140001000"}),
        ("ida", "ida.set_decompiler_comment", {"ea": "0x140001000", "text": "checked"}),
    ]


@pytest.mark.asyncio
async def test_ida_phase12_static_tools_are_forwarded(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    await app.call_tool("ida.callgraph", {"ea": "0x140001000", "depth": 2, "limit": 100})
    await app.call_tool("ida.cfg", {"ea": "0x140001000", "limit": 100})
    await app.call_tool("ida.callers", {"ea": "0x140001000", "limit": 50})
    await app.call_tool("ida.callees", {"ea": "0x140001000", "limit": 50})
    await app.call_tool("ida.string_to_functions", {"address": "0x140003000", "limit": 25})
    await app.call_tool("ida.import_to_callers", {"name": "GetProcAddress", "limit": 25})
    await app.call_tool("ida.branch_context", {"ea": "0x140001050", "window": 8})
    await app.call_tool("ida.stack_var_usage", {"ea": "0x140001000", "name": "input", "limit": 25})

    assert fake.calls == [
        ("ida", "ida.callgraph", {"ea": "0x140001000", "depth": 2, "limit": 100}),
        ("ida", "ida.cfg", {"ea": "0x140001000", "limit": 100}),
        ("ida", "ida.callers", {"ea": "0x140001000", "limit": 50}),
        ("ida", "ida.callees", {"ea": "0x140001000", "limit": 50}),
        ("ida", "ida.string_to_functions", {"address": "0x140003000", "limit": 25}),
        ("ida", "ida.import_to_callers", {"name": "GetProcAddress", "limit": 25}),
        ("ida", "ida.branch_context", {"ea": "0x140001050", "window": 8}),
        ("ida", "ida.stack_var_usage", {"ea": "0x140001000", "name": "input", "limit": 25}),
    ]


@pytest.mark.asyncio
async def test_phase12_graph_resources_proxy_to_ida(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["ida.callgraph"] = {"nodes": [{"ea": "0x140001000"}], "edges": []}
    fake.responses["ida.cfg"] = {"blocks": [{"id": 0}], "edges": []}
    app.bridges = fake

    callgraph = await app._read_resource_value("ida://callgraph/0x140001000")
    cfg = await app._read_resource_value("ida://cfg/0x140001000")

    assert "0x140001000" in callgraph
    assert '"blocks"' in cfg
    assert ("ida", "ida.callgraph", {"ea": "0x140001000", "depth": 2, "limit": 200}) in fake.calls
    assert ("ida", "ida.cfg", {"ea": "0x140001000", "limit": 300}) in fake.calls


@pytest.mark.asyncio
async def test_type_suggestions_are_preview_only(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    created = await app.call_tool(
        "analysis.suggest_type",
        {"target": "0x140001000", "suggested_value": "int __fastcall(char *)", "reason": "argument looks like input", "confidence": 0.75},
    )

    assert created["kind"] == "type"
    assert "confidence=0.75" in created["reason"]
    with pytest.raises(ValueError, match="preview-only"):
        await app.call_tool("analysis.apply_suggestion", {"id": created["id"]})


@pytest.mark.asyncio
async def test_phase13_temporary_breakpoints_and_groups(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    temporary = await app.call_tool("x64dbg.set_temporary_breakpoint", {"address": "0x401000", "group": "entry"})
    group = await app.call_tool("x64dbg.breakpoint_group_add", {"name": "apis", "addresses": ["0x402000", "0x403000"], "kind": "software"})
    removed = await app.call_tool("x64dbg.remove_breakpoint_group", {"name": "apis"})

    assert temporary["group"] == "entry"
    assert group["name"] == "apis"
    assert removed["name"] == "apis"
    assert ("x64dbg", "x64dbg.set_breakpoint", {"address": "0x401000"}) in fake.calls
    assert ("x64dbg", "x64dbg.remove_breakpoint", {"address": "0x402000"}) in fake.calls
    assert 0x401000 in app.session.breakpoints
    assert 0x402000 not in app.session.breakpoints


@pytest.mark.asyncio
async def test_phase13_runtime_correlation_and_history(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["ida.function_summary"] = {"found": True, "name": "anti_debug_check"}
    app.bridges = fake
    app.session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    app.session.active_runtime_address = 0x7FF700001000
    app.session.add_event("breakpoint.hit", "x64dbg", {"address": "0x7ff700001000"})
    app.session.add_event("trace.api_call", "x64dbg", {"api": "IsDebuggerPresent", "address": "0x7ff700001000"})
    app.session.add_event("exception.hit", "x64dbg", {"code": "0x80000003", "address": "0x7ff700001000"})

    correlation = await app.call_tool("analysis.correlate_runtime_static", {})
    history = await app.call_tool("analysis.runtime_history", {"limit": 50})
    anti_debug = await app.call_tool("analysis.detect_anti_debug", {"limit": 50})

    assert correlation["ida_ea"] == "0x140001000"
    assert correlation["function_summary"]["name"] == "anti_debug_check"
    assert history["event_counts"]["breakpoint.hit"] == 1
    assert history["hot_apis"][0]["api"] == "IsDebuggerPresent"
    assert anti_debug["hints"][0]["api"] == "IsDebuggerPresent"


@pytest.mark.asyncio
async def test_x64dbg_phase4_tools_are_forwarded(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    await app.call_tool("x64dbg.memory_map", {"limit": 10, "offset": 0})
    await app.call_tool("x64dbg.call_stack", {"limit": 8})
    await app.call_tool("x64dbg.threads", {})
    await app.call_tool("x64dbg.exceptions", {"limit": 5, "offset": 0})
    await app.call_tool("x64dbg.breakpoint_snapshot", {})
    await app.call_tool("x64dbg.dump_metadata", {"address": "0x401000", "size": 4096})

    assert [call[1] for call in fake.calls] == [
        "x64dbg.memory_map",
        "x64dbg.call_stack",
        "x64dbg.threads",
        "x64dbg.exceptions",
        "x64dbg.breakpoint_snapshot",
        "x64dbg.dump_metadata",
    ]


@pytest.mark.asyncio
async def test_trace_recipe_lifecycle_and_batch_caps(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    enabled = await app.call_tool("trace.recipe_enable", {"name": "LoadLibrary", "options": {"wide": True}})
    disabled = await app.call_tool("trace.recipe_disable", {"name": "LoadLibrary"})
    status = await app.call_tool("trace.recipe_status", {})
    app.session.add_event("trace.api_call", "x64dbg", {"api": "LoadLibraryW", "path": "A" * 800})
    await app._flush_trace_events()

    assert enabled["enabled"] is True
    assert disabled["enabled"] is False
    assert status["recipes"][0]["name"] == "LoadLibrary"
    assert ("x64dbg", "x64dbg.trace_recipe_enable", {"name": "LoadLibrary", "options": {"wide": True}}) in fake.calls
    assert ("x64dbg", "x64dbg.trace_recipe_disable", {"name": "LoadLibrary"}) in fake.calls
    assert app.trace_batches[-1]["count"] == 1
    assert len(app.trace_batches[-1]["events"][0]["payload"]["path"]) == 512


@pytest.mark.asyncio
async def test_dump_metadata_safe_but_dump_memory_blocked(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    result = await app.call_tool("x64dbg.dump_metadata", {"address": "0x401000", "size": 512})

    assert result["ok"] is True
    with pytest.raises(PermissionError):
        await app.call_tool("x64dbg.dump_memory", {"address": "0x401000", "size": 512})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "arguments", "missing"),
    [
        ("x64dbg.dump_metadata", {"size": 512}, "address"),
        ("x64dbg.dump_metadata", {"address": "0x401000"}, "size"),
        ("x64dbg.read_memory", {"size": 16}, "address"),
        ("x64dbg.read_memory", {"address": "0x401000"}, "size"),
    ],
)
async def test_x64dbg_read_tools_validate_required_context(tmp_path, tool, arguments, missing) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    with pytest.raises(ValueError, match=f"{tool} requires argument '{missing}'"):
        await app.call_tool(tool, arguments)


@pytest.mark.asyncio
async def test_suggestion_lifecycle_applies_name(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake

    created = await app.call_tool(
        "analysis.suggest_name",
        {"target": "0x140001000", "suggested_value": "check_password", "reason": "compares input"},
    )
    listed = await app.call_tool("analysis.list_suggestions", {"status": "pending", "limit": 10, "offset": 0})
    applied = await app.call_tool("analysis.apply_suggestion", {"id": created["id"]})

    assert listed["total"] == 1
    assert applied["status"] == "applied"
    assert ("ida", "ida.rename", {"ea": "0x140001000", "name": "check_password"}) in fake.calls
    assert [call[1] for call in fake.calls].count("ida.panel_update") == 2
    assert app.session.timeline[-1].type == "analysis.suggestion.applied"


@pytest.mark.asyncio
async def test_suggestion_reject_and_invalid_id(tmp_path) -> None:
    app = make_app(tmp_path)
    created = await app.call_tool(
        "analysis.suggest_comment",
        {"target": "0x140001000", "text": "candidate branch", "reason": "needs review"},
    )

    rejected = await app.call_tool("analysis.reject_suggestion", {"id": created["id"], "reason": "not correct"})

    assert rejected["status"] == "rejected"
    with pytest.raises(ValueError):
        await app.call_tool("analysis.apply_suggestion", {"id": "missing"})


@pytest.mark.asyncio
async def test_ida_panel_apply_action_executes_suggestion(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake
    created = await app.call_tool(
        "analysis.suggest_name",
        {"target": "0x140001000", "suggested_value": "check_password", "reason": "from trace"},
    )

    app.session.add_event("ida.action.apply_suggestion", "ida", {"id": created["id"]})
    await asyncio.sleep(0)

    assert app.suggestions.get(created["id"]).status == "applied"
    assert ("ida", "ida.rename", {"ea": "0x140001000", "name": "check_password"}) in fake.calls


@pytest.mark.asyncio
async def test_ida_panel_follow_action_syncs_debugger_address(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake
    app.session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    app.session.active_runtime_address = 0x7FF700001000

    app.session.add_event("ida.action.follow_x64dbg", "ida", {"ea": "0x140001000"})
    await asyncio.sleep(0)

    assert ("ida", "ida.goto", {"ea": "0x140001000"}) in fake.calls


def test_pe_summary_uses_active_session_path(tmp_path) -> None:
    app = make_app(tmp_path)
    app.session.file_path = str(tmp_path / "missing.exe")

    with pytest.raises(FileNotFoundError):
        app._pe_tool("pe.summary", {})


@pytest.mark.asyncio
async def test_patch_apply_file_is_guarded_and_rollbackable(tmp_path) -> None:
    target = tmp_path / "toy.exe"
    target.write_bytes(bytes.fromhex("558bec74059090"))
    app = make_app(tmp_path)

    with pytest.raises(PermissionError):
        await app.call_tool(
            "patch.apply_file",
            {"path": str(target), "file_offset": "0x3", "expected_hex": "7405", "patch_hex": "7505"},
        )

    await app.call_tool("analysis.policy_approve", {"action": "patch.apply_file", "reason": "unit test"})
    applied = await app.call_tool(
        "patch.apply_file",
        {
            "path": str(target),
            "file_offset": "0x3",
            "expected_hex": "7405",
            "patch_hex": "7505",
            "reason": "invert toy branch",
        },
    )
    diff = await app.call_tool("patch.diff", {"path": str(target), "backup_path": applied["backup"], "limit": 10})
    rolled_back = await app.call_tool("patch.rollback", {"path": str(target), "backup_path": applied["backup"]})

    assert target.read_bytes() == bytes.fromhex("558bec74059090")
    assert applied["sha256_before"] == rolled_back["sha256_after_rollback"]
    assert diff["diffs"] == [{"file_offset": "0x3", "before": "74", "after": "75"}]


def test_patch_plan_on_built_sample_if_available(tmp_path) -> None:
    from ix64mcp.patch import plan_patches

    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")

    plan = plan_patches(sample, limit=10)

    assert plan["candidates"]
    assert plan["image_base"].startswith("0x")
    assert plan["notes"][0].startswith("Read-only")


@pytest.mark.asyncio
async def test_malware_workspace_ioc_config_and_behavior_report(tmp_path) -> None:
    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)

    workspace = await app.call_tool(
        "malware.workspace_create",
        {"path": str(sample), "notes": "unit test sample", "copy_sample": "true"},
    )
    ioc = await app.call_tool("malware.add_ioc", {"kind": "domain", "value": "example.test"})
    config = await app.call_tool("malware.add_config", {"key": "c2", "value": "example.test", "confidence": "high"})
    app.session.add_event("trace.api_call", "x64dbg", {"api": "CreateFileW", "path": "C:\\temp\\demo.txt"})
    report = await app.call_tool("malware.behavior_report", {})

    assert Path(workspace["sample_copy_path"]).exists()
    assert app.session.file_sha256 == workspace["hashes"]["sha256"]
    assert ioc["value"] == "example.test"
    assert config["confidence"] == "high"
    assert report["iocs"][0]["value"] == "example.test"
    assert report["decoded_strings_configs"][0]["key"] == "c2"
    assert report["files_touched"][0]["api"] == "createfilew"


@pytest.mark.asyncio
async def test_malware_triage_and_sandbox_check(tmp_path) -> None:
    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)

    result = await app.call_tool("malware.triage", {"path": str(sample), "limit": 20})
    sandbox = await app.call_tool(
        "malware.sandbox_check",
        {"allow_network": "false", "vm_confirmed": "false", "snapshot_confirmed": "false"},
    )

    assert result["hashes"]["sha256"]
    assert result["summary"]["sections"]
    assert "overlay" in result
    assert sandbox["gates"]["launch_unknown_malware"] is False
    assert sandbox["warnings"]


@pytest.mark.asyncio
async def test_workflow_follow_debugger_and_explain_current_function(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["ida.function_summary"] = {"name": "check_password", "ea": "0x140001000"}
    fake.responses["ida.pseudocode"] = {"text": "return ok;"}
    app.bridges = fake
    app.session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    app.session.active_runtime_address = 0x7FF700001000

    followed = await app.call_tool("workflow.follow_debugger", {})
    explained = await app.call_tool("workflow.explain_current_function", {"max_pseudocode_chars": 256})

    assert followed["sync"] == {"runtime_address": "0x7ff700001000", "ida_ea": "0x140001000"}
    assert explained["function_summary"]["name"] == "check_password"
    assert ("ida", "ida.goto", {"ea": "0x140001000"}) in fake.calls


@pytest.mark.asyncio
async def test_workflow_password_patch_and_strcmp_breakpoint(tmp_path) -> None:
    sample = Path("build/samples/crackme_simple/crackme_simple.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)
    fake = FakeBridges()
    fake.responses["ida.list_strings"] = {"strings": [{"address": "0x140002000", "text": "wrong password"}]}
    app.bridges = fake
    app.session.file_path = str(sample)

    candidates = await app.call_tool("workflow.find_password_check", {"limit": 10})
    patch_plan = await app.call_tool("workflow.make_patch_plan", {"limit": 5})
    breakpoint = await app.call_tool("workflow.break_on_first_strcmp_like", {"run": "false"})

    assert candidates["candidates"]
    assert patch_plan["plan"]["candidates"]
    assert breakpoint["ok"] is True
    assert any(call[1] == "x64dbg.set_breakpoint" for call in fake.calls)


@pytest.mark.asyncio
async def test_workflow_rename_from_trace_creates_pending_suggestion(tmp_path) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()
    app.session.active_ida_ea = 0x140001000
    app.session.add_event("trace.api_call", "x64dbg", {"api": "CreateFileW", "path": "C:\\temp\\a.txt"})

    result = await app.call_tool("workflow.rename_functions_from_trace", {"limit": 5, "apply": "false"})

    assert result["suggestions"]
    assert result["suggestions"][0]["status"] == "pending"
    assert result["suggestions"][0]["suggested_value"].startswith("trace_createfile")


@pytest.mark.asyncio
async def test_phase7_resources_and_report_are_compact(tmp_path) -> None:
    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)
    app.bridges = FakeBridges()
    await app.call_tool("malware.workspace_create", {"path": str(sample), "copy_sample": "false"})
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x1000)
    app.session.add_event("breakpoint.hit", "x64dbg", {"runtime_address": "0x7ff700000100"})

    current = await app._analysis_current(10)
    modules = await app._analysis_modules(10)
    hot = app._analysis_hot_functions(10)
    report = await app.call_tool("workflow.generate_analysis_report", {})
    summary = await app.call_tool("analysis.timeline_summary", {"limit": 50})

    assert current["session"]["sample_id"] == sample.name
    assert modules["mappings"]
    assert hot["functions"]
    assert report["timeline_summary"]["groups"]
    assert summary["hot_addresses"]


@pytest.mark.asyncio
async def test_session_resume_and_list_restore_state(tmp_path) -> None:
    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)
    await app.call_tool("malware.workspace_create", {"path": str(sample), "copy_sample": "false"})
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    app.session.breakpoints.add(0x7FF700001000)
    app.session.add_event("analysis.note", "codex", {"address": "0x140001000", "text": "resume marker"})

    resumed_app = make_app(tmp_path)
    sessions = await resumed_app.call_tool("analysis.session_list", {"limit": 10})
    resumed = await resumed_app.call_tool("analysis.session_resume", {"file_sha256": app.session.file_sha256})

    assert sessions["sessions"][0]["file_sha256"] == app.session.file_sha256
    assert resumed["resumed"] is True
    assert resumed["session"]["breakpoints"] == ["0x7ff700001000"]
    assert resumed["timeline_summary"]["groups"]


@pytest.mark.asyncio
async def test_wait_for_event_returns_future_matching_event(tmp_path) -> None:
    app = make_app(tmp_path)

    async def emit_later():
        await asyncio.sleep(0.01)
        app.session.add_event("breakpoint.hit", "x64dbg", {"address": "0x401000"})

    task = asyncio.create_task(emit_later())
    result = await app.call_tool("analysis.wait_for_event", {"type": "breakpoint.hit", "address": "0x401000", "timeout": 1})
    await task

    assert result["type"] == "breakpoint.hit"
    assert result["payload"]["address"] == "0x401000"


@pytest.mark.asyncio
async def test_run_until_breakpoint_sets_runs_and_waits_for_exact_hit(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()

    def on_run(params):
        app.session.add_event("breakpoint.hit", "x64dbg", {"address": "0x401000", "registers": {"rip": "0x401000"}})
        return {"ok": True}

    fake.responses["x64dbg.run"] = on_run
    app.bridges = fake

    result = await app.call_tool("x64dbg.run_until_breakpoint", {"address": "0x401000", "timeout": 1, "remove": "true"})

    assert result["address"] == "0x401000"
    assert result["event"]["type"] == "breakpoint.hit"
    assert ("x64dbg", "x64dbg.set_breakpoint", {"address": "0x401000"}) in fake.calls
    assert ("x64dbg", "x64dbg.remove_breakpoint", {"address": "0x401000"}) in fake.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "arguments", "missing"),
    [
        ("analysis.wait_for_event", {"timeout": 1}, "type"),
        ("analysis.wait_for_event", {"type": "breakpoint.hit"}, "timeout"),
        ("x64dbg.set_temporary_breakpoint", {}, "address"),
        ("x64dbg.run_until_breakpoint", {"timeout": 1}, "address"),
        ("x64dbg.run_until_breakpoint", {"address": "0x401000"}, "timeout"),
        ("workflow.analyze_function_runtime", {"ea": "0x140001000"}, "timeout"),
    ],
)
async def test_runtime_workflows_validate_required_arguments(tmp_path, tool, arguments, missing) -> None:
    app = make_app(tmp_path)
    app.bridges = FakeBridges()

    with pytest.raises(ValueError, match=f"{tool} requires argument '{missing}'"):
        await app.call_tool(tool, arguments)


@pytest.mark.asyncio
async def test_analyze_function_runtime_collects_snapshot_and_comments(tmp_path) -> None:
    app = make_app(tmp_path)
    fake = FakeBridges()
    app.bridges = fake
    app.session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)

    def on_run(params):
        app.session.add_event(
            "breakpoint.hit",
            "x64dbg",
            {"address": "0x7ff700001000", "registers": {"rip": "0x7ff700001000"}, "thread_id": 1},
        )
        return {"ok": True}

    fake.responses["x64dbg.run"] = on_run
    fake.responses["x64dbg.breakpoint_snapshot"] = {"ok": True, "registers": {"rip": "0x7ff700001000"}, "stack": ["0x1", "0x2"]}
    fake.responses["x64dbg.read_registers"] = {"rip": "0x7ff700001000", "rsp": "0x1000"}
    fake.responses["x64dbg.call_stack"] = {"frames": [{"address": "0x7ff700001000"}]}
    fake.responses["x64dbg.read_memory"] = {"ok": True, "address": "0x7ff700001000", "bytes": "90"}
    fake.responses["ida.comment"] = {"ok": True}

    result = await app.call_tool(
        "workflow.analyze_function_runtime",
        {"ea": "0x140001000", "timeout": 1, "args_preview": 2, "memory_preview": 1, "comment": "true"},
    )

    assert result["ida_ea"] == "0x140001000"
    assert result["runtime_address"] == "0x7ff700001000"
    assert result["hit"]["type"] == "breakpoint.hit"
    assert result["registers"]["rip"] == "0x7ff700001000"
    assert result["ida_comment"] == {"ok": True}
    assert ("ida", "ida.comment", {"ea": "0x140001000", "text": "IX64MCP runtime hit at 0x7ff700001000; registers/call stack captured."}) in fake.calls


@pytest.mark.asyncio
async def test_context_budget_profiles_and_timeline_summary_are_capped(tmp_path) -> None:
    app = make_app(tmp_path)
    for index in range(200):
        app.session.add_event(
            "trace.api_call",
            "x64dbg",
            {"api": "CreateFileW", "address": hex(0x140000000 + index), "path": "A" * 1000},
        )

    budget = await app.call_tool("analysis.context_budget", {"profile": "quick"})
    summary = await app.call_tool("analysis.timeline_summary", {"limit": 200, "profile": "quick"})

    assert budget["default"]["profile"] == "quick"
    assert summary["context_budget"]["profile"] == "quick"
    assert summary["context_budget"]["estimated_bytes"] <= summary["context_budget"]["max_bytes"]
    assert len(summary["latest"][0]["payload"]["path"]) < 400


@pytest.mark.asyncio
async def test_analysis_report_and_semantic_cache_include_context_budget(tmp_path) -> None:
    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)
    await app.call_tool("malware.workspace_create", {"path": str(sample), "copy_sample": "false"})
    app.session.add_event("analysis.note", "codex", {"address": "0x140001000", "text": "important finding"})

    report = await app.call_tool("workflow.generate_analysis_report", {"profile": "quick"})
    cache = await app.call_tool("analysis.semantic_cache", {"profile": "quick"})

    assert report["context_budget"]["profile"] == "quick"
    assert "next_resource" in report["context_budget"]
    assert cache["context_budget"]["profile"] == "quick"
    assert cache["previous_agent_conclusions"]


@pytest.mark.asyncio
async def test_malware_workspace_v2_metadata_lineage_and_exports(tmp_path) -> None:
    sample = Path("build/samples/anti_debug_demo/anti_debug_demo.exe")
    if not sample.exists():
        pytest.skip("built sample is not available")
    app = make_app(tmp_path)
    workspace = await app.call_tool("malware.workspace_create", {"path": str(sample), "copy_sample": "false"})
    artifact_file = tmp_path / "dropped.bin"
    artifact_file.write_bytes(b"child")

    updated = await app.call_tool(
        "malware.workspace_update",
        {
            "status": "anti-debug",
            "tags": "anti-debug,loader",
            "sandbox": {"vm": "confirmed", "snapshot": "before-run"},
            "idb_path": "sample.i64",
        },
    )
    artifact = await app.call_tool("malware.add_artifact", {"kind": "extracted_file", "path": str(artifact_file), "note": "dropped"})
    lineage = await app.call_tool("malware.add_lineage", {"kind": "dropped_file", "path": str(artifact_file), "relationship": "dropped"})
    exported = await app.call_tool("malware.export_report", {"format": "markdown", "profile": "quick"})

    assert workspace["schema_version"] == 2
    assert updated["status"] == "anti-debug"
    assert updated["tags"] == ["anti-debug", "loader"]
    assert updated["sandbox"]["vm"] == "confirmed"
    assert artifact["hashes"]["sha256"]
    assert lineage["relationship"] == "dropped"
    assert exported["format"] == "md"
    assert Path(exported["path"]).exists()
