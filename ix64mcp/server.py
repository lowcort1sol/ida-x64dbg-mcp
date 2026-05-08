from __future__ import annotations

import argparse
import asyncio
import binascii
import json
import logging
import subprocess
import struct
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool
from pydantic import AnyUrl

from .agent_ux import (
    analysis_report,
    current_location,
    find_password_candidates,
    hot_functions,
    patch_reports,
    strcmp_imports,
    timeline_summary,
)
from .bridge import BridgeRegistry
from .config import IX64Config
from .context_budget import profile_limits, with_context_budget
from .daemon_api import daemon_request, serve_daemon_api
from .malware import (
    add_artifact,
    add_config,
    add_ioc,
    add_lineage,
    behavior_report,
    create_workspace,
    export_report,
    load_workspace_by_hash,
    sandbox_check,
    triage,
    update_workspace_metadata,
)
from .pe import pe_exports, pe_imports, pe_relocations, pe_resources, pe_summary
from .patch import apply_file_patch, diff_file_patch, plan_patches, rollback_file_patch
from .policy import PolicyEngine
from .protocol import parse_address
from .session import AnalysisSession, TimelineEvent
from .store import SessionStore
from .suggestions import Suggestion, SuggestionStore
from .runtime import SingleInstanceLock, is_port_in_use, is_process_running, runtime_diagnostics, setup_logging, stop_process


LOGGER = logging.getLogger("ix64mcp.server")

PROXY_RESOURCE_URIS = [
    "ida://session/summary",
    "x64dbg://debug/state",
    "x64dbg://memory-map",
    "x64dbg://threads",
    "x64dbg://call-stack",
    "analysis://timeline",
    "analysis://current",
    "analysis://modules",
    "analysis://functions/hot",
    "analysis://patches",
    "analysis://report",
    "analysis://suggestions",
    "analysis://trace",
    "analysis://runtime-history",
    "analysis://correlation",
    "malware://workspace",
    "malware://behavior-report",
]

PROXY_TOOL_NAMES = [
    "ida.goto",
    "ida.rename",
    "ida.comment",
    "ida.get_function",
    "ida.get_xrefs",
    "ida.list_strings",
    "ida.get_string_xrefs",
    "ida.function_summary",
    "ida.callgraph",
    "ida.cfg",
    "ida.callers",
    "ida.callees",
    "ida.string_to_functions",
    "ida.import_to_callers",
    "ida.branch_context",
    "ida.stack_var_usage",
    "ida.pseudocode",
    "ida.refresh_decompiler",
    "ida.set_decompiler_comment",
    "x64dbg.goto",
    "x64dbg.set_breakpoint",
    "x64dbg.remove_breakpoint",
    "x64dbg.run",
    "x64dbg.pause",
    "x64dbg.step_into",
    "x64dbg.step_over",
    "x64dbg.switch_thread",
    "x64dbg.read_memory",
    "x64dbg.read_registers",
    "x64dbg.runtime_snapshot",
    "x64dbg.list_modules",
    "x64dbg.memory_map",
    "x64dbg.call_stack",
    "x64dbg.threads",
    "x64dbg.exceptions",
    "x64dbg.set_hardware_breakpoint",
    "x64dbg.remove_hardware_breakpoint",
    "x64dbg.set_memory_breakpoint",
    "x64dbg.remove_memory_breakpoint",
    "x64dbg.set_conditional_breakpoint",
    "x64dbg.set_temporary_breakpoint",
    "x64dbg.breakpoint_group_add",
    "x64dbg.remove_breakpoint_group",
    "x64dbg.breakpoint_snapshot",
    "x64dbg.dump_metadata",
    "x64dbg.run_until_breakpoint",
    "trace.recipe_enable",
    "trace.recipe_disable",
    "trace.recipe_status",
    "analysis.sync_address",
    "analysis.add_note",
    "analysis.link_dynamic_static",
    "analysis.follow_debugger",
    "analysis.break_on_entry",
    "analysis.wait_for_event",
    "analysis.policy_status",
    "analysis.policy_approve",
    "analysis.policy_clear",
    "analysis.suggest_name",
    "analysis.suggest_comment",
    "analysis.suggest_type",
    "analysis.list_suggestions",
    "analysis.apply_suggestion",
    "analysis.reject_suggestion",
    "analysis.timeline_summary",
    "analysis.context_budget",
    "analysis.semantic_cache",
    "analysis.session_resume",
    "analysis.session_list",
    "analysis.runtime_history",
    "analysis.correlate_runtime_static",
    "analysis.detect_anti_debug",
    "workflow.follow_debugger",
    "workflow.explain_current_function",
    "workflow.find_password_check",
    "workflow.break_on_first_strcmp_like",
    "workflow.rename_functions_from_trace",
    "workflow.make_patch_plan",
    "workflow.generate_analysis_report",
    "workflow.analyze_function_runtime",
    "pe.summary",
    "pe.imports",
    "pe.exports",
    "pe.resources",
    "pe.relocations",
    "patch.plan",
    "patch.apply_file",
    "patch.rollback",
    "patch.diff",
    "malware.workspace_create",
    "malware.triage",
    "malware.behavior_report",
    "malware.add_ioc",
    "malware.add_config",
    "malware.workspace_update",
    "malware.add_artifact",
    "malware.add_lineage",
    "malware.export_report",
    "malware.sandbox_check",
]


def _required_arg(arguments: dict[str, Any], name: str, tool: str) -> Any:
    value = arguments.get(name)
    if value is None or value == "":
        raise ValueError(f"{tool} requires argument '{name}'")
    return value


def _required_float(
    arguments: dict[str, Any],
    name: str,
    tool: str,
    *,
    minimum: float = 0.1,
    maximum: float = 120.0,
) -> float:
    raw = _required_arg(arguments, name, tool)
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{tool} argument '{name}' must be a number") from exc
    return max(minimum, min(value, maximum))


def _hex_bytes_to_ints(hex_text: str, pointer_size: int = 8, limit: int = 64) -> list[int]:
    try:
        data = bytes.fromhex(hex_text)
    except ValueError:
        return []
    values = []
    step = max(1, pointer_size)
    for offset in range(0, min(len(data), limit * step), step):
        chunk = data[offset : offset + step]
        if len(chunk) != step:
            break
        values.append(int.from_bytes(chunk, "little"))
    return values


def json_text(value: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(value, indent=2, sort_keys=True))]


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_pe_entry(header: bytes) -> dict[str, int]:
    if len(header) < 0x100:
        raise ValueError("PE header read is too small")
    if header[:2] != b"MZ":
        raise ValueError("module base does not point to an MZ header")
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset + 0x40 > len(header):
        raise ValueError("PE header offset is outside the bytes read")
    if header[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE signature not found")
    coff_offset = pe_offset + 4
    optional_size = struct.unpack_from("<H", header, coff_offset + 16)[0]
    optional_offset = coff_offset + 20
    if optional_offset + optional_size > len(header):
        raise ValueError("optional header is outside the bytes read")
    magic = struct.unpack_from("<H", header, optional_offset)[0]
    entry_rva = struct.unpack_from("<I", header, optional_offset + 16)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", header, optional_offset + 24)[0]
        bitness = 64
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", header, optional_offset + 28)[0]
        bitness = 32
    else:
        raise ValueError(f"unsupported optional header magic: 0x{magic:x}")
    return {"entry_rva": entry_rva, "image_base": image_base, "bitness": bitness}


def _json_model(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    raise TypeError(f"cannot serialize MCP model: {type(value)!r}")


def _resource_from_json(value: dict[str, Any]) -> Resource:
    return Resource(uri=AnyUrl(str(value["uri"])), name=str(value.get("name", value["uri"])))


def _tool_from_json(value: dict[str, Any]) -> Tool:
    return Tool(name=str(value["name"]), description=value.get("description"), inputSchema=value["inputSchema"])


def proxy_resource_definitions() -> list[Resource]:
    return [Resource(uri=AnyUrl(uri), name=uri) for uri in PROXY_RESOURCE_URIS]


def proxy_tool_definitions() -> list[Tool]:
    return [
        Tool(
            name=name,
            description=f"IX64MCP daemon-proxied tool: {name}",
            inputSchema={"type": "object", "additionalProperties": True},
        )
        for name in PROXY_TOOL_NAMES
    ]


class IX64MCP:
    def __init__(self, config: IX64Config | None = None) -> None:
        self.config = config or IX64Config.from_env()
        self.session = AnalysisSession()
        self.store = SessionStore(self.config.database_path, self.config.timeline_dir)
        self.store.restore_session(self.session)
        self.store.attach(self.session)
        self.suggestions = SuggestionStore()
        self.suggestions.restore(self.store.load_suggestions(self.session.sample_id))
        self.policy = PolicyEngine.from_env()
        self.bridges = BridgeRegistry(self.session, token=self.config.token)
        self.server = Server("ix64mcp")
        self.trace_recipes: dict[str, dict[str, Any]] = {}
        self.trace_batches: list[dict[str, Any]] = []
        self.breakpoint_groups: dict[str, dict[str, Any]] = {}
        self._trace_events: list[dict[str, Any]] = []
        self._trace_flush_task: asyncio.Task[None] | None = None
        self._panel_update_task: asyncio.Task[None] | None = None
        self._panel_update_interval = 0.5
        self._trace_flush_interval = 0.5
        self._max_trace_events = 100
        self._max_trace_batches = 200
        self._event_waiters: list[tuple[dict[str, Any], asyncio.Future[TimelineEvent]]] = []
        self.session.event_sinks.append(self._on_session_event)
        self._register_handlers()

    def _register_handlers(self) -> None:
        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            return [
                Resource(uri=AnyUrl("ida://session/summary"), name="IDA/x64dbg session summary"),
                Resource(uri=AnyUrl("x64dbg://debug/state"), name="x64dbg debug state"),
                Resource(uri=AnyUrl("x64dbg://memory-map"), name="x64dbg memory map"),
                Resource(uri=AnyUrl("x64dbg://threads"), name="x64dbg threads"),
                Resource(uri=AnyUrl("x64dbg://call-stack"), name="x64dbg call stack"),
                Resource(uri=AnyUrl("analysis://timeline"), name="Analysis event timeline"),
                Resource(uri=AnyUrl("analysis://current"), name="Current analysis context"),
                Resource(uri=AnyUrl("analysis://modules"), name="Current module mappings"),
                Resource(uri=AnyUrl("analysis://functions/hot"), name="Hot functions from timeline"),
                Resource(uri=AnyUrl("analysis://patches"), name="Patch candidates and reports"),
                Resource(uri=AnyUrl("analysis://report"), name="Compact analysis report"),
                Resource(uri=AnyUrl("analysis://suggestions"), name="Analysis suggestions"),
                Resource(uri=AnyUrl("analysis://trace"), name="Analysis trace batches"),
                Resource(uri=AnyUrl("analysis://runtime-history"), name="Runtime history summary"),
                Resource(uri=AnyUrl("analysis://correlation"), name="Runtime/static correlation"),
                Resource(uri=AnyUrl("malware://workspace"), name="Malware sample workspace"),
                Resource(uri=AnyUrl("malware://behavior-report"), name="Malware behavior report"),
            ]

        @self.server.read_resource()
        async def read_resource(uri: AnyUrl) -> str:
            text = str(uri)
            if text == "ida://session/summary":
                return json.dumps(self.session.summary(self.bridges.connected()), indent=2, sort_keys=True)
            if text == "x64dbg://debug/state":
                return json.dumps(
                    {
                        "active_runtime_address": self.session.active_runtime_address,
                        "registers": self.session.registers,
                        "connected": self.bridges.connected()["x64dbg"],
                    },
                    indent=2,
                    sort_keys=True,
                )
            if text.startswith("analysis://timeline"):
                parsed = urlparse(text)
                limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
                if self.session.timeline:
                    events = self.session.timeline[-max(1, min(limit, 1000)) :]
                    return "\n".join(json.dumps(event.as_json(), sort_keys=True) for event in events)
                return "\n".join(json.dumps(event, sort_keys=True) for event in self.store.latest_events(limit))
            if text.startswith("analysis://current"):
                parsed = urlparse(text)
                limit = int(parse_qs(parsed.query).get("limit", ["20"])[0])
                return json.dumps(await self._analysis_current(limit), indent=2, sort_keys=True)
            if text.startswith("analysis://modules"):
                parsed = urlparse(text)
                limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
                return json.dumps(await self._analysis_modules(limit), indent=2, sort_keys=True)
            if text.startswith("analysis://functions/hot"):
                parsed = urlparse(text)
                limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                return json.dumps(self._analysis_hot_functions(limit), indent=2, sort_keys=True)
            if text.startswith("analysis://patches"):
                parsed = urlparse(text)
                limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                return json.dumps(patch_reports(self.config.state_dir, self.session, limit), indent=2, sort_keys=True)
            if text.startswith("analysis://report"):
                parsed = urlparse(text)
                profile = parse_qs(parsed.query).get("profile", ["compact"])[0]
                return json.dumps(self._analysis_report(profile), indent=2, sort_keys=True)
            if text.startswith("analysis://trace"):
                parsed = urlparse(text)
                limit = max(1, min(int(parse_qs(parsed.query).get("limit", ["50"])[0]), self._max_trace_batches))
                return json.dumps({"batches": self.trace_batches[-limit:]}, indent=2, sort_keys=True)
            if text.startswith("analysis://runtime-history"):
                parsed = urlparse(text)
                limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
                return json.dumps(self._runtime_history(limit), indent=2, sort_keys=True)
            if text.startswith("analysis://correlation"):
                parsed = urlparse(text)
                query = parse_qs(parsed.query)
                address = query.get("address", [None])[0]
                return json.dumps(await self._correlate_runtime_static({"address": address} if address else {}), indent=2, sort_keys=True)
            if text == "analysis://suggestions":
                return json.dumps(self.suggestions.list(limit=200), indent=2, sort_keys=True)
            if text == "malware://workspace":
                workspace = load_workspace_by_hash(self.config.state_dir, self.session.file_sha256)
                return json.dumps(workspace or {}, indent=2, sort_keys=True)
            if text == "malware://behavior-report":
                workspace = load_workspace_by_hash(self.config.state_dir, self.session.file_sha256)
                return json.dumps(behavior_report(self.session, self.session.timeline, workspace), indent=2, sort_keys=True)
            if text == "x64dbg://memory-map":
                result = await self.bridges.request("x64dbg", "x64dbg.memory_map", {"limit": 512, "offset": 0})
                return json.dumps(result, indent=2, sort_keys=True)
            if text == "x64dbg://threads":
                result = await self.bridges.request("x64dbg", "x64dbg.threads", {})
                return json.dumps(result, indent=2, sort_keys=True)
            if text == "x64dbg://call-stack":
                result = await self.bridges.request("x64dbg", "x64dbg.call_stack", {"limit": 64})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://function/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.get_function", {"ea": hex(ea)})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://callgraph/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.callgraph", {"ea": hex(ea), "depth": 2, "limit": 200})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://cfg/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.cfg", {"ea": hex(ea), "limit": 300})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://callers/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.callers", {"ea": hex(ea), "limit": 200})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://callees/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.callees", {"ea": hex(ea), "limit": 200})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://pseudocode/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.pseudocode", {"ea": hex(ea), "max_chars": 12000, "offset": 0})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("ida://decompile/"):
                ea = parse_address(text.rsplit("/", 1)[1])
                result = await self.bridges.request("ida", "ida.decompile", {"ea": hex(ea)})
                return json.dumps(result, indent=2, sort_keys=True)
            if text.startswith("x64dbg://memory/"):
                parts = text.removeprefix("x64dbg://memory/").split("/")
                if len(parts) != 2:
                    raise ValueError("memory resource must be x64dbg://memory/{address}/{size}")
                address_text, size_text = parts
                result = await self.bridges.request(
                    "x64dbg",
                    "x64dbg.read_memory",
                    {"address": address_text, "size": parse_address(size_text)},
                )
                return json.dumps(result, indent=2, sort_keys=True)
            raise ValueError(f"unknown resource: {text}")

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                self._tool("ida.goto", {"ea": "string"}),
                self._tool("ida.rename", {"ea": "string", "name": "string"}),
                self._tool("ida.comment", {"ea": "string", "text": "string"}),
                self._tool("ida.get_function", {"ea": "string"}),
                self._tool("ida.get_xrefs", {"ea": "string"}),
                self._tool("ida.list_strings", {"query": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("ida.get_string_xrefs", {"address": "string", "limit": "integer"}, required=["address"]),
                self._tool(
                    "ida.function_summary",
                    {"ea": "string", "detail": "string", "max_pseudocode_chars": "integer"},
                    required=["ea"],
                ),
                self._tool("ida.callgraph", {"ea": "string", "depth": "integer", "limit": "integer"}, required=["ea"]),
                self._tool("ida.cfg", {"ea": "string", "limit": "integer"}, required=["ea"]),
                self._tool("ida.callers", {"ea": "string", "limit": "integer"}, required=["ea"]),
                self._tool("ida.callees", {"ea": "string", "limit": "integer"}, required=["ea"]),
                self._tool("ida.string_to_functions", {"address": "string", "limit": "integer"}, required=["address"]),
                self._tool("ida.import_to_callers", {"name": "string", "limit": "integer"}, required=["name"]),
                self._tool("ida.branch_context", {"ea": "string", "window": "integer"}, required=["ea"]),
                self._tool("ida.stack_var_usage", {"ea": "string", "name": "string", "limit": "integer"}, required=["ea"]),
                self._tool("ida.pseudocode", {"ea": "string", "max_chars": "integer", "offset": "integer"}, required=["ea"]),
                self._tool("ida.refresh_decompiler", {"ea": "string"}),
                self._tool("ida.set_decompiler_comment", {"ea": "string", "text": "string"}),
                self._tool("x64dbg.goto", {"address": "string"}, required=["address"]),
                self._tool("x64dbg.set_breakpoint", {"address": "string"}, required=["address"]),
                self._tool("x64dbg.remove_breakpoint", {"address": "string"}, required=["address"]),
                self._tool("x64dbg.run", {}),
                self._tool("x64dbg.pause", {}),
                self._tool("x64dbg.step_into", {}),
                self._tool("x64dbg.step_over", {}),
                self._tool("x64dbg.switch_thread", {"thread_id": "string"}, required=["thread_id"]),
                self._tool("x64dbg.read_memory", {"address": "string", "size": "integer"}, required=["address", "size"]),
                self._tool("x64dbg.read_registers", {}),
                self._tool(
                    "x64dbg.runtime_snapshot",
                    {
                        "address": "string",
                        "memory_preview": "integer",
                        "stack_preview": "integer",
                        "call_stack_limit": "integer",
                    },
                    required=[],
                ),
                self._tool("x64dbg.list_modules", {}),
                self._tool("x64dbg.memory_map", {"limit": "integer", "offset": "integer"}, required=[]),
                self._tool("x64dbg.call_stack", {"limit": "integer"}, required=[]),
                self._tool("x64dbg.threads", {}),
                self._tool("x64dbg.exceptions", {"limit": "integer", "offset": "integer"}, required=[]),
                self._tool("x64dbg.set_hardware_breakpoint", {"address": "string", "access": "string", "size": "integer"}, required=["address"]),
                self._tool("x64dbg.remove_hardware_breakpoint", {"address": "string"}, required=["address"]),
                self._tool("x64dbg.set_memory_breakpoint", {"address": "string", "size": "integer", "access": "string"}, required=["address"]),
                self._tool("x64dbg.remove_memory_breakpoint", {"address": "string"}, required=["address"]),
                self._tool("x64dbg.set_conditional_breakpoint", {"address": "string", "condition": "string", "log_text": "string"}, required=["address", "condition"]),
                self._tool("x64dbg.set_temporary_breakpoint", {"address": "string", "group": "string", "one_shot": "string"}, required=["address"]),
                self._tool("x64dbg.breakpoint_group_add", {"name": "string", "addresses": "array", "kind": "string"}, required=["name", "addresses"]),
                self._tool("x64dbg.remove_breakpoint_group", {"name": "string"}, required=["name"]),
                self._tool("x64dbg.breakpoint_snapshot", {"address": "string"}, required=[]),
                self._tool("x64dbg.dump_metadata", {"address": "string", "size": "integer"}, required=["address", "size"]),
                self._tool("x64dbg.run_until_breakpoint", {"address": "string", "timeout": "integer", "remove": "string"}, required=["address", "timeout"]),
                self._tool("trace.recipe_enable", {"name": "string", "options": "object"}, required=["name"]),
                self._tool("trace.recipe_disable", {"name": "string"}),
                self._tool("trace.recipe_status", {}),
                self._tool("analysis.sync_address", {"source": "string", "address": "string"}),
                self._tool("analysis.add_note", {"address": "string", "text": "string"}),
                self._tool("analysis.link_dynamic_static", {"runtime_address": "string", "ida_ea": "string"}),
                self._tool("analysis.follow_debugger", {}),
                self._tool("analysis.break_on_entry", {"module": "string", "run": "string"}, required=[]),
                self._tool("analysis.wait_for_event", {"type": "string", "address": "string", "timeout": "integer"}, required=["type", "timeout"]),
                self._tool("analysis.policy_status", {}),
                self._tool("analysis.policy_approve", {"action": "string", "reason": "string"}, required=["action"]),
                self._tool("analysis.policy_clear", {"action": "string"}, required=[]),
                self._tool("analysis.suggest_name", {"target": "string", "suggested_value": "string", "reason": "string"}, required=["target", "suggested_value"]),
                self._tool("analysis.suggest_comment", {"target": "string", "text": "string", "reason": "string", "kind": "string"}, required=["target", "text"]),
                self._tool(
                    "analysis.suggest_type",
                    {"target": "string", "suggested_value": "string", "reason": "string", "confidence": "number"},
                    required=["target", "suggested_value"],
                ),
                self._tool("analysis.list_suggestions", {"status": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("analysis.apply_suggestion", {"id": "string"}),
                self._tool("analysis.reject_suggestion", {"id": "string", "reason": "string"}, required=["id"]),
                self._tool("analysis.timeline_summary", {"limit": "integer", "window": "string", "profile": "string"}, required=[]),
                self._tool("analysis.context_budget", {"profile": "string"}, required=[]),
                self._tool("analysis.semantic_cache", {"profile": "string"}, required=[]),
                self._tool("analysis.session_resume", {"sample_id": "string", "file_sha256": "string"}, required=[]),
                self._tool("analysis.session_list", {"limit": "integer"}, required=[]),
                self._tool("analysis.runtime_history", {"limit": "integer"}, required=[]),
                self._tool("analysis.correlate_runtime_static", {"address": "string", "include_summary": "string"}, required=[]),
                self._tool("analysis.detect_anti_debug", {"limit": "integer"}, required=[]),
                self._tool("workflow.follow_debugger", {}),
                self._tool("workflow.explain_current_function", {"max_pseudocode_chars": "integer"}, required=[]),
                self._tool("workflow.find_password_check", {"limit": "integer"}, required=[]),
                self._tool("workflow.break_on_first_strcmp_like", {"run": "string"}, required=[]),
                self._tool("workflow.rename_functions_from_trace", {"limit": "integer", "apply": "string"}, required=[]),
                self._tool("workflow.make_patch_plan", {"limit": "integer"}, required=[]),
                self._tool("workflow.generate_analysis_report", {"profile": "string"}, required=[]),
                self._tool(
                    "workflow.capture_compare_context",
                    {"address": "string", "memory_preview": "integer", "stack_preview": "integer", "call_stack_limit": "integer"},
                    required=[],
                ),
                self._tool(
                    "workflow.analyze_function_runtime",
                    {
                        "ea": "string",
                        "address": "string",
                        "timeout": "integer",
                        "args_preview": "integer",
                        "memory_preview": "integer",
                        "comment": "string",
                    },
                    required=["timeout"],
                ),
                self._tool("pe.summary", {"path": "string", "limit": "integer"}, required=[]),
                self._tool("pe.imports", {"path": "string", "dll": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("pe.exports", {"path": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("pe.resources", {"path": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("pe.relocations", {"path": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("patch.plan", {"path": "string", "limit": "integer", "window": "integer"}, required=[]),
                self._tool(
                    "patch.apply_file",
                    {
                        "path": "string",
                        "file_offset": "string",
                        "expected_hex": "string",
                        "patch_hex": "string",
                        "reason": "string",
                        "output_path": "string",
                    },
                    required=["path", "file_offset", "expected_hex", "patch_hex"],
                ),
                self._tool("patch.rollback", {"path": "string", "backup_path": "string"}),
                self._tool("patch.diff", {"path": "string", "backup_path": "string", "limit": "integer"}),
                self._tool(
                    "malware.workspace_create",
                    {
                        "path": "string",
                        "idb_path": "string",
                        "debugger_session_path": "string",
                        "notes": "string",
                        "copy_sample": "string",
                    },
                    required=[],
                ),
                self._tool("malware.triage", {"path": "string", "limit": "integer"}, required=[]),
                self._tool("malware.behavior_report", {}),
                self._tool("malware.add_ioc", {"sample_sha256": "string", "kind": "string", "value": "string", "source": "string", "note": "string"}, required=["kind", "value"]),
                self._tool(
                    "malware.add_config",
                    {"sample_sha256": "string", "key": "string", "value": "string", "source": "string", "confidence": "string"},
                    required=["key", "value"],
                ),
                self._tool(
                    "malware.workspace_update",
                    {
                        "sample_sha256": "string",
                        "status": "string",
                        "tags": "string",
                        "sandbox": "object",
                        "idb_path": "string",
                        "debugger_session_path": "string",
                    },
                    required=[],
                ),
                self._tool("malware.add_artifact", {"sample_sha256": "string", "kind": "string", "path": "string", "source": "string", "note": "string"}, required=["kind", "path"]),
                self._tool(
                    "malware.add_lineage",
                    {"sample_sha256": "string", "kind": "string", "path": "string", "relationship": "string", "note": "string"},
                    required=["kind", "path"],
                ),
                self._tool("malware.export_report", {"sample_sha256": "string", "format": "string", "profile": "string"}, required=[]),
                self._tool(
                    "malware.sandbox_check",
                    {"allow_network": "string", "vm_confirmed": "string", "snapshot_confirmed": "string"},
                    required=[],
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            result = await self.call_tool(name, arguments or {})
            return json_text(result)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.policy.require(name)
        if name.startswith("ida."):
            result = await self.bridges.request("ida", name, arguments)
            self._record_mutation(name, "ida", arguments)
            return result

        if name == "x64dbg.run_until_breakpoint":
            return await self._run_until_breakpoint(arguments)
        if name == "x64dbg.set_temporary_breakpoint":
            return await self._set_temporary_breakpoint(arguments)
        if name == "x64dbg.runtime_snapshot":
            return await self._runtime_snapshot(arguments)
        if name == "x64dbg.breakpoint_group_add":
            return await self._breakpoint_group_add(arguments)
        if name == "x64dbg.remove_breakpoint_group":
            return await self._remove_breakpoint_group(str(arguments["name"]))

        if name.startswith("x64dbg."):
            required_by_tool = {
                "x64dbg.switch_thread": ("thread_id",),
                "x64dbg.goto": ("address",),
                "x64dbg.set_breakpoint": ("address",),
                "x64dbg.remove_breakpoint": ("address",),
                "x64dbg.read_memory": ("address", "size"),
                "x64dbg.set_hardware_breakpoint": ("address",),
                "x64dbg.remove_hardware_breakpoint": ("address",),
                "x64dbg.set_memory_breakpoint": ("address",),
                "x64dbg.remove_memory_breakpoint": ("address",),
                "x64dbg.set_conditional_breakpoint": ("address", "condition"),
                "x64dbg.dump_metadata": ("address", "size"),
            }
            for required in required_by_tool.get(name, ()):
                _required_arg(arguments, required, name)
            result = await self.bridges.request("x64dbg", name, arguments)
            if name == "x64dbg.set_breakpoint":
                self.session.breakpoints.add(parse_address(arguments["address"]))
            if name == "x64dbg.remove_breakpoint":
                self.session.breakpoints.discard(parse_address(arguments["address"]))
            self._record_mutation(name, "x64dbg", arguments)
            return result

        if name == "trace.recipe_enable":
            return await self._trace_recipe_enable(arguments)
        if name == "trace.recipe_disable":
            return await self._trace_recipe_disable(str(arguments["name"]))
        if name == "trace.recipe_status":
            return {"recipes": list(self.trace_recipes.values()), "recent_batches": self.trace_batches[-10:]}

        if name == "analysis.sync_address":
            return await self._sync_address(arguments)
        if name == "analysis.add_note":
            address = parse_address(arguments["address"])
            event = self.session.add_event("analysis.note", "codex", {"address": hex(address), "text": arguments["text"]})
            return event.as_json()
        if name == "analysis.link_dynamic_static":
            runtime = parse_address(_required_arg(arguments, "runtime_address", name))
            ida_ea = parse_address(_required_arg(arguments, "ida_ea", name))
            self.session.upsert_mapping("manual", ida_base=ida_ea, runtime_base=runtime, size=None)
            event = self.session.add_event(
                "analysis.linked",
                "codex",
                {"runtime_address": hex(runtime), "ida_ea": hex(ida_ea)},
            )
            return event.as_json()
        if name == "analysis.follow_debugger":
            if self.session.active_runtime_address is None:
                raise ValueError("no active x64dbg runtime address")
            return await self._sync_address({"source": "x64dbg", "address": hex(self.session.active_runtime_address)})
        if name == "analysis.break_on_entry":
            return await self._break_on_entry(arguments)
        if name == "analysis.wait_for_event":
            timeout = _required_float(arguments, "timeout", name)
            event = await self._wait_for_event(
                {"type": str(_required_arg(arguments, "type", name)), "address": arguments.get("address")},
                timeout,
            )
            return event.as_json()
        if name == "analysis.policy_status":
            return self.policy.status()
        if name == "analysis.policy_approve":
            approval = self.policy.approve(str(arguments["action"]), str(arguments.get("reason", "")))
            self.session.add_event("policy.approved", "codex", approval)
            return approval
        if name == "analysis.policy_clear":
            result = self.policy.clear(None if arguments.get("action") is None else str(arguments["action"]))
            self.session.add_event("policy.cleared", "codex", result)
            return result
        if name == "analysis.suggest_name":
            return await self._create_suggestion("name", str(arguments["target"]), str(arguments["suggested_value"]), str(arguments.get("reason", "")))
        if name == "analysis.suggest_comment":
            kind = str(arguments.get("kind", "comment"))
            if kind not in {"comment", "decompiler_comment"}:
                raise ValueError("comment suggestion kind must be 'comment' or 'decompiler_comment'")
            return await self._create_suggestion(kind, str(arguments["target"]), str(arguments["text"]), str(arguments.get("reason", "")))
        if name == "analysis.suggest_type":
            confidence = arguments.get("confidence")
            reason = str(arguments.get("reason", ""))
            if confidence is not None:
                reason = f"{reason} confidence={float(confidence):.2f}".strip()
            return await self._create_suggestion("type", str(arguments["target"]), str(arguments["suggested_value"]), reason)
        if name == "analysis.list_suggestions":
            return self.suggestions.list(
                None if arguments.get("status") is None else str(arguments["status"]),
                int(arguments.get("limit", 100)),
                int(arguments.get("offset", 0)),
            )
        if name == "analysis.apply_suggestion":
            return await self._apply_suggestion(str(arguments["id"]))
        if name == "analysis.reject_suggestion":
            return await self._reject_suggestion(str(arguments["id"]), str(arguments.get("reason", "")))
        if name == "analysis.timeline_summary":
            return timeline_summary(
                self.session.timeline or self.store.latest_events(int(arguments.get("limit", 200))),
                arguments.get("limit"),
                arguments.get("profile"),
            )
        if name == "analysis.context_budget":
            return {"profiles": {name: profile_limits(name) for name in ("quick", "compact", "deep", "forensic")}, "default": profile_limits(arguments.get("profile"))}
        if name == "analysis.semantic_cache":
            profile = arguments.get("profile")
            return with_context_budget(
                {
                    "function_summaries": self._analysis_hot_functions(50),
                    "trace_summaries": timeline_summary(self.session.timeline, 300, profile),
                    "patch_candidates": patch_reports(self.config.state_dir, self.session, 50),
                    "behavior_summary": behavior_report(
                        self.session,
                        self.session.timeline,
                        load_workspace_by_hash(self.config.state_dir, self.session.file_sha256),
                    ),
                    "previous_agent_conclusions": [event.as_json() for event in self.session.timeline if event.type in {"analysis.note", "workflow.function_runtime.analyzed"}][-50:],
                },
                profile,
                next_resource="analysis://report?profile=deep",
                recommended_followup="Use this semantic cache before reading raw timeline or large pseudocode resources.",
            )
        if name == "analysis.session_resume":
            return self._session_resume(arguments)
        if name == "analysis.session_list":
            return {"sessions": self.store.list_sessions(int(arguments.get("limit", 20)))}
        if name == "analysis.runtime_history":
            return self._runtime_history(int(arguments.get("limit", 200)))
        if name == "analysis.correlate_runtime_static":
            return await self._correlate_runtime_static(arguments)
        if name == "analysis.detect_anti_debug":
            return self._detect_anti_debug(int(arguments.get("limit", 200)))
        if name.startswith("workflow."):
            return await self._workflow_tool(name, arguments)
        if name.startswith("pe."):
            return self._pe_tool(name, arguments)
        if name.startswith("patch."):
            return self._patch_tool(name, arguments)
        if name.startswith("malware."):
            return self._malware_tool(name, arguments)
        raise ValueError(f"unknown tool: {name}")

    async def daemon_api(self, method: str, params: dict[str, Any]) -> Any:
        if method == "daemon.health":
            return {
                "ok": True,
                "version": "0.1.0",
                "capabilities": {
                    "bridge": ["ida", "x64dbg"],
                    "daemon_api": ["mcp.list_tools", "mcp.list_resources", "mcp.call_tool", "mcp.read_resource"],
                },
                "session": self.session.summary(self.bridges.connected()),
            }
        if method == "mcp.list_tools":
            return [_json_model(tool) for tool in proxy_tool_definitions()]
        if method == "mcp.list_resources":
            return [_json_model(resource) for resource in proxy_resource_definitions()]
        if method == "mcp.call_tool":
            return await self.call_tool(str(params["name"]), params.get("arguments", {}) if isinstance(params.get("arguments"), dict) else {})
        if method == "mcp.read_resource":
            return await self._read_resource_value(str(params["uri"]))
        raise ValueError(f"unknown daemon API method: {method}")

    async def _read_resource_value(self, text: str) -> str:
        if text == "ida://session/summary":
            return json.dumps(self.session.summary(self.bridges.connected()), indent=2, sort_keys=True)
        if text == "x64dbg://debug/state":
            return json.dumps(
                {
                    "active_runtime_address": self.session.active_runtime_address,
                    "registers": self.session.registers,
                    "connected": self.bridges.connected()["x64dbg"],
                },
                indent=2,
                sort_keys=True,
            )
        if text.startswith("analysis://timeline"):
            parsed = urlparse(text)
            limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
            if self.session.timeline:
                events = self.session.timeline[-max(1, min(limit, 1000)) :]
                return "\n".join(json.dumps(event.as_json(), sort_keys=True) for event in events)
            return "\n".join(json.dumps(event, sort_keys=True) for event in self.store.latest_events(limit))
        if text.startswith("analysis://current"):
            parsed = urlparse(text)
            limit = int(parse_qs(parsed.query).get("limit", ["20"])[0])
            return json.dumps(await self._analysis_current(limit), indent=2, sort_keys=True)
        if text.startswith("analysis://modules"):
            parsed = urlparse(text)
            limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
            return json.dumps(await self._analysis_modules(limit), indent=2, sort_keys=True)
        if text.startswith("analysis://functions/hot"):
            parsed = urlparse(text)
            limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
            return json.dumps(self._analysis_hot_functions(limit), indent=2, sort_keys=True)
        if text.startswith("analysis://patches"):
            parsed = urlparse(text)
            limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
            return json.dumps(patch_reports(self.config.state_dir, self.session, limit), indent=2, sort_keys=True)
        if text.startswith("analysis://report"):
            parsed = urlparse(text)
            profile = parse_qs(parsed.query).get("profile", ["compact"])[0]
            return json.dumps(self._analysis_report(profile), indent=2, sort_keys=True)
        if text.startswith("analysis://trace"):
            parsed = urlparse(text)
            limit = max(1, min(int(parse_qs(parsed.query).get("limit", ["50"])[0]), self._max_trace_batches))
            return json.dumps({"batches": self.trace_batches[-limit:]}, indent=2, sort_keys=True)
        if text.startswith("analysis://runtime-history"):
            parsed = urlparse(text)
            limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
            return json.dumps(self._runtime_history(limit), indent=2, sort_keys=True)
        if text.startswith("analysis://correlation"):
            parsed = urlparse(text)
            query = parse_qs(parsed.query)
            address = query.get("address", [None])[0]
            return json.dumps(await self._correlate_runtime_static({"address": address} if address else {}), indent=2, sort_keys=True)
        if text == "analysis://suggestions":
            return json.dumps(self.suggestions.list(limit=200), indent=2, sort_keys=True)
        if text == "malware://workspace":
            workspace = load_workspace_by_hash(self.config.state_dir, self.session.file_sha256)
            return json.dumps(workspace or {}, indent=2, sort_keys=True)
        if text == "malware://behavior-report":
            workspace = load_workspace_by_hash(self.config.state_dir, self.session.file_sha256)
            return json.dumps(behavior_report(self.session, self.session.timeline, workspace), indent=2, sort_keys=True)
        if text == "x64dbg://memory-map":
            result = await self.bridges.request("x64dbg", "x64dbg.memory_map", {"limit": 512, "offset": 0})
            return json.dumps(result, indent=2, sort_keys=True)
        if text == "x64dbg://threads":
            result = await self.bridges.request("x64dbg", "x64dbg.threads", {})
            return json.dumps(result, indent=2, sort_keys=True)
        if text == "x64dbg://call-stack":
            result = await self.bridges.request("x64dbg", "x64dbg.call_stack", {"limit": 64})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://function/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.get_function", {"ea": hex(ea)})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://callgraph/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.callgraph", {"ea": hex(ea), "depth": 2, "limit": 200})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://cfg/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.cfg", {"ea": hex(ea), "limit": 300})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://callers/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.callers", {"ea": hex(ea), "limit": 200})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://callees/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.callees", {"ea": hex(ea), "limit": 200})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://pseudocode/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.pseudocode", {"ea": hex(ea), "max_chars": 12000, "offset": 0})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("ida://decompile/"):
            ea = parse_address(text.rsplit("/", 1)[1])
            result = await self.bridges.request("ida", "ida.decompile", {"ea": hex(ea)})
            return json.dumps(result, indent=2, sort_keys=True)
        if text.startswith("x64dbg://memory/"):
            parts = text.removeprefix("x64dbg://memory/").split("/")
            if len(parts) != 2:
                raise ValueError("memory resource must be x64dbg://memory/{address}/{size}")
            address_text, size_text = parts
            result = await self.bridges.request(
                "x64dbg",
                "x64dbg.read_memory",
                {"address": address_text, "size": parse_address(size_text)},
            )
            return json.dumps(result, indent=2, sort_keys=True)
        raise ValueError(f"unknown resource: {text}")

    async def _workflow_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "workflow.follow_debugger":
            result = await self.call_tool("analysis.follow_debugger", {})
            return {"workflow": name, "sync": result, "current": await self._analysis_current(10)}
        if name == "workflow.explain_current_function":
            location = current_location(self.session)
            if not location["ida_ea"]:
                raise ValueError("no current IDA/debugger address is available")
            max_chars = int(arguments.get("max_pseudocode_chars", 4000))
            summary = await self.bridges.request(
                "ida",
                "ida.function_summary",
                {"ea": location["ida_ea"], "detail": "compact", "max_pseudocode_chars": max_chars},
            )
            pseudocode = None
            if max_chars > 0:
                try:
                    pseudocode = await self.bridges.request(
                        "ida",
                        "ida.pseudocode",
                        {"ea": location["ida_ea"], "max_chars": max_chars, "offset": 0},
                    )
                except Exception as exc:
                    pseudocode = {"error": str(exc)}
            return {"workflow": name, "location": location, "function_summary": summary, "pseudocode": pseudocode}
        if name == "workflow.find_password_check":
            limit = int(arguments.get("limit", 20))
            ida_strings = []
            if self.bridges.connected().get("ida"):
                for query in ("pass", "wrong", "correct", "success", "fail"):
                    try:
                        result = await self.bridges.request("ida", "ida.list_strings", {"query": query, "limit": limit, "offset": 0})
                        ida_strings.extend(result.get("strings", result.get("items", [])))
                    except Exception:
                        pass
            patch_plan = self._safe_patch_plan(limit)
            triage_result = self._safe_triage(limit)
            return find_password_candidates(ida_strings, patch_plan, triage_result, limit)
        if name == "workflow.break_on_first_strcmp_like":
            imports = self._safe_imports(1000)
            matches = strcmp_imports(imports, 20)
            if not matches:
                return {"ok": False, "error": "no strcmp-like import found", "matches": []}
            selected = matches[0]
            static_iat = parse_address(selected["iat"])
            runtime_address = self.session.ida_to_runtime(static_iat) or static_iat
            await self.bridges.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(runtime_address)})
            self.session.breakpoints.add(runtime_address)
            if _parse_bool(arguments.get("run"), default=False):
                await self.bridges.request("x64dbg", "x64dbg.run", {})
                self._record_mutation("x64dbg.run", "x64dbg", {})
            event = self.session.add_event(
                "workflow.break_on_first_strcmp_like",
                "codex",
                {"import": selected, "runtime_address": hex(runtime_address), "run": _parse_bool(arguments.get("run"), False)},
            )
            return {"ok": True, "selected": selected, "runtime_address": hex(runtime_address), "event": event.as_json()}
        if name == "workflow.rename_functions_from_trace":
            limit = int(arguments.get("limit", 20))
            apply = _parse_bool(arguments.get("apply"), default=False)
            suggestions = []
            for candidate in self._trace_name_candidates(limit):
                created = await self._create_suggestion("name", candidate["target"], candidate["name"], candidate["reason"])
                suggestions.append(created)
                if apply:
                    suggestions[-1] = await self._apply_suggestion(created["id"])
            return {"workflow": name, "apply": apply, "suggestions": suggestions}
        if name == "workflow.make_patch_plan":
            limit = int(arguments.get("limit", 50))
            plan = self._safe_patch_plan(limit)
            if plan is None:
                raise ValueError("no active sample path is available for patch planning")
            return {"workflow": name, "plan": plan, "explanation": "read-only patch plan; no bytes were modified"}
        if name == "workflow.generate_analysis_report":
            return self._analysis_report(arguments.get("profile"))
        if name == "workflow.capture_compare_context":
            return await self._capture_compare_context(arguments)
        if name == "workflow.analyze_function_runtime":
            return await self._analyze_function_runtime(arguments)
        raise ValueError(f"unknown workflow tool: {name}")

    async def _run_until_breakpoint(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = "x64dbg.run_until_breakpoint"
        address = parse_address(_required_arg(arguments, "address", tool))
        timeout = _required_float(arguments, "timeout", tool)
        await self.bridges.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(address)})
        self.session.breakpoints.add(address)
        wait_task = asyncio.create_task(
            self._wait_for_event({"type": "breakpoint.hit", "address": hex(address), "after_index": len(self.session.timeline)}, timeout)
        )
        await asyncio.sleep(0)
        await self.bridges.request("x64dbg", "x64dbg.run", {})
        self._record_mutation("x64dbg.run", "x64dbg", {})
        try:
            event = await wait_task
        except asyncio.TimeoutError:
            diagnostic = await self._runtime_timeout_diagnostic(address, timeout)
            self.session.add_event("x64dbg.run_until_breakpoint.timeout", "codex", diagnostic)
            raise TimeoutError(json.dumps(diagnostic, sort_keys=True))
        if _parse_bool(arguments.get("remove"), default=False):
            await self.bridges.request("x64dbg", "x64dbg.remove_breakpoint", {"address": hex(address)})
            self.session.breakpoints.discard(address)
        payload = {"address": hex(address), "timeout": timeout, "event": event.as_json()}
        self.session.add_event("x64dbg.run_until_breakpoint", "codex", payload)
        return payload

    async def _set_temporary_breakpoint(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = "x64dbg.set_temporary_breakpoint"
        address = parse_address(_required_arg(arguments, "address", tool))
        group = str(arguments.get("group") or "temporary")
        result = await self.bridges.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(address)})
        self.session.breakpoints.add(address)
        entry = {"address": hex(address), "kind": "software", "temporary": True, "one_shot": _parse_bool(arguments.get("one_shot"), True)}
        group_state = self.breakpoint_groups.setdefault(group, {"name": group, "breakpoints": []})
        group_state["breakpoints"] = [item for item in group_state["breakpoints"] if item.get("address") != hex(address)]
        group_state["breakpoints"].append(entry)
        payload = {"group": group, "breakpoint": entry, "bridge": result}
        self.session.add_event("x64dbg.temporary_breakpoint.set", "codex", payload)
        return payload

    async def _runtime_snapshot(self, arguments: dict[str, Any]) -> dict[str, Any]:
        registers = await self.bridges.request("x64dbg", "x64dbg.read_registers", {})
        register_map = registers if isinstance(registers, dict) else {}
        for key in ("cip", "rip", "eip"):
            if register_map.get(key):
                current_address = parse_address(str(register_map[key]))
                break
        else:
            current_address = self.session.active_runtime_address

        address_text = arguments.get("address")
        target_address = parse_address(str(address_text)) if address_text else current_address
        memory_preview = max(0, min(int(arguments.get("memory_preview", 64)), 4096))
        stack_preview = max(0, min(int(arguments.get("stack_preview", 128)), 4096))
        call_stack_limit = max(0, min(int(arguments.get("call_stack_limit", 32)), 128))

        errors: dict[str, str] = {}
        snapshot = None
        memory = None
        stack = None
        call_stack = None
        threads = None
        exceptions = None

        if target_address is not None:
            try:
                snapshot = await self.bridges.request("x64dbg", "x64dbg.breakpoint_snapshot", {"address": hex(target_address)})
            except Exception as exc:
                errors["breakpoint_snapshot"] = str(exc)
            if memory_preview:
                try:
                    memory = await self.bridges.request("x64dbg", "x64dbg.read_memory", {"address": hex(target_address), "size": memory_preview})
                except Exception as exc:
                    errors["memory"] = str(exc)

        stack_pointer = None
        for key in ("csp", "rsp", "esp"):
            if register_map.get(key):
                stack_pointer = parse_address(str(register_map[key]))
                break
        if stack_pointer is not None and stack_preview:
            try:
                stack = await self.bridges.request("x64dbg", "x64dbg.read_memory", {"address": hex(stack_pointer), "size": stack_preview})
            except Exception as exc:
                errors["stack"] = str(exc)

        if call_stack_limit:
            try:
                call_stack = await self.bridges.request("x64dbg", "x64dbg.call_stack", {"limit": call_stack_limit})
            except Exception as exc:
                errors["call_stack"] = str(exc)
        try:
            threads = await self.bridges.request("x64dbg", "x64dbg.threads", {})
        except Exception as exc:
            errors["threads"] = str(exc)
        try:
            exceptions = await self.bridges.request("x64dbg", "x64dbg.exceptions", {"limit": 10, "offset": 0})
        except Exception as exc:
            errors["exceptions"] = str(exc)

        fallback_call_stack = None
        if call_stack_limit and (not isinstance(call_stack, dict) or not call_stack.get("frames")) and isinstance(stack, dict):
            fallback_call_stack = self._fallback_call_stack_from_stack_memory(stack, call_stack_limit)

        payload = {
            "ok": True,
            "address": None if target_address is None else hex(target_address),
            "stack_pointer": None if stack_pointer is None else hex(stack_pointer),
            "registers": registers,
            "snapshot": snapshot,
            "memory": memory,
            "stack": stack,
            "call_stack": call_stack,
            "fallback_call_stack": fallback_call_stack,
            "threads": threads,
            "exceptions": exceptions,
            "errors": errors,
            "degraded": bool(errors),
        }
        self.session.add_event(
            "x64dbg.runtime_snapshot",
            "codex",
            {
                "address": payload["address"],
                "stack_pointer": payload["stack_pointer"],
                "degraded": payload["degraded"],
                "errors": errors,
            },
        )
        return payload

    def _fallback_call_stack_from_stack_memory(self, stack: dict[str, Any], limit: int) -> dict[str, Any]:
        values = _hex_bytes_to_ints(str(stack.get("bytes", "")), pointer_size=8, limit=limit)
        frames = []
        for index, value in enumerate(values):
            if value <= 0x10000:
                continue
            ida_ea = self.session.runtime_to_ida(value)
            frames.append(
                {
                    "index": index,
                    "return_address": hex(value),
                    "ida_ea": None if ida_ea is None else hex(ida_ea),
                    "source": "stack_memory",
                }
            )
            if len(frames) >= limit:
                break
        return {"ok": True, "source": "stack_memory", "frames": frames, "total": len(frames)}

    async def _runtime_timeout_diagnostic(self, address: int, timeout: float) -> dict[str, Any]:
        try:
            snapshot = await self._runtime_snapshot({"address": hex(address), "memory_preview": 0, "stack_preview": 128, "call_stack_limit": 32})
        except Exception as exc:
            snapshot = {"ok": False, "error": str(exc)}
        last_exception = None
        for event in reversed(self.session.timeline):
            if event.type == "exception.hit":
                last_exception = event.as_json()
                break
        return {
            "ok": False,
            "error": "timeout",
            "address": hex(address),
            "timeout": timeout,
            "active_runtime_address": None if self.session.active_runtime_address is None else hex(self.session.active_runtime_address),
            "active_ida_ea": None if self.session.active_ida_ea is None else hex(self.session.active_ida_ea),
            "active_breakpoints": [hex(item) for item in sorted(self.session.breakpoints)][-128:],
            "last_exception": last_exception,
            "runtime_snapshot": snapshot,
        }

    async def _capture_compare_context(self, arguments: dict[str, Any]) -> dict[str, Any]:
        snapshot = await self._runtime_snapshot(
            {
                "address": arguments.get("address"),
                "memory_preview": arguments.get("memory_preview", 128),
                "stack_preview": arguments.get("stack_preview", 256),
                "call_stack_limit": arguments.get("call_stack_limit", 32),
            }
        )
        registers = snapshot.get("registers") if isinstance(snapshot.get("registers"), dict) else {}
        candidates = []
        for name in ("cax", "cbx", "ccx", "cdx", "csi", "cdi", "r8", "r9", "r10", "r11"):
            value = registers.get(name)
            if not value:
                continue
            try:
                parsed = parse_address(str(value))
            except Exception:
                continue
            candidates.append({"register": name, "value": hex(parsed), "kind": "register"})
        stack = snapshot.get("stack") if isinstance(snapshot.get("stack"), dict) else {}
        for index, value in enumerate(_hex_bytes_to_ints(str(stack.get("bytes", "")), limit=16)):
            if value > 0x10000:
                candidates.append({"stack_index": index, "value": hex(value), "kind": "stack_pointer"})
        payload = {
            "workflow": "workflow.capture_compare_context",
            "snapshot": snapshot,
            "argument_candidates": candidates[:32],
            "note": "read-only compare/call context; pointer candidates are heuristic previews",
        }
        self.session.add_event(
            "workflow.compare_context.captured",
            "codex",
            {"address": snapshot.get("address"), "candidate_count": len(payload["argument_candidates"]), "degraded": snapshot.get("degraded")},
        )
        return payload

    async def _breakpoint_group_add(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = str(arguments["name"])
        kind = str(arguments.get("kind", "software"))
        raw_addresses = arguments.get("addresses") or []
        if not isinstance(raw_addresses, list):
            raise ValueError("addresses must be an array")
        addresses = [parse_address(str(item)) for item in raw_addresses[:128]]
        bridge_results = []
        entries = []
        for address in addresses:
            if kind == "hardware":
                result = await self.bridges.request("x64dbg", "x64dbg.set_hardware_breakpoint", {"address": hex(address)})
            elif kind == "memory":
                result = await self.bridges.request("x64dbg", "x64dbg.set_memory_breakpoint", {"address": hex(address)})
            else:
                result = await self.bridges.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(address)})
            self.session.breakpoints.add(address)
            bridge_results.append(result)
            entries.append({"address": hex(address), "kind": kind})
        state = {"name": name, "kind": kind, "breakpoints": entries}
        self.breakpoint_groups[name] = state
        payload = {**state, "bridge_results": bridge_results}
        self.session.add_event("x64dbg.breakpoint_group.added", "codex", payload)
        return payload

    async def _remove_breakpoint_group(self, name: str) -> dict[str, Any]:
        state = self.breakpoint_groups.pop(name, None)
        if state is None:
            raise ValueError(f"breakpoint group not found: {name}")
        bridge_results = []
        for item in state.get("breakpoints", []):
            address = parse_address(str(item["address"]))
            kind = str(item.get("kind", "software"))
            if kind == "hardware":
                method = "x64dbg.remove_hardware_breakpoint"
            elif kind == "memory":
                method = "x64dbg.remove_memory_breakpoint"
            else:
                method = "x64dbg.remove_breakpoint"
            bridge_results.append(await self.bridges.request("x64dbg", method, {"address": hex(address)}))
            self.session.breakpoints.discard(address)
        payload = {"name": name, "removed": state.get("breakpoints", []), "bridge_results": bridge_results}
        self.session.add_event("x64dbg.breakpoint_group.removed", "codex", payload)
        return payload

    async def _analyze_function_runtime(self, arguments: dict[str, Any]) -> dict[str, Any]:
        timeout = _required_float(arguments, "timeout", "workflow.analyze_function_runtime")
        args_preview = max(0, min(int(arguments.get("args_preview", 8)), 32))
        memory_preview = max(0, min(int(arguments.get("memory_preview", 128)), 4096))
        should_comment = _parse_bool(arguments.get("comment"), default=True)
        ida_ea: int | None = None
        runtime_address: int | None = None
        if arguments.get("ea"):
            ida_ea = parse_address(arguments["ea"])
            runtime_address = self.session.ida_to_runtime(ida_ea) or ida_ea
        elif arguments.get("address"):
            runtime_address = parse_address(arguments["address"])
            ida_ea = self.session.runtime_to_ida(runtime_address)
        else:
            location = current_location(self.session)
            if not location["ida_ea"] and not location["runtime_address"]:
                raise ValueError("ea/address is required when there is no current IDA/debugger address")
            ida_ea = None if not location["ida_ea"] else parse_address(location["ida_ea"])
            runtime_address = None if not location["runtime_address"] else parse_address(location["runtime_address"])
        if runtime_address is None:
            raise ValueError("runtime address could not be resolved")

        await self.bridges.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(runtime_address)})
        self.session.breakpoints.add(runtime_address)
        wait_task = asyncio.create_task(
            self._wait_for_event(
                {"type": "breakpoint.hit", "address": hex(runtime_address), "after_index": len(self.session.timeline)},
                timeout,
            )
        )
        await asyncio.sleep(0)
        await self.bridges.request("x64dbg", "x64dbg.run", {})
        self._record_mutation("x64dbg.run", "x64dbg", {})
        hit = await wait_task

        snapshot = await self.bridges.request("x64dbg", "x64dbg.breakpoint_snapshot", {"address": hex(runtime_address)})
        registers = await self.bridges.request("x64dbg", "x64dbg.read_registers", {})
        call_stack = await self.bridges.request("x64dbg", "x64dbg.call_stack", {"limit": 32})
        memory = None
        if memory_preview:
            memory = await self.bridges.request("x64dbg", "x64dbg.read_memory", {"address": hex(runtime_address), "size": memory_preview})

        report = {
            "workflow": "workflow.analyze_function_runtime",
            "ida_ea": None if ida_ea is None else hex(ida_ea),
            "runtime_address": hex(runtime_address),
            "timeout": timeout,
            "args_preview": args_preview,
            "memory_preview": memory_preview,
            "hit": hit.as_json(),
            "snapshot": snapshot,
            "registers": registers,
            "call_stack": call_stack,
            "memory": memory,
        }
        if should_comment and ida_ea is not None and self.bridges.connected().get("ida"):
            comment = f"IX64MCP runtime hit at {hex(runtime_address)}; registers/call stack captured."
            try:
                report["ida_comment"] = await self.bridges.request("ida", "ida.comment", {"ea": hex(ida_ea), "text": comment})
            except Exception as exc:
                report["ida_comment"] = {"error": str(exc)}
        self.session.add_event("workflow.function_runtime.analyzed", "codex", report)
        return report

    async def _analysis_current(self, limit: int = 20) -> dict[str, Any]:
        location = current_location(self.session)
        function_summary: dict[str, Any] | None = None
        if location["ida_ea"] and self.bridges.connected().get("ida"):
            try:
                function_summary = await self.bridges.request(
                    "ida",
                    "ida.function_summary",
                    {"ea": location["ida_ea"], "detail": "compact", "max_pseudocode_chars": 0},
                )
            except Exception as exc:
                function_summary = {"error": str(exc)}
        return {
            "session": self.session.summary(self.bridges.connected()),
            "location": location,
            "function_summary": function_summary,
            "pending_suggestions": self.suggestions.list(status="pending", limit=limit, offset=0),
            "timeline_summary": timeline_summary(self.session.timeline, limit),
        }

    async def _analysis_modules(self, limit: int = 200) -> dict[str, Any]:
        bounded = max(1, min(int(limit), 1000))
        modules: dict[str, Any] = {
            "connected": self.bridges.connected(),
            "mappings": self.session.summary(self.bridges.connected())["mappings"][:bounded],
            "x64dbg_modules": None,
            "memory_map": None,
        }
        if self.bridges.connected().get("x64dbg"):
            try:
                modules["x64dbg_modules"] = await self.bridges.request("x64dbg", "x64dbg.list_modules", {})
            except Exception as exc:
                modules["x64dbg_modules"] = {"error": str(exc)}
            try:
                modules["memory_map"] = await self.bridges.request("x64dbg", "x64dbg.memory_map", {"limit": bounded, "offset": 0})
            except Exception as exc:
                modules["memory_map"] = {"error": str(exc)}
        return modules

    def _analysis_hot_functions(self, limit: int = 50) -> dict[str, Any]:
        suggestions = self.suggestions.list(limit=200)["suggestions"]
        return hot_functions(self.session, suggestions, limit)

    def _analysis_report(self, profile: str | None = None) -> dict[str, Any]:
        return analysis_report(self.config.state_dir, self.session, self.suggestions.list(limit=200), self.bridges.connected(), profile)

    def _runtime_history(self, limit: int = 200) -> dict[str, Any]:
        bounded = max(1, min(int(limit), 1000))
        selected = self.session.timeline[-bounded:]
        interesting = {
            "breakpoint.hit",
            "breakpoint.hit.snapshot",
            "trace.api_call",
            "trace.batch",
            "debug.paused",
            "step",
            "module.loaded",
            "module.unloaded",
            "thread.created",
            "thread.exited",
            "exception.hit",
            "memory_map.changed",
        }
        counters: dict[str, int] = {}
        modules = []
        exceptions = []
        breakpoints = []
        threads = []
        api_hits: dict[str, int] = {}
        for event in selected:
            if event.type not in interesting:
                continue
            counters[event.type] = counters.get(event.type, 0) + 1
            payload = event.payload
            if event.type.startswith("module."):
                modules.append(payload)
            elif event.type == "exception.hit":
                exceptions.append(payload)
            elif event.type in {"breakpoint.hit", "breakpoint.hit.snapshot"}:
                breakpoints.append(payload)
            elif event.type.startswith("thread."):
                threads.append(payload)
            elif event.type in {"trace.api_call", "trace.batch"}:
                for api in self._payload_api_names(payload):
                    api_hits[api] = api_hits.get(api, 0) + 1
        return {
            "limit": bounded,
            "event_counts": counters,
            "breakpoint_groups": list(self.breakpoint_groups.values()),
            "recent_modules": modules[-20:],
            "recent_exceptions": exceptions[-20:],
            "recent_breakpoints": breakpoints[-20:],
            "recent_threads": threads[-20:],
            "hot_apis": sorted(({"api": api, "count": count} for api, count in api_hits.items()), key=lambda row: -row["count"])[:20],
            "trace_batches_kept": len(self.trace_batches),
        }

    async def _correlate_runtime_static(self, arguments: dict[str, Any]) -> dict[str, Any]:
        address_text = arguments.get("address")
        runtime_address = parse_address(str(address_text)) if address_text else self.session.active_runtime_address
        ida_ea = None if runtime_address is None else self.session.runtime_to_ida(runtime_address)
        if ida_ea is None and runtime_address is None and self.session.active_ida_ea is not None:
            ida_ea = self.session.active_ida_ea
            runtime_address = self.session.ida_to_runtime(ida_ea)
        include_summary = _parse_bool(arguments.get("include_summary"), default=True)
        summary = None
        if include_summary and ida_ea is not None and self.bridges.connected().get("ida"):
            try:
                summary = await self.bridges.request("ida", "ida.function_summary", {"ea": hex(ida_ea), "detail": "compact", "max_pseudocode_chars": 0})
            except Exception as exc:
                summary = {"error": str(exc)}
        return {
            "runtime_address": None if runtime_address is None else hex(runtime_address),
            "ida_ea": None if ida_ea is None else hex(ida_ea),
            "mapped": ida_ea is not None,
            "function_summary": summary,
            "recent_events": [
                event.as_json()
                for event in self.session.timeline[-100:]
                if runtime_address is not None and self._event_matches(event, {"address": hex(runtime_address)})
            ][-10:],
        }

    def _detect_anti_debug(self, limit: int = 200) -> dict[str, Any]:
        bounded = max(1, min(int(limit), 1000))
        needles = {
            "IsDebuggerPresent": "direct debugger check",
            "CheckRemoteDebuggerPresent": "remote debugger check",
            "NtQueryInformationProcess": "debug flags/process information check",
            "QueryPerformanceCounter": "timing check candidate",
            "GetTickCount": "timing check candidate",
            "OutputDebugString": "debugger side effect check",
            "FindWindow": "tool/window detection candidate",
            "UnhandledExceptionFilter": "exception-based anti-debug candidate",
        }
        hints = []
        for event in self.session.timeline[-bounded:]:
            text = json.dumps(event.payload, sort_keys=True)
            for api, reason in needles.items():
                if api.lower() in text.lower():
                    hints.append({"source": "timeline", "api": api, "reason": reason, "event": event.as_json()})
        return {
            "limit": bounded,
            "hints": hints[:100],
            "recommendations": [
                "Inspect wrappers via ida.import_to_callers for each API hint.",
                "Use workflow.analyze_function_runtime with a timeout on the suspected wrapper.",
                "Prefer preview suggestions/comments before any bypass patch.",
            ],
        }

    @staticmethod
    def _payload_api_names(payload: Any) -> list[str]:
        names = []
        if isinstance(payload, dict):
            for key in ("api", "name", "function", "import_name"):
                if payload.get(key):
                    names.append(str(payload[key]))
            for value in payload.values():
                names.extend(IX64MCP._payload_api_names(value))
        elif isinstance(payload, list):
            for item in payload[:100]:
                names.extend(IX64MCP._payload_api_names(item))
        return names

    def _session_resume(self, arguments: dict[str, Any]) -> dict[str, Any]:
        sample_id = None if arguments.get("sample_id") is None else str(arguments.get("sample_id"))
        file_sha256 = None if arguments.get("file_sha256") is None else str(arguments.get("file_sha256"))
        if not self.store.restore_session(self.session, sample_id=sample_id, file_sha256=file_sha256):
            raise ValueError("session not found")
        self.suggestions.restore(self.store.load_suggestions(self.session.sample_id))
        rows = self.store.latest_events(200, self.session.sample_id)
        self.session.timeline = [
            TimelineEvent(type=str(row["type"]), source=str(row["source"]), payload=row["payload"], timestamp=str(row["timestamp"]))
            for row in rows
        ]
        return {
            "resumed": True,
            "session": self.session.summary(self.bridges.connected()),
            "workspace": load_workspace_by_hash(self.config.state_dir, self.session.file_sha256) or {},
            "suggestions": self.suggestions.list(limit=100),
            "timeline_summary": timeline_summary(self.session.timeline, 200),
            "next_steps": [
                "Open IDA/x64dbg bridges if disconnected.",
                "Read analysis://current for current context.",
                "Use workflow.explain_current_function or workflow.find_password_check for the next analysis step.",
            ],
        }

    def _safe_patch_plan(self, limit: int = 50) -> dict[str, Any] | None:
        if not self.session.file_path or not Path(self.session.file_path).exists():
            return None
        try:
            return plan_patches(self.session.file_path, limit=limit)
        except Exception as exc:
            return {"error": str(exc), "path": self.session.file_path}

    def _safe_triage(self, limit: int = 100) -> dict[str, Any] | None:
        if not self.session.file_path or not Path(self.session.file_path).exists():
            return None
        try:
            return triage(self.session.file_path, limit)
        except Exception as exc:
            return {"error": str(exc), "path": self.session.file_path}

    def _safe_imports(self, limit: int = 1000) -> dict[str, Any]:
        if not self.session.file_path or not Path(self.session.file_path).exists():
            return {"imports": [], "error": "no active sample path"}
        try:
            return pe_imports(self.session.file_path, limit=limit)
        except Exception as exc:
            return {"imports": [], "error": str(exc)}

    def _trace_name_candidates(self, limit: int = 20) -> list[dict[str, str]]:
        candidates: list[dict[str, str]] = []
        seen: set[str] = set()
        for event in reversed(self.session.timeline[-500:]):
            payload_text = json.dumps(event.payload, sort_keys=True).lower()
            api = None
            for marker in ("loadlibrary", "getprocaddress", "createfile", "regopenkey", "internet", "winhttp", "connect", "strcmp", "memcmp"):
                if marker in payload_text:
                    api = marker
                    break
            if not api:
                continue
            address = None
            for key in ("ida_ea", "address", "runtime_address", "rip", "cip"):
                if key in event.payload:
                    try:
                        value = parse_address(str(event.payload[key]))
                        address = self.session.runtime_to_ida(value) or value
                        break
                    except Exception:
                        pass
            if address is None:
                address = self.session.active_ida_ea
            if address is None:
                continue
            target = hex(address)
            if target in seen:
                continue
            seen.add(target)
            candidates.append({"target": target, "name": f"trace_{api}_handler_{target[2:]}", "reason": f"recent trace mentions {api}"})
            if len(candidates) >= limit:
                break
        return candidates

    async def _create_suggestion(self, kind: str, target: str, suggested_value: str, reason: str) -> dict[str, Any]:
        suggestion = self.suggestions.add(
            Suggestion(kind=kind, target=target, suggested_value=suggested_value, reason=reason)
        )
        payload = suggestion.as_json()
        self.store.record_suggestion(self.session, payload)
        self.session.add_event("analysis.suggestion.created", "codex", payload)
        await self._push_ida_panel_update()
        return payload

    async def _apply_suggestion(self, suggestion_id: str) -> dict[str, Any]:
        try:
            suggestion = self.suggestions.get(suggestion_id)
        except KeyError as exc:
            raise ValueError(str(exc)) from exc
        if suggestion.status != "pending":
            raise ValueError(f"suggestion is already {suggestion.status}: {suggestion_id}")
        target = hex(parse_address(suggestion.target))
        if suggestion.kind == "name":
            self.policy.require("ida.rename")
            result = await self.bridges.request("ida", "ida.rename", {"ea": target, "name": suggestion.suggested_value})
        elif suggestion.kind == "comment":
            self.policy.require("ida.comment")
            result = await self.bridges.request("ida", "ida.comment", {"ea": target, "text": suggestion.suggested_value})
        elif suggestion.kind == "decompiler_comment":
            self.policy.require("ida.set_decompiler_comment")
            result = await self.bridges.request(
                "ida",
                "ida.set_decompiler_comment",
                {"ea": target, "text": suggestion.suggested_value},
            )
        elif suggestion.kind == "type":
            raise ValueError("type suggestions are preview-only in Phase 12")
        else:
            raise ValueError(f"unsupported suggestion kind: {suggestion.kind}")
        suggestion.mark("applied")
        payload = {**suggestion.as_json(), "result": result}
        self.store.record_suggestion(self.session, suggestion.as_json())
        self.session.add_event("analysis.suggestion.applied", "codex", payload)
        await self._push_ida_panel_update()
        return payload

    async def _reject_suggestion(self, suggestion_id: str, reason: str) -> dict[str, Any]:
        try:
            suggestion = self.suggestions.get(suggestion_id)
        except KeyError as exc:
            raise ValueError(str(exc)) from exc
        suggestion.mark("rejected")
        payload = {**suggestion.as_json(), "reject_reason": reason}
        self.store.record_suggestion(self.session, suggestion.as_json())
        self.session.add_event("analysis.suggestion.rejected", "codex", payload)
        await self._push_ida_panel_update()
        return payload

    async def _push_ida_panel_update(self) -> None:
        if not self.bridges.connected().get("ida"):
            return
        state = {
            "connected": self.bridges.connected(),
            "active_runtime_address": None if self.session.active_runtime_address is None else hex(self.session.active_runtime_address),
            "active_ida_ea": None if self.session.active_ida_ea is None else hex(self.session.active_ida_ea),
            "timeline": [event.as_json() for event in self.session.timeline[-20:]],
            "suggestions": self.suggestions.list(status="pending", limit=50, offset=0)["suggestions"],
            "trace_batches": self.trace_batches[-5:],
            "trace_recipes": list(self.trace_recipes.values()),
        }
        try:
            await self.bridges.request("ida", "ida.panel_update", state)
        except Exception as exc:
            self.session.add_event("ida.panel_update_failed", "codex", {"error": str(exc)})

    def _on_session_event(self, event: TimelineEvent, session: AnalysisSession) -> None:
        if event.type in {
            "debug.paused",
            "step",
            "breakpoint.hit",
            "breakpoint.hit.snapshot",
            "module.loaded",
            "module.unloaded",
            "thread.created",
            "thread.exited",
            "exception.hit",
            "memory_map.changed",
            "trace.batch",
            "ida.action.follow_x64dbg",
            "ida.action.apply_suggestion",
            "ida.action.reject_suggestion",
            "analysis.suggestion.created",
            "analysis.suggestion.applied",
            "analysis.suggestion.rejected",
        }:
            self._schedule_panel_update()
        if event.type == "trace.api_call":
            self._queue_trace_event(event.as_json())
        self._notify_event_waiters(event)
        if event.type in {"ida.action.follow_x64dbg", "ida.action.apply_suggestion", "ida.action.reject_suggestion"}:
            self._schedule_ida_action(event)

    def _notify_event_waiters(self, event: TimelineEvent) -> None:
        remaining: list[tuple[dict[str, Any], asyncio.Future[TimelineEvent]]] = []
        for criteria, future in self._event_waiters:
            if future.done():
                continue
            if self._event_matches(event, criteria):
                future.set_result(event)
            else:
                remaining.append((criteria, future))
        self._event_waiters = remaining

    async def _wait_for_event(self, criteria: dict[str, Any], timeout: float | int) -> TimelineEvent:
        bounded_timeout = max(0.1, min(float(timeout), 120.0))
        if criteria.get("after_index") is None:
            for event in reversed(self.session.timeline[-500:]):
                if self._event_matches(event, criteria):
                    return event
        loop = asyncio.get_running_loop()
        future: asyncio.Future[TimelineEvent] = loop.create_future()
        self._event_waiters.append((criteria, future))
        try:
            return await asyncio.wait_for(future, bounded_timeout)
        finally:
            self._event_waiters = [(item, waiter) for item, waiter in self._event_waiters if waiter is not future]

    def _event_matches(self, event: TimelineEvent, criteria: dict[str, Any]) -> bool:
        event_type = criteria.get("type")
        if event_type and event.type != str(event_type):
            return False
        address = criteria.get("address")
        if address in {None, ""}:
            return True
        try:
            expected = parse_address(str(address))
        except Exception:
            return False
        for key in ("address", "runtime_address", "ida_ea", "ea", "rip", "eip", "cip"):
            if event.payload.get(key) is None:
                continue
            try:
                if parse_address(str(event.payload[key])) == expected:
                    return True
            except Exception:
                continue
        return False

    def _schedule_panel_update(self) -> None:
        if self._panel_update_task is not None and not self._panel_update_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._panel_update_task = loop.create_task(self._delayed_panel_update())

    async def _delayed_panel_update(self) -> None:
        await asyncio.sleep(self._panel_update_interval)
        await self._push_ida_panel_update()

    def _schedule_ida_action(self, event: TimelineEvent) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._handle_ida_action(event))

    async def _handle_ida_action(self, event: TimelineEvent) -> None:
        try:
            if event.type == "ida.action.follow_x64dbg":
                if self.session.active_runtime_address is None:
                    self.session.add_event("ida.action.failed", "codex", {"action": event.type, "error": "no active x64dbg runtime address"})
                    return
                await self._sync_address({"source": "x64dbg", "address": hex(self.session.active_runtime_address)})
                return
            if event.type == "ida.action.apply_suggestion":
                suggestion_id = str(event.payload.get("id") or "")
                if not suggestion_id:
                    raise ValueError("missing suggestion id")
                await self._apply_suggestion(suggestion_id)
                return
            if event.type == "ida.action.reject_suggestion":
                suggestion_id = str(event.payload.get("id") or "")
                if not suggestion_id:
                    raise ValueError("missing suggestion id")
                await self._reject_suggestion(suggestion_id, str(event.payload.get("reason", "rejected from IDA panel")))
        except Exception as exc:
            self.session.add_event("ida.action.failed", "codex", {"action": event.type, "error": str(exc), "payload": event.payload})

    def _queue_trace_event(self, event: dict[str, Any]) -> None:
        self._trace_events.append(self._cap_trace_event(event))
        self._trace_events = self._trace_events[-self._max_trace_events :]
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if len(self._trace_events) >= self._max_trace_events:
            if self._trace_flush_task is not None and not self._trace_flush_task.done():
                self._trace_flush_task.cancel()
            self._trace_flush_task = loop.create_task(self._flush_trace_events())
            return
        if self._trace_flush_task is None or self._trace_flush_task.done():
            self._trace_flush_task = loop.create_task(self._delayed_trace_flush())

    async def _delayed_trace_flush(self) -> None:
        await asyncio.sleep(self._trace_flush_interval)
        await self._flush_trace_events()

    async def _flush_trace_events(self) -> None:
        if not self._trace_events:
            return
        events = self._trace_events[: self._max_trace_events]
        self._trace_events = self._trace_events[len(events) :]
        batch = {"count": len(events), "events": events}
        self.trace_batches.append(batch)
        self.trace_batches = self.trace_batches[-self._max_trace_batches :]
        self.session.add_event("trace.batch", "codex", batch)

    def _cap_trace_event(self, value: Any) -> Any:
        if isinstance(value, str):
            return value[:512]
        if isinstance(value, list):
            return [self._cap_trace_event(item) for item in value[: self._max_trace_events]]
        if isinstance(value, dict):
            return {str(key)[:128]: self._cap_trace_event(item) for key, item in list(value.items())[:100]}
        return value

    async def _trace_recipe_enable(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = str(arguments["name"])
        options = arguments.get("options") if isinstance(arguments.get("options"), dict) else {}
        bridge_result: dict[str, Any] = {}
        if self.bridges.connected().get("x64dbg"):
            bridge_result = await self.bridges.request(
                "x64dbg",
                "x64dbg.trace_recipe_enable",
                {"name": name, "options": options},
            )
        recipe = {"name": name, "enabled": True, "options": options, "bridge": bridge_result}
        self.trace_recipes[name] = recipe
        self.session.add_event("trace.recipe.enabled", "codex", recipe)
        return recipe

    async def _trace_recipe_disable(self, name: str) -> dict[str, Any]:
        bridge_result: dict[str, Any] = {}
        if self.bridges.connected().get("x64dbg"):
            bridge_result = await self.bridges.request("x64dbg", "x64dbg.trace_recipe_disable", {"name": name})
        recipe = {**self.trace_recipes.get(name, {"name": name}), "enabled": False, "bridge": bridge_result}
        self.trace_recipes[name] = recipe
        self.session.add_event("trace.recipe.disabled", "codex", recipe)
        return recipe

    def _pe_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        path = str(arguments.get("path") or self.session.file_path or "")
        if not path:
            raise ValueError("PE path is required when no active IDA session file is known")
        if name == "pe.summary":
            return pe_summary(path, arguments.get("limit"))
        if name == "pe.imports":
            return pe_imports(path, arguments.get("dll"), arguments.get("limit"), arguments.get("offset"))
        if name == "pe.exports":
            return pe_exports(path, arguments.get("limit"), arguments.get("offset"))
        if name == "pe.resources":
            return pe_resources(path, arguments.get("limit"), arguments.get("offset"))
        if name == "pe.relocations":
            return pe_relocations(path, arguments.get("limit"), arguments.get("offset"))
        raise ValueError(f"unknown PE tool: {name}")

    def _patch_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        path = str(arguments.get("path") or self.session.file_path or "")
        if not path:
            raise ValueError("patch path is required when no active IDA session file is known")
        if name == "patch.plan":
            return plan_patches(path, arguments.get("limit"), arguments.get("window"))
        if name == "patch.apply_file":
            result = apply_file_patch(
                path,
                arguments["file_offset"],
                str(arguments["expected_hex"]),
                str(arguments["patch_hex"]),
                str(arguments.get("reason", "")),
                arguments.get("output_path"),
            )
            self.session.add_event("patch.file.applied", "codex", result)
            return result
        if name == "patch.rollback":
            result = rollback_file_patch(path, str(arguments["backup_path"]))
            self.session.add_event("patch.file.rolled_back", "codex", result)
            return result
        if name == "patch.diff":
            return diff_file_patch(path, str(arguments["backup_path"]), arguments.get("limit"))
        raise ValueError(f"unknown patch tool: {name}")

    def _malware_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        path = str(arguments.get("path") or self.session.file_path or "")
        if name == "malware.workspace_create":
            if not path:
                raise ValueError("sample path is required when no active IDA session file is known")
            result = create_workspace(
                self.config.state_dir,
                path,
                None if arguments.get("idb_path") is None else str(arguments.get("idb_path")),
                None if arguments.get("debugger_session_path") is None else str(arguments.get("debugger_session_path")),
                str(arguments.get("notes", "")),
                _parse_bool(arguments.get("copy_sample"), default=True),
            )
            self.session.sample_id = str(result["sample_id"])
            self.session.file_path = str(result["source_path"])
            self.session.file_sha256 = str(result["hashes"]["sha256"])
            self.session.add_event("malware.workspace.created", "codex", result)
            return result
        if name == "malware.triage":
            if not path:
                raise ValueError("sample path is required when no active IDA session file is known")
            result = triage(path, arguments.get("limit"))
            self.session.file_path = str(result["path"])
            self.session.file_sha256 = str(result["hashes"]["sha256"])
            self.session.add_event(
                "malware.triage",
                "codex",
                {
                    "path": result["path"],
                    "sha256": result["hashes"]["sha256"],
                    "suspicious_imports": len(result["suspicious_imports"]),
                    "suspicious_strings": len(result["suspicious_strings"]),
                    "packer_hints": len(result["packer_hints"]),
                },
            )
            return result
        if name == "malware.behavior_report":
            workspace = load_workspace_by_hash(self.config.state_dir, self.session.file_sha256)
            return behavior_report(self.session, self.session.timeline, workspace)
        if name == "malware.add_ioc":
            sample_sha256 = str(arguments.get("sample_sha256") or self.session.file_sha256 or "")
            if not sample_sha256:
                raise ValueError("sample_sha256 is required before a malware workspace or triage exists")
            result = add_ioc(
                self.config.state_dir,
                sample_sha256,
                str(arguments["kind"]),
                str(arguments["value"]),
                str(arguments.get("source", "codex")),
                str(arguments.get("note", "")),
            )
            self.session.add_event("malware.ioc.added", "codex", result)
            return result
        if name == "malware.add_config":
            sample_sha256 = str(arguments.get("sample_sha256") or self.session.file_sha256 or "")
            if not sample_sha256:
                raise ValueError("sample_sha256 is required before a malware workspace or triage exists")
            result = add_config(
                self.config.state_dir,
                sample_sha256,
                str(arguments["key"]),
                str(arguments["value"]),
                str(arguments.get("source", "codex")),
                str(arguments.get("confidence", "medium")),
            )
            self.session.add_event("malware.config.added", "codex", result)
            return result
        if name == "malware.workspace_update":
            sample_sha256 = str(arguments.get("sample_sha256") or self.session.file_sha256 or "")
            if not sample_sha256:
                raise ValueError("sample_sha256 is required before a malware workspace exists")
            tags = arguments.get("tags")
            tag_list = None if tags is None else [item.strip() for item in str(tags).split(",") if item.strip()]
            sandbox = arguments.get("sandbox") if isinstance(arguments.get("sandbox"), dict) else None
            result = update_workspace_metadata(
                self.config.state_dir,
                sample_sha256,
                None if arguments.get("status") is None else str(arguments.get("status")),
                tag_list,
                sandbox,
                None if arguments.get("idb_path") is None else str(arguments.get("idb_path")),
                None if arguments.get("debugger_session_path") is None else str(arguments.get("debugger_session_path")),
            )
            self.session.add_event("malware.workspace.updated", "codex", result)
            return result
        if name == "malware.add_artifact":
            sample_sha256 = str(arguments.get("sample_sha256") or self.session.file_sha256 or "")
            if not sample_sha256:
                raise ValueError("sample_sha256 is required before a malware workspace exists")
            result = add_artifact(
                self.config.state_dir,
                sample_sha256,
                str(arguments["kind"]),
                str(arguments["path"]),
                str(arguments.get("source", "codex")),
                str(arguments.get("note", "")),
            )
            self.session.add_event("malware.artifact.added", "codex", result)
            return result
        if name == "malware.add_lineage":
            sample_sha256 = str(arguments.get("sample_sha256") or self.session.file_sha256 or "")
            if not sample_sha256:
                raise ValueError("sample_sha256 is required before a malware workspace exists")
            result = add_lineage(
                self.config.state_dir,
                sample_sha256,
                str(arguments["kind"]),
                str(arguments["path"]),
                str(arguments.get("relationship", "derived")),
                str(arguments.get("note", "")),
            )
            self.session.add_event("malware.lineage.added", "codex", result)
            return result
        if name == "malware.export_report":
            sample_sha256 = str(arguments.get("sample_sha256") or self.session.file_sha256 or "")
            if not sample_sha256:
                raise ValueError("sample_sha256 is required before a malware workspace exists")
            report = self._analysis_report(arguments.get("profile"))
            result = export_report(self.config.state_dir, sample_sha256, report, str(arguments.get("format", "json")))
            self.session.add_event("malware.report.exported", "codex", result)
            return result
        if name == "malware.sandbox_check":
            result = sandbox_check(
                allow_network=_parse_bool(arguments.get("allow_network"), default=False),
                vm_confirmed=_parse_bool(arguments.get("vm_confirmed"), default=False),
                snapshot_confirmed=_parse_bool(arguments.get("snapshot_confirmed"), default=False),
            )
            self.session.add_event("malware.sandbox.check", "codex", result)
            return result
        raise ValueError(f"unknown malware tool: {name}")

    async def _break_on_entry(self, arguments: dict[str, Any]) -> dict[str, Any]:
        requested_module = str(arguments.get("module") or "main")
        should_run = _parse_bool(arguments.get("run"), default=False)
        mapping = self.session.mapping_by_name(requested_module)
        if mapping is None and requested_module == "main":
            modules = await self.bridges.request("x64dbg", "x64dbg.list_modules", {})
            for module in modules.get("modules", []):
                name = str(module.get("name", ""))
                if self.session.mapping_by_name(name) is None:
                    runtime_base = parse_address(module["runtime_base"])
                    size = parse_address(module["size"]) if module.get("size") is not None else None
                    self.session.upsert_mapping(name, ida_base=runtime_base, runtime_base=runtime_base, size=size)
            mapping = self.session.mapping_by_name("main") or (self.session.mappings[0] if self.session.mappings else None)
        if mapping is None:
            raise ValueError(f"module mapping not found: {requested_module}")

        memory = await self.bridges.request(
            "x64dbg",
            "x64dbg.read_memory",
            {"address": hex(mapping.runtime_base), "size": 0x1000},
        )
        if not memory.get("ok", False):
            raise ValueError(str(memory.get("error", "failed to read module header")))
        header = binascii.unhexlify(memory["bytes"])
        pe = _parse_pe_entry(header)
        runtime_entry = mapping.runtime_base + pe["entry_rva"]
        ida_entry = mapping.ida_base + pe["entry_rva"]
        await self.bridges.request("x64dbg", "x64dbg.set_breakpoint", {"address": hex(runtime_entry)})
        self.session.breakpoints.add(runtime_entry)
        event = self.session.add_event(
            "analysis.break_on_entry",
            "codex",
            {
                "module": mapping.name,
                "runtime_base": hex(mapping.runtime_base),
                "ida_base": hex(mapping.ida_base),
                "entry_rva": hex(pe["entry_rva"]),
                "runtime_entry": hex(runtime_entry),
                "ida_entry": hex(ida_entry),
                "image_base": hex(pe["image_base"]),
                "bitness": pe["bitness"],
                "run": should_run,
            },
        )
        if should_run:
            await self.bridges.request("x64dbg", "x64dbg.run", {})
            self._record_mutation("x64dbg.run", "x64dbg", {})
        return event.as_json()

    async def _sync_address(self, arguments: dict[str, Any]) -> dict[str, Any]:
        source = str(arguments["source"])
        address = parse_address(arguments["address"])
        if source == "ida":
            runtime = self.session.ida_to_runtime(address)
            self.session.active_ida_ea = address
            if runtime is not None:
                self.session.active_runtime_address = runtime
                await self.bridges.request("x64dbg", "x64dbg.goto", {"address": hex(runtime)})
            self.session.add_event("analysis.sync_address", "codex", {"source": source, "ida_ea": hex(address), "runtime_address": None if runtime is None else hex(runtime)})
            return {"ida_ea": hex(address), "runtime_address": None if runtime is None else hex(runtime)}
        if source == "x64dbg":
            ida_ea = self.session.runtime_to_ida(address)
            self.session.active_runtime_address = address
            if ida_ea is not None:
                self.session.active_ida_ea = ida_ea
                await self.bridges.request("ida", "ida.goto", {"ea": hex(ida_ea)})
            self.session.add_event("analysis.sync_address", "codex", {"source": source, "runtime_address": hex(address), "ida_ea": None if ida_ea is None else hex(ida_ea)})
            return {"runtime_address": hex(address), "ida_ea": None if ida_ea is None else hex(ida_ea)}
        raise ValueError("source must be 'ida' or 'x64dbg'")

    def _record_mutation(self, tool: str, source: str, arguments: dict[str, Any]) -> None:
        mutating = {
            "ida.goto",
            "ida.rename",
            "ida.comment",
            "ida.set_decompiler_comment",
            "x64dbg.goto",
            "x64dbg.set_breakpoint",
            "x64dbg.remove_breakpoint",
            "x64dbg.run",
            "x64dbg.pause",
            "x64dbg.step_into",
            "x64dbg.step_over",
            "x64dbg.set_hardware_breakpoint",
            "x64dbg.remove_hardware_breakpoint",
            "x64dbg.set_memory_breakpoint",
            "x64dbg.remove_memory_breakpoint",
            "x64dbg.set_conditional_breakpoint",
            "trace.recipe_enable",
            "trace.recipe_disable",
        }
        if tool in mutating:
            self.session.add_event("tool.called", source, {"tool": tool, "arguments": arguments})

    @staticmethod
    def _tool(name: str, properties: dict[str, str], required: list[str] | None = None) -> Tool:
        return Tool(
            name=name,
            description=f"IX64MCP tool: {name}",
            inputSchema={
                "type": "object",
                "properties": {key: {"type": value} for key, value in properties.items()},
                "required": list(properties.keys()) if required is None else required,
            },
        )


async def async_main(host: str, port: int) -> None:
    config = IX64Config.from_env()
    config = IX64Config(bridge_host=host, bridge_port=port, state_dir=config.state_dir, token=config.token)
    LOGGER.info("starting IX64MCP server host=%s port=%s state_dir=%s", host, port, config.state_dir)
    app = IX64MCP(config)
    bridge_task = asyncio.create_task(app.bridges.serve(host, port))
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.server.run(read_stream, write_stream, app.server.create_initialization_options())
    finally:
        LOGGER.info("stopping IX64MCP server")
        bridge_task.cancel()
        try:
            await bridge_task
        except asyncio.CancelledError:
            pass


async def async_daemon_main(host: str, port: int, api_host: str, api_port: int) -> None:
    config = IX64Config.from_env()
    config = IX64Config(bridge_host=host, bridge_port=port, state_dir=config.state_dir, token=config.token)
    LOGGER.info(
        "starting IX64MCP daemon bridge=%s:%s api=%s:%s state_dir=%s",
        host,
        port,
        api_host,
        api_port,
        config.state_dir,
    )
    app = IX64MCP(config)
    bridge_task = asyncio.create_task(app.bridges.serve(host, port))
    api_task = asyncio.create_task(serve_daemon_api(app.daemon_api, api_host, api_port))
    try:
        await asyncio.gather(bridge_task, api_task)
    finally:
        LOGGER.info("stopping IX64MCP daemon")
        for task in (bridge_task, api_task):
            task.cancel()
        for task in (bridge_task, api_task):
            try:
                await task
            except asyncio.CancelledError:
                pass


async def async_mcp_proxy_main(api_host: str, api_port: int) -> None:
    server = Server("ix64mcp")

    @server.list_resources()
    async def list_resources() -> list[Resource]:
        try:
            rows = await daemon_request("mcp.list_resources", host=api_host, port=api_port)
            return [_resource_from_json(row) for row in rows]
        except Exception as exc:
            LOGGER.warning("daemon resource list unavailable: %s", exc)
            return proxy_resource_definitions()

    @server.read_resource()
    async def read_resource(uri: AnyUrl) -> str:
        return str(await daemon_request("mcp.read_resource", {"uri": str(uri)}, host=api_host, port=api_port))

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        try:
            rows = await daemon_request("mcp.list_tools", host=api_host, port=api_port)
            return [_tool_from_json(row) for row in rows]
        except Exception as exc:
            LOGGER.warning("daemon tool list unavailable: %s", exc)
            return proxy_tool_definitions()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        result = await daemon_request(
            "mcp.call_tool",
            {"name": name, "arguments": arguments or {}},
            host=api_host,
            port=api_port,
        )
        return json_text(result)

    LOGGER.info("starting IX64MCP MCP adapter api=%s:%s", api_host, api_port)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", default="mcp", choices=["mcp", "start", "daemon", "legacy", "stop", "status", "doctor"])
    parser.add_argument("--bridge-host", default="127.0.0.1")
    parser.add_argument("--bridge-port", default=8765, type=int)
    parser.add_argument("--api-host", default="127.0.0.1")
    parser.add_argument("--api-port", default=8766, type=int)
    parser.add_argument("--log-file", default="auto")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--no-lock", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    config_from_env = IX64Config.from_env()
    log_path: Path | None = None
    if args.log_file.strip().lower() == "auto":
        log_name = "mcp.log" if args.command == "mcp" else "daemon.log"
        log_path = config_from_env.state_dir / "logs" / log_name
    elif args.log_file.strip().lower() not in {"", "none", "off"}:
        candidate = Path(args.log_file)
        log_path = candidate if candidate.is_absolute() else config_from_env.state_dir / candidate
    setup_logging(log_path, args.log_level)
    lock_path = config_from_env.state_dir / "ix64mcp.server.lock"
    lock = SingleInstanceLock(lock_path)

    if args.command == "mcp":
        asyncio.run(async_mcp_proxy_main(args.api_host, args.api_port))
        return

    if args.command == "doctor":
        diagnostics = runtime_diagnostics(lock, args.bridge_host, args.bridge_port, args.api_host, args.api_port)
        try:
            health = asyncio.run(daemon_request("daemon.health", host=args.api_host, port=args.api_port))
        except Exception as exc:
            health = {"ok": False, "error": str(exc)}
        report = {
            "diagnostics": diagnostics,
            "daemon_health": health,
            "logs": {
                "daemon": str(config_from_env.state_dir / "logs" / "daemon.log"),
                "mcp": str(config_from_env.state_dir / "logs" / "mcp.log"),
                "bridges": str(config_from_env.state_dir / "logs" / "bridges.log"),
            },
        }
        LOGGER.info("doctor %s", json.dumps(report, sort_keys=True))
        raise SystemExit(0 if diagnostics.get("ok") and health.get("ok") else 1)

    if args.command == "status":
        diagnostics = runtime_diagnostics(lock, args.bridge_host, args.bridge_port, args.api_host, args.api_port)
        LOGGER.info(
            "status %s",
            json.dumps(diagnostics, sort_keys=True),
        )
        raise SystemExit(0 if diagnostics["running"] else 1)

    if args.command == "stop":
        pid = lock.read_pid()
        if pid and is_process_running(pid):
            if stop_process(pid):
                LOGGER.info("stop signal sent to pid=%s", pid)
                raise SystemExit(0)
            LOGGER.error("failed to stop pid=%s", pid)
            raise SystemExit(4)
        if is_port_in_use(args.bridge_host, args.bridge_port):
            if args.force:
                command = (
                    "Get-CimInstance Win32_Process | "
                    "Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*ix64mcp.server*' } | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
                )
                subprocess.run(["powershell", "-NoProfile", "-Command", command], check=False)
                LOGGER.info("force stop attempted for legacy ix64mcp.server processes")
                raise SystemExit(0)
            LOGGER.error("port %s:%s is busy but lock pid is missing/stale", args.bridge_host, args.bridge_port)
            raise SystemExit(5)
        LOGGER.info("server is already stopped")
        raise SystemExit(0)

    active_lock = None
    if not args.no_lock:
        active_lock = lock
        if not active_lock.acquire():
            LOGGER.error("another ix64mcp.server instance is already running (lock=%s)", lock_path)
            raise SystemExit(2)
        LOGGER.info("single-instance lock acquired: %s", lock_path)
    if is_port_in_use(args.bridge_host, args.bridge_port):
        LOGGER.error(
            "bridge port is already in use: %s:%s (existing server may be stale or started without lock)",
            args.bridge_host,
            args.bridge_port,
        )
        raise SystemExit(3)
    if args.command in {"start", "daemon"} and is_port_in_use(args.api_host, args.api_port):
        LOGGER.error(
            "daemon API port is already in use: %s:%s (existing server may be stale or started without lock)",
            args.api_host,
            args.api_port,
        )
        raise SystemExit(6)
    try:
        if args.command == "legacy":
            asyncio.run(async_main(args.bridge_host, args.bridge_port))
        else:
            asyncio.run(async_daemon_main(args.bridge_host, args.bridge_port, args.api_host, args.api_port))
    finally:
        if active_lock is not None:
            active_lock.release()


if __name__ == "__main__":
    main()
