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
from .malware import add_config, add_ioc, behavior_report, create_workspace, load_workspace_by_hash, sandbox_check, triage
from .pe import pe_exports, pe_imports, pe_relocations, pe_resources, pe_summary
from .patch import apply_file_patch, diff_file_patch, plan_patches, rollback_file_patch
from .policy import PolicyEngine
from .protocol import parse_address
from .session import AnalysisSession, TimelineEvent
from .store import SessionStore
from .suggestions import Suggestion, SuggestionStore
from .runtime import SingleInstanceLock, is_port_in_use, is_process_running, setup_logging, stop_process


LOGGER = logging.getLogger("ix64mcp.server")


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
        self._trace_events: list[dict[str, Any]] = []
        self._trace_flush_task: asyncio.Task[None] | None = None
        self._panel_update_task: asyncio.Task[None] | None = None
        self._panel_update_interval = 0.5
        self._trace_flush_interval = 0.5
        self._max_trace_events = 100
        self._max_trace_batches = 200
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
                return json.dumps(self._analysis_report(), indent=2, sort_keys=True)
            if text.startswith("analysis://trace"):
                parsed = urlparse(text)
                limit = max(1, min(int(parse_qs(parsed.query).get("limit", ["50"])[0]), self._max_trace_batches))
                return json.dumps({"batches": self.trace_batches[-limit:]}, indent=2, sort_keys=True)
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
                self._tool("ida.pseudocode", {"ea": "string", "max_chars": "integer", "offset": "integer"}, required=["ea"]),
                self._tool("ida.refresh_decompiler", {"ea": "string"}),
                self._tool("ida.set_decompiler_comment", {"ea": "string", "text": "string"}),
                self._tool("x64dbg.goto", {"address": "string"}),
                self._tool("x64dbg.set_breakpoint", {"address": "string"}),
                self._tool("x64dbg.remove_breakpoint", {"address": "string"}),
                self._tool("x64dbg.run", {}),
                self._tool("x64dbg.pause", {}),
                self._tool("x64dbg.step_into", {}),
                self._tool("x64dbg.step_over", {}),
                self._tool("x64dbg.read_memory", {"address": "string", "size": "integer"}),
                self._tool("x64dbg.read_registers", {}),
                self._tool("x64dbg.list_modules", {}),
                self._tool("x64dbg.memory_map", {"limit": "integer", "offset": "integer"}, required=[]),
                self._tool("x64dbg.call_stack", {"limit": "integer"}, required=[]),
                self._tool("x64dbg.threads", {}),
                self._tool("x64dbg.exceptions", {"limit": "integer", "offset": "integer"}, required=[]),
                self._tool("x64dbg.set_hardware_breakpoint", {"address": "string", "access": "string", "size": "integer"}, required=["address"]),
                self._tool("x64dbg.remove_hardware_breakpoint", {"address": "string"}),
                self._tool("x64dbg.set_memory_breakpoint", {"address": "string", "size": "integer", "access": "string"}, required=["address"]),
                self._tool("x64dbg.remove_memory_breakpoint", {"address": "string"}),
                self._tool("x64dbg.set_conditional_breakpoint", {"address": "string", "condition": "string", "log_text": "string"}, required=["address", "condition"]),
                self._tool("x64dbg.breakpoint_snapshot", {"address": "string"}, required=[]),
                self._tool("x64dbg.dump_metadata", {"address": "string", "size": "integer"}),
                self._tool("trace.recipe_enable", {"name": "string", "options": "object"}, required=["name"]),
                self._tool("trace.recipe_disable", {"name": "string"}),
                self._tool("trace.recipe_status", {}),
                self._tool("analysis.sync_address", {"source": "string", "address": "string"}),
                self._tool("analysis.add_note", {"address": "string", "text": "string"}),
                self._tool("analysis.link_dynamic_static", {"runtime_address": "string", "ida_ea": "string"}),
                self._tool("analysis.follow_debugger", {}),
                self._tool("analysis.break_on_entry", {"module": "string", "run": "string"}, required=[]),
                self._tool("analysis.policy_status", {}),
                self._tool("analysis.policy_approve", {"action": "string", "reason": "string"}, required=["action"]),
                self._tool("analysis.policy_clear", {"action": "string"}, required=[]),
                self._tool("analysis.suggest_name", {"target": "string", "suggested_value": "string", "reason": "string"}, required=["target", "suggested_value"]),
                self._tool("analysis.suggest_comment", {"target": "string", "text": "string", "reason": "string", "kind": "string"}, required=["target", "text"]),
                self._tool("analysis.list_suggestions", {"status": "string", "limit": "integer", "offset": "integer"}, required=[]),
                self._tool("analysis.apply_suggestion", {"id": "string"}),
                self._tool("analysis.reject_suggestion", {"id": "string", "reason": "string"}, required=["id"]),
                self._tool("analysis.timeline_summary", {"limit": "integer", "window": "string"}, required=[]),
                self._tool("analysis.session_resume", {"sample_id": "string", "file_sha256": "string"}, required=[]),
                self._tool("analysis.session_list", {"limit": "integer"}, required=[]),
                self._tool("workflow.follow_debugger", {}),
                self._tool("workflow.explain_current_function", {"max_pseudocode_chars": "integer"}, required=[]),
                self._tool("workflow.find_password_check", {"limit": "integer"}, required=[]),
                self._tool("workflow.break_on_first_strcmp_like", {"run": "string"}, required=[]),
                self._tool("workflow.rename_functions_from_trace", {"limit": "integer", "apply": "string"}, required=[]),
                self._tool("workflow.make_patch_plan", {"limit": "integer"}, required=[]),
                self._tool("workflow.generate_analysis_report", {}),
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

        if name.startswith("x64dbg."):
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
            runtime = parse_address(arguments["runtime_address"])
            ida_ea = parse_address(arguments["ida_ea"])
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
            return timeline_summary(self.session.timeline or self.store.latest_events(int(arguments.get("limit", 200))), arguments.get("limit"))
        if name == "analysis.session_resume":
            return self._session_resume(arguments)
        if name == "analysis.session_list":
            return {"sessions": self.store.list_sessions(int(arguments.get("limit", 20)))}
        if name.startswith("workflow."):
            return await self._workflow_tool(name, arguments)
        if name.startswith("pe."):
            return self._pe_tool(name, arguments)
        if name.startswith("patch."):
            return self._patch_tool(name, arguments)
        if name.startswith("malware."):
            return self._malware_tool(name, arguments)
        raise ValueError(f"unknown tool: {name}")

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
            return self._analysis_report()
        raise ValueError(f"unknown workflow tool: {name}")

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

    def _analysis_report(self) -> dict[str, Any]:
        return analysis_report(self.config.state_dir, self.session, self.suggestions.list(limit=200), self.bridges.connected())

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
        if event.type in {"ida.action.follow_x64dbg", "ida.action.apply_suggestion", "ida.action.reject_suggestion"}:
            self._schedule_ida_action(event)

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", default="start", choices=["start", "stop", "status"])
    parser.add_argument("--bridge-host", default="127.0.0.1")
    parser.add_argument("--bridge-port", default=8765, type=int)
    parser.add_argument("--log-file", default="state/ix64mcp.log")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--no-lock", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    config_from_env = IX64Config.from_env()
    log_path: Path | None = None
    if args.log_file.strip().lower() not in {"", "none", "off"}:
        candidate = Path(args.log_file)
        log_path = candidate if candidate.is_absolute() else config_from_env.state_dir / candidate
    setup_logging(log_path, args.log_level)
    lock_path = config_from_env.state_dir / "ix64mcp.server.lock"
    lock = SingleInstanceLock(lock_path)

    if args.command == "status":
        pid = lock.read_pid()
        running = bool(pid and is_process_running(pid))
        port_busy = is_port_in_use(args.bridge_host, args.bridge_port)
        LOGGER.info(
            "status running=%s pid=%s port_busy=%s host=%s port=%s lock=%s",
            running,
            pid,
            port_busy,
            args.bridge_host,
            args.bridge_port,
            lock_path,
        )
        raise SystemExit(0 if running else 1)

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
    try:
        asyncio.run(async_main(args.bridge_host, args.bridge_port))
    finally:
        if active_lock is not None:
            active_lock.release()


if __name__ == "__main__":
    main()
