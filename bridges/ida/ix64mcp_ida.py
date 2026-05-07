from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import ida_auto
import ida_bytes
import ida_frame
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_xref
import idautils
import idc

try:
    import websockets
except ImportError:
    websockets = None


BRIDGE_URI = "ws://127.0.0.1:8765"
PROTOCOL_VERSION = "0.1"
BRIDGE_VERSION = "0.1.0"
CAPABILITIES = [
    "cursor.changed",
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
    "ida.panel_update",
    "ida.decompile",
]


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _get_str_type_compat(ea: int) -> int | None:
    for module in (ida_nalt, idc, ida_bytes):
        getter = getattr(module, "get_str_type", None)
        if getter is None:
            continue
        try:
            return getter(ea)
        except Exception:
            continue
    return None


def _main_thread(callable_, flags=ida_kernwin.MFF_READ):
    box = {"value": None, "error": None}

    def wrapper():
        try:
            box["value"] = callable_()
        except Exception as exc:
            box["error"] = exc
        return 1

    ida_kernwin.execute_sync(wrapper, flags)
    if box["error"] is not None:
        raise box["error"]
    return box["value"]


async def _connect_bridge():
    kwargs = {
        "open_timeout": 15,
        "close_timeout": 1,
        "ping_interval": None,
    }
    try:
        return await websockets.connect(BRIDGE_URI, proxy=None, **kwargs)
    except TypeError:
        return await websockets.connect(BRIDGE_URI, **kwargs)


class IX64MCPIdaPlugin(ida_kernwin.UI_Hooks):
    def __init__(self) -> None:
        super().__init__()
        self.loop = asyncio.new_event_loop()
        self.socket = None
        self.last_ea = idc.BADADDR
        self.events: list[str] = []
        self.panel_state: dict[str, Any] = {"suggestions": []}
        self.timer = None
        self.idb_hooks = IX64MCPIdbHooks(self)
        self.panel = IX64MCPPanel(self)
        self.thread = threading.Thread(target=self._thread_main, name="IX64MCP IDA bridge", daemon=True)
        self._last_disconnect_message = None
        self._func_update_window = 0.0
        self._func_update_sent = 0

    def start(self) -> None:
        if websockets is None:
            ida_kernwin.msg("[IX64MCP] Python package 'websockets' is required.\n")
            return
        self.hook()
        self.idb_hooks.hook()
        self.timer = ida_kernwin.register_timer(500, self._poll_cursor)
        self._register_actions()
        self.thread.start()
        ida_kernwin.msg("[IX64MCP] IDA bridge started.\n")

    def finish_populating_widget_popup(self, widget, popup) -> None:
        self._check_cursor()

    def _poll_cursor(self):
        self._check_cursor()
        self.panel.refresh()
        return 500

    def _check_cursor(self) -> None:
        ea = ida_kernwin.get_screen_ea()
        if ea != idc.BADADDR and ea != self.last_ea:
            self.last_ea = ea
            self._submit_event("ida.cursor.changed", {"ea": _hex(ea)})
            self._panel_event(f"cursor {_hex(ea)}")

    def _thread_main(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect_forever())

    async def _connect_forever(self) -> None:
        while True:
            try:
                async with await _connect_bridge() as socket:
                    self.socket = socket
                    await self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": uuid4().hex,
                            "method": "hello",
                            "params": {
                                "role": "ida",
                                "protocol_version": PROTOCOL_VERSION,
                                "bridge_version": BRIDGE_VERSION,
                                "capabilities": CAPABILITIES,
                                "token": os.environ.get("IX64MCP_TOKEN", ""),
                                "session": _main_thread(self._session_info),
                            },
                        }
                    )
                    await socket.recv()
                    await self._serve(socket)
            except Exception as exc:
                message = str(exc)
                if message != self._last_disconnect_message:
                    ida_kernwin.msg(f"[IX64MCP] bridge disconnected: {message}\n")
                    self._last_disconnect_message = message
                self.socket = None
                await asyncio.sleep(2)

    async def _serve(self, socket) -> None:
        async for raw in socket:
            request = json.loads(raw)
            try:
                result = self._handle(request.get("method"), request.get("params", {}))
                response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
            except Exception as exc:
                response = {"jsonrpc": "2.0", "id": request.get("id"), "error": {"message": str(exc)}}
            await self._send(response)

    def _handle(self, method: str, params: dict[str, Any]) -> Any:
        if method == "ida.goto":
            ea = int(str(params["ea"]), 0)
            _main_thread(lambda: ida_kernwin.jumpto(ea), ida_kernwin.MFF_WRITE)
            return {"ok": True, "ea": _hex(ea)}
        if method == "ida.rename":
            ea = int(str(params["ea"]), 0)
            name = str(params["name"])
            _main_thread(lambda: ida_name.set_name(ea, name, ida_name.SN_CHECK), ida_kernwin.MFF_WRITE)
            self._submit_event("ida.name.changed", {"ea": _hex(ea), "name": name})
            return {"ok": True, "ea": _hex(ea), "name": name}
        if method == "ida.comment":
            ea = int(str(params["ea"]), 0)
            text = str(params["text"])
            _main_thread(lambda: ida_bytes.set_cmt(ea, text, False), ida_kernwin.MFF_WRITE)
            self._submit_event("ida.comment.changed", {"ea": _hex(ea), "text": text})
            return {"ok": True, "ea": _hex(ea)}
        if method == "ida.get_function":
            return _main_thread(lambda: self._get_function(int(str(params["ea"]), 0)))
        if method == "ida.get_xrefs":
            return _main_thread(lambda: self._get_xrefs(int(str(params["ea"]), 0)))
        if method == "ida.list_strings":
            return _main_thread(lambda: self._list_strings(params))
        if method == "ida.get_string_xrefs":
            return _main_thread(lambda: self._get_string_xrefs(int(str(params["address"]), 0), int(params.get("limit", 100))))
        if method == "ida.function_summary":
            return _main_thread(lambda: self._function_summary(params))
        if method == "ida.callgraph":
            return _main_thread(lambda: self._callgraph(params))
        if method == "ida.cfg":
            return _main_thread(lambda: self._cfg(params))
        if method == "ida.callers":
            return _main_thread(lambda: self._callers(int(str(params["ea"]), 0), int(params.get("limit", 100))))
        if method == "ida.callees":
            return _main_thread(lambda: self._callees(int(str(params["ea"]), 0), int(params.get("limit", 100))))
        if method == "ida.string_to_functions":
            return _main_thread(lambda: self._string_to_functions(int(str(params["address"]), 0), int(params.get("limit", 100))))
        if method == "ida.import_to_callers":
            return _main_thread(lambda: self._import_to_callers(str(params["name"]), int(params.get("limit", 100))))
        if method == "ida.branch_context":
            return _main_thread(lambda: self._branch_context(int(str(params["ea"]), 0), int(params.get("window", 6))))
        if method == "ida.stack_var_usage":
            return _main_thread(lambda: self._stack_var_usage(params))
        if method == "ida.pseudocode":
            return _main_thread(lambda: self._pseudocode(params))
        if method == "ida.refresh_decompiler":
            return _main_thread(lambda: self._refresh_decompiler(int(str(params["ea"]), 0)), ida_kernwin.MFF_WRITE)
        if method == "ida.set_decompiler_comment":
            return _main_thread(
                lambda: self._set_decompiler_comment(int(str(params["ea"]), 0), str(params["text"])),
                ida_kernwin.MFF_WRITE,
            )
        if method == "ida.panel_update":
            return _main_thread(lambda: self._panel_update(params))
        if method == "ida.decompile":
            return _main_thread(lambda: self._decompile(int(str(params["ea"]), 0)))
        raise ValueError(f"unknown method: {method}")

    def _get_function(self, ea: int) -> dict[str, Any]:
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ea": _hex(ea), "found": False}
        chunks = [{"start_ea": _hex(chunk.start_ea), "end_ea": _hex(chunk.end_ea)} for chunk in ida_funcs.func_tail_iterator_t(func)]
        return {
            "found": True,
            "start_ea": _hex(func.start_ea),
            "end_ea": _hex(func.end_ea),
            "name": ida_funcs.get_func_name(func.start_ea),
            "chunks": chunks,
        }

    def _get_xrefs(self, ea: int) -> dict[str, Any]:
        refs = []
        xref = ida_xref.get_first_cref_to(ea)
        while xref != idc.BADADDR:
            refs.append({"from": _hex(xref), "to": _hex(ea), "type": "code"})
            xref = ida_xref.get_next_cref_to(ea, xref)
        xref = ida_xref.get_first_dref_to(ea)
        while xref != idc.BADADDR:
            refs.append({"from": _hex(xref), "to": _hex(ea), "type": "data"})
            xref = ida_xref.get_next_dref_to(ea, xref)
        return {"ea": _hex(ea), "xrefs": refs}

    def _list_strings(self, params: dict[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", "")).lower()
        limit = max(1, min(int(params.get("limit", 100)), 500))
        offset = max(0, int(params.get("offset", 0)))
        rows = []
        matched = 0
        for item in idautils.Strings():
            text = str(item)
            if query and query not in text.lower():
                continue
            if matched >= offset and len(rows) < limit:
                rows.append({"address": _hex(item.ea), "length": item.length, "type": item.strtype, "text": text})
            matched += 1
        return {"query": query, "offset": offset, "limit": limit, "total_matched": matched, "strings": rows}

    def _get_string_xrefs(self, address: int, limit: int) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        refs = []
        xref = ida_xref.get_first_dref_to(address)
        while xref != idc.BADADDR and len(refs) < limit:
            func = ida_funcs.get_func(xref)
            refs.append(
                {
                    "from": _hex(xref),
                    "to": _hex(address),
                    "function": None if func is None else ida_funcs.get_func_name(func.start_ea),
                    "function_start": None if func is None else _hex(func.start_ea),
                    "line": ida_lines.generate_disasm_line(xref, 0) or "",
                }
            )
            xref = ida_xref.get_next_dref_to(address, xref)
        return {"address": _hex(address), "limit": limit, "xrefs": refs}

    def _function_summary(self, params: dict[str, Any]) -> dict[str, Any]:
        ea = int(str(params["ea"]), 0)
        detail = str(params.get("detail", "compact"))
        max_pseudocode_chars = max(0, min(int(params.get("max_pseudocode_chars", 0)), 20000))
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ea": _hex(ea), "found": False}

        calls = []
        strings = []
        branches = []
        imports = []
        stack_vars = []
        constants = []
        suspicious_apis = []
        for insn_ea in idautils.FuncItems(func.start_ea):
            mnemonic = (ida_lines.generate_disasm_line(insn_ea, 0) or "").lower()
            for target in idautils.CodeRefsFrom(insn_ea, False):
                target_func = ida_funcs.get_func(target)
                target_name = ida_name.get_name(target) or (None if target_func is None else ida_funcs.get_func_name(target_func.start_ea))
                item = {
                    "from": _hex(insn_ea),
                    "to": _hex(target),
                    "name": target_name,
                }
                if target_func is None or target_func.start_ea != func.start_ea:
                    calls.append(item)
                    if target_name and self._is_suspicious_api(target_name):
                        suspicious_apis.append({"from": _hex(insn_ea), "to": _hex(target), "name": target_name})
                else:
                    branches.append(item)
            for data_ea in idautils.DataRefsFrom(insn_ea):
                string_text = self._string_at(data_ea)
                name = ida_name.get_name(data_ea)
                if string_text is not None:
                    strings.append({"from": _hex(insn_ea), "address": _hex(data_ea), "text": string_text})
                elif name:
                    imports.append({"from": _hex(insn_ea), "address": _hex(data_ea), "name": name})
                    if self._is_suspicious_api(name):
                        suspicious_apis.append({"from": _hex(insn_ea), "address": _hex(data_ea), "name": name})
            for op_index in range(2):
                value = idc.get_operand_value(insn_ea, op_index)
                if value and value not in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF} and (value > 0xFF or "cmp" in mnemonic):
                    constants.append({"ea": _hex(insn_ea), "operand": op_index, "value": _hex(value), "line": ida_lines.generate_disasm_line(insn_ea, 0) or ""})

        stack_vars = self._stack_vars_for_function(func)

        pseudocode = None
        if max_pseudocode_chars:
            decompiled = self._decompile(func.start_ea)
            text = decompiled.get("text") or ""
            pseudocode = text[:max_pseudocode_chars]
        return {
            "found": True,
            "detail": detail,
            "start_ea": _hex(func.start_ea),
            "end_ea": _hex(func.end_ea),
            "name": ida_funcs.get_func_name(func.start_ea),
            "instruction_count": len(list(idautils.FuncItems(func.start_ea))),
            "calls": self._dedupe_rows(calls, ("from", "to"))[:100],
            "strings": self._dedupe_rows(strings, ("address", "text"))[:100],
            "imports": self._dedupe_rows(imports, ("address", "name"))[:100],
            "branches": self._dedupe_rows(branches, ("from", "to"))[:200] if detail == "full" else [],
            "stack_vars": stack_vars[:100],
            "constants": self._dedupe_rows(constants, ("ea", "operand", "value"))[:100] if detail == "full" else [],
            "suspicious_apis": self._dedupe_rows(suspicious_apis, ("from", "name"))[:100],
            "pseudocode": pseudocode,
            "truncated": {
                "calls": len(calls) > 100,
                "strings": len(strings) > 100,
                "imports": len(imports) > 100,
                "branches": detail == "full" and len(branches) > 200,
                "constants": detail == "full" and len(constants) > 100,
                "suspicious_apis": len(suspicious_apis) > 100,
                "pseudocode": pseudocode is not None and len(text) > max_pseudocode_chars,
            },
        }

    @staticmethod
    def _is_suspicious_api(name: str) -> bool:
        lowered = name.lower()
        needles = (
            "virtualalloc",
            "virtualprotect",
            "writeprocessmemory",
            "createremotethread",
            "loadlibrary",
            "getprocaddress",
            "internet",
            "winhttp",
            "wsastartup",
            "crypt",
            "regopen",
            "createfile",
            "writefile",
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
        )
        return any(needle in lowered for needle in needles)

    def _stack_vars_for_function(self, func) -> list[dict[str, Any]]:
        frame = None
        try:
            if hasattr(ida_funcs, "get_frame"):
                frame = ida_funcs.get_frame(func)
            elif hasattr(ida_frame, "get_frame"):
                frame = ida_frame.get_frame(func)
        except Exception:
            frame = None
        if frame is None:
            return []
        rows = []
        try:
            count = int(getattr(frame, "memqty", 0))
            for index in range(count):
                member = frame.get_member(index) if hasattr(frame, "get_member") else None
                if member is not None:
                    rows.append({"name": str(member.name), "offset": _hex(int(member.soff)), "size": int(member.size)})
        except Exception:
            return []
        return rows

    def _callers(self, ea: int, limit: int) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        func = ida_funcs.get_func(ea)
        target = ea if func is None else func.start_ea
        rows = []
        for ref in idautils.CodeRefsTo(target, False):
            caller = ida_funcs.get_func(ref)
            rows.append(
                {
                    "from": _hex(ref),
                    "function_start": None if caller is None else _hex(caller.start_ea),
                    "function_name": None if caller is None else ida_funcs.get_func_name(caller.start_ea),
                    "line": ida_lines.generate_disasm_line(ref, 0) or "",
                }
            )
            if len(rows) >= limit:
                break
        return {"ea": _hex(ea), "target": _hex(target), "limit": limit, "callers": rows}

    def _callees(self, ea: int, limit: int) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ea": _hex(ea), "found": False, "callees": []}
        rows = []
        for insn_ea in idautils.FuncItems(func.start_ea):
            for target in idautils.CodeRefsFrom(insn_ea, False):
                target_func = ida_funcs.get_func(target)
                if target_func is not None and target_func.start_ea == func.start_ea:
                    continue
                rows.append(
                    {
                        "from": _hex(insn_ea),
                        "to": _hex(target),
                        "name": ida_name.get_name(target) or (None if target_func is None else ida_funcs.get_func_name(target_func.start_ea)),
                        "function_start": None if target_func is None else _hex(target_func.start_ea),
                    }
                )
                if len(rows) >= limit:
                    return {"ea": _hex(ea), "function": _hex(func.start_ea), "limit": limit, "callees": self._dedupe_rows(rows, ("to", "from"))}
        return {"ea": _hex(ea), "function": _hex(func.start_ea), "limit": limit, "callees": self._dedupe_rows(rows, ("to", "from"))}

    def _callgraph(self, params: dict[str, Any]) -> dict[str, Any]:
        ea = int(str(params["ea"]), 0)
        depth = max(1, min(int(params.get("depth", 2)), 4))
        limit = max(1, min(int(params.get("limit", 200)), 1000))
        root = ida_funcs.get_func(ea)
        if root is None:
            return {"ea": _hex(ea), "found": False, "nodes": [], "edges": []}
        queue = [(root.start_ea, 0)]
        seen = {root.start_ea}
        nodes = []
        edges = []
        while queue and len(nodes) < limit:
            func_ea, level = queue.pop(0)
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue
            nodes.append({"ea": _hex(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea), "depth": level})
            if level >= depth:
                continue
            for row in self._callees(func.start_ea, limit).get("callees", []):
                target_text = row.get("function_start") or row.get("to")
                if not target_text:
                    continue
                target = int(str(target_text), 0)
                edges.append({"from": _hex(func.start_ea), "to": _hex(target), "callsite": row["from"], "name": row.get("name")})
                if target not in seen and len(seen) < limit:
                    seen.add(target)
                    queue.append((target, level + 1))
                if len(edges) >= limit:
                    break
        return {"ea": _hex(ea), "root": _hex(root.start_ea), "depth": depth, "limit": limit, "nodes": nodes, "edges": edges[:limit], "truncated": len(nodes) >= limit or len(edges) >= limit}

    def _cfg(self, params: dict[str, Any]) -> dict[str, Any]:
        ea = int(str(params["ea"]), 0)
        limit = max(1, min(int(params.get("limit", 300)), 1000))
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ea": _hex(ea), "found": False, "blocks": [], "edges": []}
        blocks = []
        edges = []
        for block in ida_gdl.FlowChart(func):
            if len(blocks) >= limit:
                break
            blocks.append({"id": block.id, "start_ea": _hex(block.start_ea), "end_ea": _hex(block.end_ea)})
            for succ in block.succs():
                edges.append({"from": block.id, "to": succ.id, "from_ea": _hex(block.start_ea), "to_ea": _hex(succ.start_ea)})
                if len(edges) >= limit:
                    break
        return {"ea": _hex(ea), "function": _hex(func.start_ea), "limit": limit, "blocks": blocks, "edges": edges[:limit], "truncated": len(blocks) >= limit or len(edges) >= limit}

    def _string_to_functions(self, address: int, limit: int) -> dict[str, Any]:
        xrefs = self._get_string_xrefs(address, limit)
        functions = []
        for row in xrefs["xrefs"]:
            if row.get("function_start"):
                functions.append({"function_start": row["function_start"], "function_name": row.get("function"), "xref": row["from"], "line": row.get("line", "")})
        return {"address": _hex(address), "string": self._string_at(address), "functions": self._dedupe_rows(functions, ("function_start", "xref")), "limit": xrefs["limit"]}

    def _import_to_callers(self, name: str, limit: int) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        lowered = name.lower()
        matches = []
        for ea, symbol in idautils.Names():
            if lowered not in symbol.lower():
                continue
            refs = self._get_xrefs(ea)["xrefs"]
            for ref in refs:
                if ref["type"] != "code":
                    continue
                caller = ida_funcs.get_func(int(ref["from"], 0))
                matches.append(
                    {
                        "import_address": _hex(ea),
                        "import_name": symbol,
                        "callsite": ref["from"],
                        "function_start": None if caller is None else _hex(caller.start_ea),
                        "function_name": None if caller is None else ida_funcs.get_func_name(caller.start_ea),
                    }
                )
                if len(matches) >= limit:
                    return {"name": name, "limit": limit, "callers": matches}
        return {"name": name, "limit": limit, "callers": matches}

    def _branch_context(self, ea: int, window: int) -> dict[str, Any]:
        window = max(1, min(window, 32))
        func = ida_funcs.get_func(ea)
        items = list(idautils.FuncItems(func.start_ea)) if func is not None else []
        if ea not in items:
            items = [item for item in items if abs(item - ea) < 0x100] or [ea]
        try:
            index = items.index(ea)
        except ValueError:
            index = min(range(len(items)), key=lambda idx: abs(items[idx] - ea)) if items else 0
        selected = items[max(0, index - window) : index + window + 1] if items else [ea]
        lines = [{"ea": _hex(item), "line": ida_lines.generate_disasm_line(item, 0) or ""} for item in selected]
        return {"ea": _hex(ea), "function": None if func is None else _hex(func.start_ea), "window": window, "lines": lines}

    def _stack_var_usage(self, params: dict[str, Any]) -> dict[str, Any]:
        ea = int(str(params["ea"]), 0)
        name_filter = str(params.get("name", "")).lower()
        limit = max(1, min(int(params.get("limit", 100)), 500))
        func = ida_funcs.get_func(ea)
        if func is None:
            return {"ea": _hex(ea), "found": False, "stack_vars": [], "usages": []}
        stack_vars = self._function_summary({"ea": _hex(func.start_ea)}).get("stack_vars", [])
        if name_filter:
            stack_vars = [row for row in stack_vars if name_filter in str(row.get("name", "")).lower()]
        usages = []
        for insn_ea in idautils.FuncItems(func.start_ea):
            line = ida_lines.generate_disasm_line(insn_ea, 0) or ""
            lowered = line.lower()
            for var in stack_vars:
                if str(var.get("name", "")).lower() and str(var["name"]).lower() in lowered:
                    usages.append({"ea": _hex(insn_ea), "variable": var["name"], "line": line})
                    break
            if len(usages) >= limit:
                break
        return {"ea": _hex(ea), "function": _hex(func.start_ea), "stack_vars": stack_vars[:limit], "usages": usages, "limit": limit}

    def _string_at(self, ea: int) -> str | None:
        string_type = _get_str_type_compat(ea)
        if string_type is None or string_type < 0:
            value = idc.get_strlit_contents(ea, -1, -1)
        else:
            value = idc.get_strlit_contents(ea, -1, string_type)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    @staticmethod
    def _dedupe_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for row in rows:
            key = tuple(row.get(name) for name in keys)
            if key in seen:
                continue
            seen.add(key)
            result.append(row)
        return result

    def _decompile(self, ea: int) -> dict[str, Any]:
        if not ida_hexrays.init_hexrays_plugin():
            return {"ea": _hex(ea), "available": False, "text": None}
        cfunc = ida_hexrays.decompile(ea)
        return {"ea": _hex(ea), "available": True, "text": str(cfunc)}

    def _pseudocode(self, params: dict[str, Any]) -> dict[str, Any]:
        ea = int(str(params["ea"]), 0)
        max_chars = max(1, min(int(params.get("max_chars", 12000)), 50000))
        offset = max(0, int(params.get("offset", 0)))
        result = self._decompile(ea)
        text = result.get("text") or ""
        chunk = text[offset : offset + max_chars]
        return {
            "ea": _hex(ea),
            "available": result.get("available", False),
            "offset": offset,
            "max_chars": max_chars,
            "total_chars": len(text),
            "next_offset": None if offset + max_chars >= len(text) else offset + max_chars,
            "text": chunk,
        }

    def _refresh_decompiler(self, ea: int) -> dict[str, Any]:
        if not ida_hexrays.init_hexrays_plugin():
            return {"ea": _hex(ea), "available": False, "refreshed": False}
        ida_hexrays.mark_cfunc_dirty(ea, True)
        self._submit_event("ida.decompiler.refreshed", {"ea": _hex(ea)})
        self._panel_event(f"decompiler refreshed {_hex(ea)}")
        return {"ea": _hex(ea), "available": True, "refreshed": True}

    def _set_decompiler_comment(self, ea: int, text: str) -> dict[str, Any]:
        applied = False
        if ida_hexrays.init_hexrays_plugin():
            try:
                cfunc = ida_hexrays.decompile(ea)
                loc = ida_hexrays.treeloc_t()
                loc.ea = ea
                loc.itp = ida_hexrays.ITP_SEMI
                cfunc.set_user_cmt(loc, text)
                cfunc.save_user_cmts()
                ida_hexrays.mark_cfunc_dirty(ea, True)
                applied = True
            except Exception:
                applied = False
        if not applied:
            ida_bytes.set_cmt(ea, text, False)
        self._submit_event("ida.comment.changed", {"ea": _hex(ea), "text": text, "decompiler": applied})
        self._panel_event(f"comment {_hex(ea)}")
        return {"ok": True, "ea": _hex(ea), "decompiler": applied}

    def _panel_update(self, params: dict[str, Any]) -> dict[str, Any]:
        self.panel_state = dict(params)
        self.panel.refresh()
        return {"ok": True}

    def _session_info(self) -> dict[str, Any]:
        path = Path(ida_nalt.get_input_file_path())
        sha256 = None
        try:
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            pass
        return {
            "sample_id": path.name,
            "file_path": str(path),
            "file_sha256": sha256,
            "architecture": ida_idp_name(),
            "image_base": _hex(ida_nalt.get_imagebase()),
        }

    def _submit_event(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.socket is None:
            return
        asyncio.run_coroutine_threadsafe(
            self._send({"jsonrpc": "2.0", "method": "event", "params": {"type": event_type, "payload": payload}}),
            self.loop,
        )

    async def _send(self, message: dict[str, Any]) -> None:
        if self.socket is not None:
            await self.socket.send(json.dumps(message))

    def _panel_event(self, text: str) -> None:
        self.events.append(text)
        self.events = self.events[-20:]
        self.panel.refresh()

    def _register_actions(self) -> None:
        actions = [
            ("ix64mcp:show_panel", "IX64MCP: Show Panel", lambda: self.panel.show()),
            ("ix64mcp:follow_x64dbg", "IX64MCP: Follow x64dbg", self._action_follow_x64dbg),
            ("ix64mcp:send_function", "IX64MCP: Send function to Codex", self._action_send_function),
            ("ix64mcp:apply_suggestion", "IX64MCP: Apply selected suggestion", self._action_apply_selected_suggestion),
            ("ix64mcp:reject_suggestion", "IX64MCP: Reject selected suggestion", self._action_reject_selected_suggestion),
        ]
        for name, label, callback in actions:
            ida_kernwin.unregister_action(name)
            ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, IX64MCPActionHandler(callback)))

    def stop(self) -> None:
        try:
            self.unhook()
            self.idb_hooks.unhook()
        except Exception:
            pass
        if self.timer is not None:
            ida_kernwin.unregister_timer(self.timer)
            self.timer = None
        for name in (
            "ix64mcp:show_panel",
            "ix64mcp:follow_x64dbg",
            "ix64mcp:send_function",
            "ix64mcp:apply_suggestion",
            "ix64mcp:reject_suggestion",
        ):
            ida_kernwin.unregister_action(name)

    def _action_follow_x64dbg(self) -> None:
        self._submit_event("ida.action.follow_x64dbg", {"ea": _hex(ida_kernwin.get_screen_ea())})
        self._panel_event("requested follow x64dbg")

    def _action_send_function(self) -> None:
        ea = ida_kernwin.get_screen_ea()
        if ea == idc.BADADDR:
            return
        summary = self._function_summary({"ea": _hex(ea), "detail": "compact", "max_pseudocode_chars": 4000})
        self._submit_event("ida.function.sent_to_codex", summary)
        self._panel_event(f"sent function {summary.get('name', _hex(ea))}")

    def _action_apply_selected_suggestion(self) -> None:
        suggestion = self.panel.selected_suggestion()
        if suggestion is None:
            self._panel_event("no selected suggestion")
            return
        self._submit_event("ida.action.apply_suggestion", {"id": suggestion.get("id")})
        self._panel_event(f"requested apply {suggestion.get('id')}")

    def _action_reject_selected_suggestion(self) -> None:
        suggestion = self.panel.selected_suggestion()
        if suggestion is None:
            self._panel_event("no selected suggestion")
            return
        self._submit_event("ida.action.reject_suggestion", {"id": suggestion.get("id")})
        self._panel_event(f"requested reject {suggestion.get('id')}")


class IX64MCPIdbHooks(ida_idp.IDB_Hooks):
    def __init__(self, plugin: IX64MCPIdaPlugin) -> None:
        super().__init__()
        self.plugin = plugin

    def renamed(self, ea, new_name, local_name):  # IDA callback signature
        self.plugin._submit_event("ida.name.changed", {"ea": _hex(ea), "name": str(new_name), "local": bool(local_name)})
        self.plugin._panel_event(f"name {str(new_name)}")
        return 0

    def cmt_changed(self, ea, repeatable_cmt):  # IDA callback signature
        text = ida_bytes.get_cmt(ea, bool(repeatable_cmt)) or ""
        self.plugin._submit_event("ida.comment.changed", {"ea": _hex(ea), "text": text, "repeatable": bool(repeatable_cmt)})
        self.plugin._panel_event(f"comment {_hex(ea)}")
        return 0

    def func_added(self, func):
        self.plugin._submit_event("ida.function.created", {"ea": _hex(func.start_ea), "end_ea": _hex(func.end_ea)})
        self.plugin._panel_event(f"function created {_hex(func.start_ea)}")
        return 0

    def func_updated(self, func):
        now = time.monotonic()
        if now - self.plugin._func_update_window > 5.0:
            self.plugin._func_update_window = now
            self.plugin._func_update_sent = 0
        self.plugin._func_update_sent += 1
        if self.plugin._func_update_sent <= 50:
            self.plugin._submit_event("ida.function.updated", {"ea": _hex(func.start_ea), "end_ea": _hex(func.end_ea)})
        elif self.plugin._func_update_sent == 51:
            self.plugin._submit_event("ida.function.updated.throttled", {"window_seconds": 5, "limit": 50})
        return 0

    def deleting_func(self, func):
        self.plugin._submit_event("ida.function.deleted", {"ea": _hex(func.start_ea), "end_ea": _hex(func.end_ea)})
        self.plugin._panel_event(f"function deleted {_hex(func.start_ea)}")
        return 0


class IX64MCPActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class IX64MCPPanel:
    def __init__(self, plugin: IX64MCPIdaPlugin) -> None:
        self.plugin = plugin
        self.viewer = None

    def show(self) -> None:
        if self.viewer is None:
            self.viewer = IX64MCPViewer(self)
            if not self.viewer.Create("IX64MCP"):
                ida_kernwin.msg("[IX64MCP] failed to create native viewer panel.\n")
                self.viewer = None
                return
        self.viewer.Show()
        self.refresh()

    def refresh(self) -> None:
        if self.viewer is None:
            return
        status = "connected" if self.plugin.socket is not None else "disconnected"
        active = _hex(self.plugin.last_ea) if self.plugin.last_ea != idc.BADADDR else "unknown"
        state = self.plugin.panel_state
        runtime_address = state.get("active_runtime_address") or "unknown"
        mapped_ea = state.get("active_ida_ea") or active
        pending = state.get("suggestions", [])
        trace_batches = state.get("trace_batches", [])
        recipes = state.get("trace_recipes", [])
        lines = [
            f"IDA bridge: {status}",
            f"IDA EA: {mapped_ea}",
            f"x64dbg address: {runtime_address}",
            f"pending suggestions: {len(pending)}",
            f"trace recipes: {len([item for item in recipes if item.get('enabled')])}",
            "",
            "Actions:",
            "  Use Edit > Plugins > IX64MCP actions or hotkeys after binding them in IDA.",
            "  Available actions: Follow x64dbg, Send function to Codex, Apply/Reject via MCP tools.",
            "",
            "Pending suggestions:",
            *[
                f"  {item.get('id')} | {item.get('kind')} | {item.get('target')} -> {item.get('suggested_value')}"
                for item in pending[:20]
            ],
            "",
            "Recent trace:",
            *[
                f"  batch {index + 1}: {item.get('count', 0)} events"
                for index, item in enumerate(trace_batches[-5:])
            ],
            "",
            "Recent events:",
            *self.plugin.events[-20:],
        ]
        self.viewer.replace_lines(lines)

    def selected_suggestion(self) -> dict[str, Any] | None:
        pending = self.plugin.panel_state.get("suggestions", [])
        return pending[0] if pending else None


class IX64MCPViewer(ida_kernwin.simplecustviewer_t):
    def __init__(self, panel: IX64MCPPanel) -> None:
        super().__init__()
        self.panel = panel

    def replace_lines(self, lines: list[str]) -> None:
        self.ClearLines()
        for line in lines:
            self.AddLine(line)
        self.Refresh()

    def OnClose(self):
        self.panel.viewer = None


class IX64MCPPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IX64MCP bridge"
    help = "Connect IDA Pro to the IX64MCP server"
    wanted_name = "IX64MCP"
    wanted_hotkey = ""

    def init(self):
        global PLUGIN
        if PLUGIN is None:
            PLUGIN = IX64MCPIdaPlugin()
            PLUGIN.start()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if PLUGIN is not None:
            PLUGIN.panel.show()

    def term(self):
        if PLUGIN is not None:
            PLUGIN.stop()


def ida_idp_name() -> str:
    return ida_ida.inf_get_procname()


PLUGIN = None


def PLUGIN_ENTRY():
    return IX64MCPPlugin()
