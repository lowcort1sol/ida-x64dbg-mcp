# IX64MCP

Unified local MCP server for Codex-driven reverse engineering with IDA Pro and x64dbg.

The MVP has three pieces:

- `ix64mcp`: Python MCP server and localhost bridge hub.
- `bridges/ida/ix64mcp_ida.py`: IDAPython bridge plugin.
- `bridges/x64dbg/ix64mcp_x64dbg.cpp`: x64dbg plugin skeleton for the x64 target.

There is also a small `samples/` tree with deliberately simple binaries for reverse-engineering practice:

- `samples/crackme_simple`: a tiny password checker with a couple of helper functions and obvious inspection points.
- `samples/anti_debug_demo`: a benign debugger-detection example with timing and environment checks.
- `samples/control_flow_lab`: a branch-heavy console app designed to make control-flow exploration and renaming useful.

All bridge traffic is local-only by default. The server listens for IDA/x64dbg bridge clients on `127.0.0.1:8765` and exposes MCP tools/resources over stdio.

## Phase 1 Production Foundation

The bridge protocol now has a small production-oriented handshake:

- `protocol_version`: current value is `0.1`.
- `bridge_version`: bridge implementation version.
- `capabilities`: event and command names supported by each bridge.
- `token`: optional shared secret from `IX64MCP_TOKEN`.

Authentication is off by default for frictionless local development. To require a shared token, set the same environment variable before launching Codex/IX64MCP, IDA, and x64dbg:

```powershell
$env:IX64MCP_TOKEN = "change-me-local-secret"
```

Session state is now durable enough for real investigations:

- SQLite event/session database: `state/ix64mcp.sqlite3`
- JSONL timeline files: `state/timeline/*.jsonl`
- Override location with `IX64MCP_STATE_DIR`.

The server records bridge connect/disconnect, tool calls, analysis notes, mapping changes, and debugger events. The x64dbg bridge announces `module.loaded` and `module.unloaded`, so stale runtime mappings are removed when DLLs unload.

Reconnect recovery uses that stored state when the MCP server starts again. It restores the latest session metadata, module mappings, and remembered breakpoints, then reapplies those breakpoints when x64dbg reconnects.

Risky actions are now separated behind a policy layer. The default mode is `analysis-safe`; future tools for patching memory, dumping memory, or long scripted execution must pass policy approval before they can run.

## Phase 2 Reverse Workflow Tools

Phase 2 adds compact reverse-engineering queries designed to avoid flooding the agent context:

- `ida.list_strings(query, limit, offset)` searches IDA strings with pagination.
- `ida.get_string_xrefs(address, limit)` returns data references to one string.
- `ida.function_summary(ea, detail, max_pseudocode_chars)` returns calls, strings, imports, stack vars, and optional capped pseudocode.
- `pe.summary(path, limit)` returns PE sections and high-level directory counts.
- `pe.imports`, `pe.exports`, `pe.resources`, and `pe.relocations` expose paginated PE details.

The default behavior is intentionally compact. Use `limit`, `offset`, `detail="full"`, or `max_pseudocode_chars` only when the current question needs more detail.

## Phase 3 IDA Power Layer

Phase 3 makes IDA more operator-friendly while keeping changes preview-first:

- Real IDA database hooks emit name/comment/function/cursor events into the MCP timeline.
- `ida.pseudocode`, `ida.refresh_decompiler`, and `ida.set_decompiler_comment` add capped Hex-Rays integration.
- `analysis.suggest_name`, `analysis.suggest_comment`, `analysis.list_suggestions`, `analysis.apply_suggestion`, and `analysis.reject_suggestion` implement a persistent suggestion review flow.
- The IDA plugin registers actions for showing the IX64MCP panel, following x64dbg, and sending the current function context to Codex.
- The minimal IDA panel shows bridge status, current IDA address, and recent local bridge events.

Suggestions are not applied automatically. Codex creates preview items, then IDA-safe apply calls perform the actual rename/comment only after explicit approval.

## Phase 4 x64dbg Power Layer

Phase 4 adds a stronger dynamic-analysis surface while keeping high-frequency data capped:

- The IDA panel now live-refreshes from server-pushed state with a 500ms throttle; open it once with `IX64MCP: Show Panel`.
- `x64dbg.memory_map`, `x64dbg.call_stack`, `x64dbg.threads`, `x64dbg.exceptions`, `x64dbg.breakpoint_snapshot`, and `x64dbg.dump_metadata` expose compact runtime state.
- Hardware, memory, and conditional breakpoint tools are wired through x64dbg commands for the first x64 path.
- Breakpoint hits include a capped register/stack snapshot and thread/exception/module events update the timeline.
- `trace.recipe_enable`, `trace.recipe_disable`, and `trace.recipe_status` manage API tracing recipes for common loader, file, registry, network, and socket APIs.
- Trace API events are batched into `trace.batch` entries with hard caps so Codex does not ingest an unbounded stream.

`x64dbg.dump_metadata` returns only region/module/protection-style metadata and cheap entropy information. Raw memory dumping remains policy-blocked as `x64dbg.dump_memory`.

## Phase 5 Patch/Crackme Assistant

Phase 5 starts with a safe patch-planning workflow:

- `patch.plan(path?, limit?, window?)` scans a PE for success/failure-like strings and compare/conditional-branch patterns. It reports VA, RVA, file offset, current bytes, and minimal patch proposals.
- `patch.apply_file(path, file_offset, expected_hex, patch_hex, reason?, output_path?)` is policy-gated. It verifies current bytes, writes a backup, patches the file, and records before/after hashes.
- `patch.diff(path, backup_path, limit?)` reports byte-level differences between the patched file and backup.
- `patch.rollback(path, backup_path)` restores a patched file from backup and logs hashes.

Memory patching remains a future risky action. The current public path is preview-first and file-patching only after explicit `analysis.policy_approve`.

## Phase 6 Malware Analysis Readiness

Phase 6 adds a sample-centric workflow for real investigations:

- `malware.workspace_create(path?, idb_path?, debugger_session_path?, notes?, copy_sample?)` creates `state/workspaces/<sha256>/workspace.json`, records hashes, optional IDB/debugger paths, notes, IoCs, and extracted configs.
- `malware.triage(path?, limit?)` returns hashes, entropy, PE sections/imports/resources, suspicious strings/imports, packer hints, and overlay metadata.
- `malware.add_ioc(sample_sha256?, kind, value, source?, note?)` and `malware.add_config(sample_sha256?, key, value, source?, confidence?)` append operator findings to the workspace.
- `malware.behavior_report()` summarizes timeline and trace events into files, registry, process, network indicators, decoded configs, IoCs, and a capped timeline tail.
- `malware.sandbox_check(allow_network?, vm_confirmed?, snapshot_confirmed?)` gives explicit safety gates for VM isolation, network exposure, snapshots, and dangerous actions.

The related resources are `malware://workspace` and `malware://behavior-report`. Outputs stay capped and structured so Codex can pull the exact layer it needs without ingesting an entire IDB or trace log.

## Phase 7 Agent UX

Phase 7 adds Codex-oriented workflow tools and compact resources:

- `workflow.follow_debugger`, `workflow.explain_current_function`, `workflow.find_password_check`, `workflow.break_on_first_strcmp_like`, `workflow.rename_functions_from_trace`, `workflow.make_patch_plan`, and `workflow.generate_analysis_report` orchestrate existing safe IDA/x64dbg/patch/malware APIs.
- `analysis.timeline_summary` groups timeline noise by event/source/address/API so Codex can browse signal instead of raw spam.
- `analysis.session_list` and `analysis.session_resume` make restarts explicit and recover the latest sample, mappings, breakpoints, suggestions, workspace metadata, and recent timeline.
- New resources: `analysis://current`, `analysis://modules`, `analysis://functions/hot`, `analysis://patches`, and `analysis://report`.

The workflow layer is analysis-safe by default. It plans patches and creates rename suggestions, but does not apply file patches or memory writes unless the existing policy layer allows those lower-level tools.

## Quick Start

```powershell
uv python install 3.14.4
uv venv --python 3.14.4 .venv
uv pip install --python .\.venv\Scripts\python.exe -e ".[dev]"
.\.venv\Scripts\python -m ix64mcp.server
```

Run tests:

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m compileall ix64mcp bridges tests
```

Manual server run with visible logs:

```powershell
.\.venv\Scripts\python -m ix64mcp.server start --bridge-host 127.0.0.1 --bridge-port 8765 --log-file ix64mcp.log --log-level INFO
```

By default the server uses a single-instance lock at `state/ix64mcp.server.lock`. If another instance is running, startup exits with code `2` and logs an error instead of spawning duplicates.
If the lock is free but the bridge port is already occupied by a stale server, startup exits with code `3`.

Default log file location:

```text
state/ix64mcp.log
```

Server control commands:

```powershell
.\.venv\Scripts\python -m ix64mcp.server status
.\.venv\Scripts\python -m ix64mcp.server stop
.\.venv\Scripts\python -m ix64mcp.server start
```

If `stop` reports a stale/legacy server without a valid lock, use:

```powershell
.\.venv\Scripts\python -m ix64mcp.server stop --force
```

## Build x64dbg Bridge

The x64dbg bridge builds as an x64 plugin named `ix64mcp.dp64`.

```powershell
$vs = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
cmd /c "call `"$vs`" -arch=x64 -host_arch=x64 && `"$cmake`" -S bridges/x64dbg -B build/x64dbg-release -G Ninja -DCMAKE_BUILD_TYPE=Release && `"$cmake`" --build build/x64dbg-release"
```

Output:

```text
dist/x64dbg/ix64mcp.dp64
```

## Sample Projects

The sample projects are independent from the MCP server and can be built on their own.

```powershell
cmake -S samples -B build/samples -G Ninja
cmake --build build/samples
```

Produced binaries:

- `build/samples/crackme_simple/crackme_simple.exe`
- `build/samples/anti_debug_demo/anti_debug_demo.exe`
- `build/samples/control_flow_lab/control_flow_lab.exe`

Install by copying `dist/x64dbg/ix64mcp.dp64` into the x64dbg plugin folder, normally `release/x64/plugins/`, then start `release/x64/x64dbg.exe` while the MCP server is running.

Live smoke test:

```powershell
.\.venv\Scripts\python -m ix64mcp.smoke_x64dbg --kill --timeout 30 --event-timeout 10
```

Expected checks:

- x64dbg bridge connects to `127.0.0.1:8765`
- initial `debug.paused` event is observed
- register read returns `cip/csp/cax/...`
- module snapshot returns loaded modules
- memory read at `cip` returns bytes
- setting a breakpoint at `cip` and running emits `breakpoint.hit`

Break on the current main module entry from Codex after MCP refresh:

```text
analysis.break_on_entry
```

Optional arguments:

- `module`: module/mapping name, defaults to `main`
- `run`: `true` to continue after setting the breakpoint, defaults to `false`

## Codex MCP Config

This workspace is registered in the local Codex config as:

```toml
[mcp_servers.ix64mcp]
command = 'C:\Users\giornodjawana\Desktop\IX64MCP\.venv\Scripts\python.exe'
args = ['-m', 'ix64mcp.server']
```

Restart or refresh Codex after changing MCP config so the `ix64mcp` server is spawned by Codex. Start x64dbg after the MCP server is active; the x64dbg plugin connects back to `127.0.0.1:8765`.

Run the local simulator without IDA or x64dbg:

```powershell
.\.venv\Scripts\python -m ix64mcp.harness --role ida
.\.venv\Scripts\python -m ix64mcp.harness --role x64dbg
```

## Safety Model

The implemented default tool surface is analysis-safe: navigation, reads, names, comments, breakpoints, stepping, and pause/run control. Higher-risk operations such as memory patching, dumping, malware launch automation, or network interaction are intentionally not implemented in this MVP.
