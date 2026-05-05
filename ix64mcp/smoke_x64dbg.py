from __future__ import annotations

import argparse
import asyncio
import subprocess
import time
from pathlib import Path
from typing import Any

from .bridge import BridgeRegistry
from .session import AnalysisSession


async def wait_for_x64dbg(registry: BridgeRegistry, timeout: float) -> None:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if registry.connected()["x64dbg"]:
            return
        await asyncio.sleep(0.25)
    raise TimeoutError("x64dbg bridge did not connect")


async def wait_for_event(
    session: AnalysisSession,
    event_types: set[str],
    timeout: float,
    start_index: int = 0,
) -> dict[str, Any] | None:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        for event in session.timeline[start_index:]:
            if event.type in event_types:
                return event.as_json()
        await asyncio.sleep(0.25)
    return None


async def run_smoke(args: argparse.Namespace) -> int:
    session = AnalysisSession()
    registry = BridgeRegistry(session)
    server_task = asyncio.create_task(registry.serve(args.host, args.port))

    target = Path(args.target)
    debugger = Path(args.x64dbg)
    if not debugger.exists():
        raise FileNotFoundError(debugger)
    if not target.exists():
        raise FileNotFoundError(target)

    print(f"[smoke] bridge listening on ws://{args.host}:{args.port}")
    print(f"[smoke] launching {debugger} {target}")
    process = subprocess.Popen([str(debugger), str(target)], cwd=str(debugger.parent))

    try:
        await wait_for_x64dbg(registry, args.timeout)
        print("[smoke] x64dbg bridge connected")

        module = await wait_for_event(session, {"module.loaded"}, args.event_timeout)
        if module:
            print(f"[smoke] observed module event: {module}")
        else:
            print("[smoke] no module.loaded event observed before timeout")

        paused = await wait_for_event(session, {"debug.paused", "breakpoint.hit", "step"}, args.event_timeout)
        if paused:
            print(f"[smoke] observed debug event: {paused}")
        else:
            print("[smoke] no pause/breakpoint/step event observed before timeout")

        registers = await registry.request("x64dbg", "x64dbg.read_registers", {})
        print(f"[smoke] registers: {registers}")

        modules = await registry.request("x64dbg", "x64dbg.list_modules", {})
        module_count = len(modules.get("modules", [])) if isinstance(modules, dict) else 0
        print(f"[smoke] list_modules: {module_count} modules")

        address = registers.get("cip") or registers.get("rip") or registers.get("eip")
        if address and address != "0x0":
            memory = await registry.request("x64dbg", "x64dbg.read_memory", {"address": address, "size": 16})
            print(f"[smoke] memory@cip: {memory}")
        else:
            print("[smoke] skipped memory read because CIP/RIP/EIP is zero")

        if address and address != "0x0":
            breakpoint_result = await registry.request("x64dbg", "x64dbg.set_breakpoint", {"address": address})
            print(f"[smoke] set_breakpoint@cip: {breakpoint_result}")
            event_start = len(session.timeline)
            run_result = await registry.request("x64dbg", "x64dbg.run", {})
            print(f"[smoke] run: {run_result}")
            hit = await wait_for_event(session, {"breakpoint.hit", "debug.paused"}, args.event_timeout, event_start)
            if hit:
                print(f"[smoke] post-run event: {hit}")
            else:
                print("[smoke] no breakpoint/pause event observed after run before timeout")

        print(f"[smoke] connected state: {registry.connected()}")
        print(f"[smoke] mappings: {session.summary(registry.connected())['mappings']}")
        print(f"[smoke] timeline event count: {len(session.timeline)}")
        print(f"[smoke] last timeline events: {[event.as_json() for event in session.timeline[-8:]]}")
        return 0
    finally:
        if args.kill:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Live smoke test for the x64dbg IX64MCP bridge.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--timeout", default=20.0, type=float)
    parser.add_argument("--event-timeout", default=10.0, type=float)
    parser.add_argument("--x64dbg", default="release/x64/x64dbg.exe")
    parser.add_argument("--target", default="C:/Windows/System32/notepad.exe")
    parser.add_argument("--kill", action="store_true", help="Terminate x64dbg after the smoke test.")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run_smoke(args)))


if __name__ == "__main__":
    main()
