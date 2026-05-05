from ix64mcp.bridge import BridgeRegistry
from ix64mcp.session import AnalysisSession


def test_x64dbg_breakpoint_event_maps_to_ida() -> None:
    session = AnalysisSession()
    session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    registry = BridgeRegistry(session)

    registry._apply_event("x64dbg", {"type": "breakpoint.hit", "payload": {"address": "0x7ff700001000"}})

    assert session.active_runtime_address == 0x7FF700001000
    assert session.active_ida_ea == 0x140001000
    assert session.timeline[-1].payload["ida_ea"] == "0x140001000"


def test_x64dbg_breakpoint_snapshot_updates_registers() -> None:
    session = AnalysisSession()
    session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)
    registry = BridgeRegistry(session)

    registry._apply_event(
        "x64dbg",
        {
            "type": "breakpoint.hit.snapshot",
            "payload": {"address": "0x7ff700001000", "registers": {"cip": "0x7ff700001000"}},
        },
    )

    assert session.active_runtime_address == 0x7FF700001000
    assert session.active_ida_ea == 0x140001000
    assert session.registers["cip"] == "0x7ff700001000"


def test_ida_rename_event_updates_names() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    registry._apply_event("ida", {"type": "function.renamed", "payload": {"ea": "0x140001000", "name": "decrypt_config"}})

    assert session.active_ida_ea == 0x140001000
    assert session.names[0x140001000] == "decrypt_config"


def test_ida_power_layer_events_update_names_and_comments() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    registry._apply_event("ida", {"type": "ida.name.changed", "payload": {"ea": "0x140001000", "name": "main_logic"}})
    registry._apply_event("ida", {"type": "ida.comment.changed", "payload": {"ea": "0x140001010", "text": "checks input"}})

    assert session.names[0x140001000] == "main_logic"
    assert session.comments[0x140001010] == "checks input"
    assert session.timeline[-1].type == "ida.comment.changed"


def test_sample_module_event_promotes_to_main_mapping() -> None:
    session = AnalysisSession(sample_id="sample.exe")
    session.upsert_mapping("main", ida_base=0x140000000, runtime_base=0x140000000, size=0x200000)
    registry = BridgeRegistry(session)

    registry._apply_event(
        "x64dbg",
        {
            "type": "module.loaded",
            "payload": {
                "name": "sample",
                "runtime_base": "0x7ff700000000",
                "size": "0x200000",
            },
        },
    )

    main = session.mapping_by_name("main")
    assert main is not None
    assert main.ida_base == 0x140000000
    assert main.runtime_base == 0x7FF700000000


def test_duplicate_module_events_are_deduplicated_by_module_key() -> None:
    session = AnalysisSession()
    registry = BridgeRegistry(session)

    payload = {"name": "kernel32.dll", "runtime_base": "0x7ffc49dc0000", "size": "0x1000"}
    registry._apply_event("x64dbg", {"type": "module.loaded", "payload": payload})
    registry._apply_event("x64dbg", {"type": "module.loaded", "payload": {**payload, "name": "kernel32"}})

    module_events = [event for event in session.timeline if event.type == "module.loaded"]
    assert len(module_events) == 1
    assert len([mapping for mapping in session.mappings if mapping.name.lower().startswith("kernel32")]) == 1


def test_module_unloaded_removes_runtime_mapping() -> None:
    session = AnalysisSession()
    session.upsert_mapping("kernel32", ida_base=0x7FFC49DC0000, runtime_base=0x7FFC49DC0000, size=0x200000)
    registry = BridgeRegistry(session)

    registry._apply_event(
        "x64dbg",
        {"type": "module.unloaded", "payload": {"runtime_base": "0x7ffc49dc0000"}},
    )

    assert session.mapping_by_name("kernel32") is None
    assert session.timeline[-1].type == "module.unloaded"


def test_bridge_token_is_optional_but_enforced_when_configured() -> None:
    open_registry = BridgeRegistry(AnalysisSession())
    locked_registry = BridgeRegistry(AnalysisSession(), token="secret")

    assert open_registry._token_valid(None)
    assert locked_registry._token_valid("secret")
    assert not locked_registry._token_valid("wrong")
