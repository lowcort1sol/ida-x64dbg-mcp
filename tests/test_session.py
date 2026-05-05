from ix64mcp.session import AnalysisSession


def test_runtime_to_ida_rebased_module() -> None:
    session = AnalysisSession()
    session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x200000)

    assert session.runtime_to_ida(0x7FF700001234) == 0x140001234
    assert session.ida_to_runtime(0x140001234) == 0x7FF700001234


def test_unmapped_address_returns_none() -> None:
    session = AnalysisSession()
    session.upsert_mapping("sample.exe", ida_base=0x140000000, runtime_base=0x7FF700000000, size=0x1000)

    assert session.runtime_to_ida(0x7FF700002000) is None
    assert session.ida_to_runtime(0x140002000) is None


def test_summary_uses_hex_addresses() -> None:
    session = AnalysisSession(active_ida_ea=0x140001000, active_runtime_address=0x7FF700001000)
    session.breakpoints.add(0x7FF700001000)

    summary = session.summary({"ida": True, "x64dbg": False})

    assert summary["active_ida_ea"] == "0x140001000"
    assert summary["active_runtime_address"] == "0x7ff700001000"
    assert summary["breakpoints"] == ["0x7ff700001000"]

