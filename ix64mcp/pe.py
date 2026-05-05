from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError:  # pragma: no cover - exercised only in underinstalled envs
    pefile = None


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _bounded(value: int | str | None, default: int, maximum: int) -> int:
    if value is None:
        return default
    parsed = int(value)
    return max(0, min(parsed, maximum))


def _safe_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    return str(value)


def load_pe(path: str | Path):
    if pefile is None:
        raise RuntimeError("pefile package is required for PE parsing")
    return pefile.PE(str(path), fast_load=False)


def pe_summary(path: str | Path, limit: int | str | None = 100) -> dict[str, Any]:
    max_items = _bounded(limit, 100, 500)
    pe = load_pe(path)
    try:
        imports = list(_iter_import_descriptors(pe))[:max_items]
        exports = list(_iter_exports(pe))[:max_items]
        sections = [_section_summary(section) for section in pe.sections[:max_items]]
        return {
            "path": str(path),
            "machine": _hex(pe.FILE_HEADER.Machine),
            "bitness": 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32,
            "image_base": _hex(pe.OPTIONAL_HEADER.ImageBase),
            "entry_point": _hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "entry_rva": _hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "sections": sections,
            "import_dlls": imports,
            "exports": exports,
            "has_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
            "has_relocations": hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"),
            "resource_count": len(list(_iter_resources(pe, max_items))),
        }
    finally:
        pe.close()


def pe_imports(path: str | Path, dll: str | None = None, limit: int | str | None = 200, offset: int | str | None = 0) -> dict[str, Any]:
    max_items = _bounded(limit, 200, 1000)
    skip = _bounded(offset, 0, 1_000_000)
    dll_filter = dll.lower() if dll else None
    pe = load_pe(path)
    try:
        rows: list[dict[str, Any]] = []
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll_name = _safe_text(descriptor.dll)
            if dll_filter and dll_filter not in dll_name.lower():
                continue
            for imported in descriptor.imports:
                rows.append(
                    {
                        "dll": dll_name,
                        "name": _safe_text(imported.name) if imported.name else None,
                        "ordinal": imported.ordinal,
                        "iat": _hex(imported.address),
                    }
                )
        selected = rows[skip : skip + max_items]
        return {"path": str(path), "offset": skip, "limit": max_items, "total": len(rows), "imports": selected}
    finally:
        pe.close()


def pe_exports(path: str | Path, limit: int | str | None = 200, offset: int | str | None = 0) -> dict[str, Any]:
    max_items = _bounded(limit, 200, 1000)
    skip = _bounded(offset, 0, 1_000_000)
    pe = load_pe(path)
    try:
        rows = list(_iter_exports(pe))
        return {"path": str(path), "offset": skip, "limit": max_items, "total": len(rows), "exports": rows[skip : skip + max_items]}
    finally:
        pe.close()


def pe_resources(path: str | Path, limit: int | str | None = 100, offset: int | str | None = 0) -> dict[str, Any]:
    max_items = _bounded(limit, 100, 500)
    skip = _bounded(offset, 0, 1_000_000)
    pe = load_pe(path)
    try:
        rows = list(_iter_resources(pe, max_items + skip))
        return {"path": str(path), "offset": skip, "limit": max_items, "total_seen": len(rows), "resources": rows[skip : skip + max_items]}
    finally:
        pe.close()


def pe_relocations(path: str | Path, limit: int | str | None = 200, offset: int | str | None = 0) -> dict[str, Any]:
    max_items = _bounded(limit, 200, 1000)
    skip = _bounded(offset, 0, 1_000_000)
    pe = load_pe(path)
    try:
        rows: list[dict[str, Any]] = []
        for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
            for entry in block.entries:
                rows.append({"rva": _hex(entry.rva), "type": entry.type})
        return {"path": str(path), "offset": skip, "limit": max_items, "total": len(rows), "relocations": rows[skip : skip + max_items]}
    finally:
        pe.close()


def _section_summary(section: Any) -> dict[str, Any]:
    return {
        "name": _safe_text(section.Name),
        "virtual_address": _hex(section.VirtualAddress),
        "virtual_size": _hex(section.Misc_VirtualSize),
        "raw_size": _hex(section.SizeOfRawData),
        "raw_pointer": _hex(section.PointerToRawData),
        "characteristics": _hex(section.Characteristics),
    }


def _iter_import_descriptors(pe: Any):
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        yield {"dll": _safe_text(descriptor.dll), "count": len(descriptor.imports)}


def _iter_exports(pe: Any):
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return
    for symbol in directory.symbols:
        yield {
            "name": _safe_text(symbol.name) if symbol.name else None,
            "ordinal": symbol.ordinal,
            "rva": _hex(symbol.address),
        }


def _iter_resources(pe: Any, limit: int):
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return
    count = 0
    stack = [([], root)]
    while stack and count < limit:
        path, node = stack.pop()
        for entry in getattr(node, "entries", []):
            name = str(entry.name) if entry.name is not None else str(entry.id)
            next_path = [*path, name]
            if hasattr(entry, "directory"):
                stack.append((next_path, entry.directory))
            elif hasattr(entry, "data"):
                data = entry.data.struct
                yield {"path": "/".join(next_path), "rva": _hex(data.OffsetToData), "size": data.Size}
                count += 1
                if count >= limit:
                    break
