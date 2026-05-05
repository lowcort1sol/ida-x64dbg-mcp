from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .pe import load_pe
from .protocol import parse_address


JCC_SHORT = {
    0x70: "jo",
    0x71: "jno",
    0x72: "jb",
    0x73: "jnb",
    0x74: "jz",
    0x75: "jnz",
    0x76: "jbe",
    0x77: "ja",
    0x78: "js",
    0x79: "jns",
    0x7A: "jp",
    0x7B: "jnp",
    0x7C: "jl",
    0x7D: "jge",
    0x7E: "jle",
    0x7F: "jg",
}
JCC_NEAR = {
    0x80: "jo",
    0x81: "jno",
    0x82: "jb",
    0x83: "jnb",
    0x84: "jz",
    0x85: "jnz",
    0x86: "jbe",
    0x87: "ja",
    0x88: "js",
    0x89: "jns",
    0x8A: "jp",
    0x8B: "jnp",
    0x8C: "jl",
    0x8D: "jge",
    0x8E: "jle",
    0x8F: "jg",
}
COMPARE_OPS = {0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x80, 0x81, 0x83, 0x84, 0x85}
SUCCESS_WORDS = ("success", "correct", "valid", "good", "welcome", "accepted", "right", "ok")
FAILURE_WORDS = ("fail", "wrong", "invalid", "bad", "denied", "incorrect", "nope", "try")


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass(slots=True)
class PeView:
    path: Path
    image_base: int
    data: bytes
    sections: list[dict[str, int]]

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            start = section["virtual_address"]
            size = max(section["virtual_size"], section["raw_size"])
            if start <= rva < start + size:
                offset = section["raw_pointer"] + (rva - start)
                return offset if 0 <= offset < len(self.data) else None
        return rva if 0 <= rva < len(self.data) else None

    def offset_to_rva(self, offset: int) -> int | None:
        for section in self.sections:
            start = section["raw_pointer"]
            end = start + section["raw_size"]
            if start <= offset < end:
                return section["virtual_address"] + (offset - start)
        return offset if 0 <= offset < len(self.data) else None


def _load_view(path: str | Path) -> PeView:
    file_path = Path(path)
    data = file_path.read_bytes()
    pe = load_pe(file_path)
    try:
        sections = [
            {
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_pointer": int(section.PointerToRawData),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": int(section.Characteristics),
            }
            for section in pe.sections
        ]
        return PeView(file_path, int(pe.OPTIONAL_HEADER.ImageBase), data, sections)
    finally:
        pe.close()


def plan_patches(path: str | Path, limit: int | str | None = 50, window: int | str | None = 8) -> dict[str, Any]:
    max_items = max(1, min(int(limit or 50), 200))
    compare_window = max(1, min(int(window or 8), 32))
    view = _load_view(path)
    strings = _find_interesting_strings(view, max_items)
    candidates = _find_jcc_candidates(view, max_items, compare_window)
    return {
        "path": str(view.path),
        "sha256": _sha256(view.path),
        "image_base": _hex(view.image_base),
        "strings": strings,
        "candidates": candidates,
        "notes": [
            "Read-only planner: no bytes were modified.",
            "Prefer invert_jcc for minimal behavior flip; use nop_jcc only after manual review.",
            "Verify the current bytes before applying any patch.",
        ],
    }


def apply_file_patch(
    path: str | Path,
    file_offset: str | int,
    expected_hex: str,
    patch_hex: str,
    reason: str = "",
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    source = Path(path)
    offset = parse_address(str(file_offset)) if not isinstance(file_offset, int) else file_offset
    expected = bytes.fromhex(expected_hex)
    patch = bytes.fromhex(patch_hex)
    if not expected or not patch:
        raise ValueError("expected_hex and patch_hex must be non-empty hex strings")
    data = bytearray(source.read_bytes())
    if offset < 0 or offset + len(expected) > len(data):
        raise ValueError("file offset is outside the file")
    current = bytes(data[offset : offset + len(expected)])
    if current != expected:
        raise ValueError(f"current bytes mismatch at {_hex(offset)}: expected {expected.hex()}, got {current.hex()}")
    target = Path(output_path) if output_path else source
    backup = target.with_suffix(target.suffix + f".bak-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}")
    if target.exists():
        shutil.copy2(target, backup)
    data[offset : offset + len(patch)] = patch
    target.write_bytes(data)
    report = {
        "path": str(target),
        "backup": str(backup),
        "file_offset": _hex(offset),
        "expected_hex": expected.hex(),
        "patch_hex": patch.hex(),
        "reason": reason,
        "sha256_before": _sha256(backup),
        "sha256_after": _sha256(target),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    report_path = target.with_suffix(target.suffix + ".ix64patch.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    report["report"] = str(report_path)
    return report


def rollback_file_patch(path: str | Path, backup_path: str | Path) -> dict[str, Any]:
    target = Path(path)
    backup = Path(backup_path)
    if not backup.exists():
        raise FileNotFoundError(str(backup))
    before = _sha256(target) if target.exists() else None
    shutil.copy2(backup, target)
    return {
        "path": str(target),
        "backup": str(backup),
        "sha256_before_rollback": before,
        "sha256_after_rollback": _sha256(target),
        "timestamp": datetime.now(UTC).isoformat(),
    }


def diff_file_patch(path: str | Path, backup_path: str | Path, limit: int | str | None = 100) -> dict[str, Any]:
    target = Path(path)
    backup = Path(backup_path)
    max_items = max(1, min(int(limit or 100), 1000))
    old = backup.read_bytes()
    new = target.read_bytes()
    rows: list[dict[str, str]] = []
    for index, (before, after) in enumerate(zip(old, new)):
        if before != after:
            rows.append({"file_offset": _hex(index), "before": f"{before:02x}", "after": f"{after:02x}"})
            if len(rows) >= max_items:
                break
    size_changed = len(old) != len(new)
    return {
        "path": str(target),
        "backup": str(backup),
        "sha256_before": _sha256(backup),
        "sha256_after": _sha256(target),
        "size_changed": size_changed,
        "diffs": rows,
        "truncated": len(rows) >= max_items,
    }


def _find_interesting_strings(view: PeView, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    data = view.data
    start = None
    for index, byte in enumerate(data + b"\x00"):
        printable = 32 <= byte < 127
        if printable and start is None:
            start = index
        if (not printable) and start is not None:
            if index - start >= 4:
                text = data[start:index].decode("ascii", errors="replace")
                lowered = text.lower()
                kind = "success" if any(word in lowered for word in SUCCESS_WORDS) else "failure" if any(word in lowered for word in FAILURE_WORDS) else None
                if kind:
                    rva = view.offset_to_rva(start)
                    rows.append(
                        {
                            "kind": kind,
                            "text": text[:200],
                            "file_offset": _hex(start),
                            "rva": None if rva is None else _hex(rva),
                            "va": None if rva is None else _hex(view.image_base + rva),
                        }
                    )
                    if len(rows) >= limit:
                        return rows
            start = None
    return rows


def _find_jcc_candidates(view: PeView, limit: int, compare_window: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text_ranges = [
        section
        for section in view.sections
        if section["characteristics"] & 0x20 and section["raw_pointer"] and section["raw_size"]
    ]
    for section in text_ranges:
        start = section["raw_pointer"]
        end = min(len(view.data), start + section["raw_size"])
        index = start
        while index < end and len(rows) < limit:
            byte = view.data[index]
            if byte in JCC_SHORT and index + 1 < end:
                expected = view.data[index : index + 2]
                patch = bytes([byte ^ 1, expected[1]])
                rows.append(_candidate(view, index, 2, JCC_SHORT[byte], expected, patch, compare_window))
                index += 2
                continue
            if byte == 0x0F and index + 5 < end and view.data[index + 1] in JCC_NEAR:
                op = view.data[index + 1]
                expected = view.data[index : index + 6]
                patch = bytes([0x0F, op ^ 1]) + expected[2:]
                rows.append(_candidate(view, index, 6, JCC_NEAR[op], expected, patch, compare_window))
                index += 6
                continue
            index += 1
        if len(rows) >= limit:
            break
    return rows


def _candidate(view: PeView, offset: int, size: int, mnemonic: str, expected: bytes, invert_patch: bytes, compare_window: int) -> dict[str, Any]:
    rva = view.offset_to_rva(offset)
    nearby_start = max(0, offset - compare_window)
    nearby = view.data[nearby_start:offset]
    has_compare = any(byte in COMPARE_OPS for byte in nearby)
    return {
        "file_offset": _hex(offset),
        "rva": None if rva is None else _hex(rva),
        "va": None if rva is None else _hex(view.image_base + rva),
        "mnemonic": mnemonic,
        "current_bytes": expected.hex(),
        "nearby_compare_like": has_compare,
        "proposals": [
            {"kind": "invert_jcc", "patch_hex": invert_patch.hex(), "description": f"invert {mnemonic} condition"},
            {"kind": "nop_jcc", "patch_hex": ("90" * size), "description": "remove conditional branch with NOPs"},
        ],
    }
