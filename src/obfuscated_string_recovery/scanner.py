"""A small static interpreter for a documented x86-64 instruction subset.

No bytes from the inspected object are executed or passed to a native decoder.
The only accepted input is a bounded ELF64 little-endian x86-64 relocatable
object with sized function symbols and no relocation targeting .text.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from pathlib import Path


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")


class InputRejected(ValueError):
    """The file is outside the supported static analysis boundary."""


class BudgetExceeded(InputRejected):
    """A deterministic or elapsed-time budget was exceeded."""


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 1_048_576
    max_sections: int = 128
    max_text_bytes: int = 65_536
    max_functions: int = 64
    max_function_bytes: int = 4096
    max_instructions: int = 4096
    max_stack_cells: int = 256
    max_writes: int = 4096
    max_strings: int = 16
    max_string_bytes: int = 64
    max_wall_ms: int = 500

    def __post_init__(self) -> None:
        if any(value <= 0 for value in vars(self).values()):
            raise ValueError("all limits must be positive")


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    kind: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


@dataclass(frozen=True)
class Function:
    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class Cell:
    value: int
    initial_file_offset: int
    last_write_file_offset: int
    transform_file_offsets: tuple[int, ...] = ()


class UnsupportedInstruction(Exception):
    def __init__(self, position: int, reason: str):
        super().__init__(reason)
        self.position = position
        self.reason = reason


def _deadline_check(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise BudgetExceeded("wall-time budget exceeded")


def _string(table: bytes, offset: int, label: str) -> str:
    if offset >= len(table):
        raise InputRejected(f"{label} string offset outside table")
    end = table.find(b"\0", offset, min(len(table), offset + 129))
    if end < 0:
        raise InputRejected(f"{label} string is not terminated within 128 bytes")
    raw = table[offset:end]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputRejected(f"{label} is not UTF-8") from exc


def _parse_elf(data: bytes, limits: Limits, deadline: float) -> tuple[Section, list[Function]]:
    if len(data) < ELF_HEADER.size or len(data) > limits.max_file_bytes:
        raise InputRejected("file size outside configured boundary")
    fields = ELF_HEADER.unpack_from(data)
    ident = fields[0]
    if ident[:4] != b"\x7fELF" or ident[4:7] != b"\x02\x01\x01":
        raise InputRejected("expected little-endian ELF64")
    if fields[1] != 1 or fields[2] != 62 or fields[3] != 1 or fields[4] != 0:
        raise InputRejected("expected x86-64 ET_REL object without entry point")
    shoff, phnum, shentsize, shnum, shstrndx = fields[6], fields[10], fields[11], fields[12], fields[13]
    if phnum or fields[8] != ELF_HEADER.size or shentsize != SECTION_HEADER.size:
        raise InputRejected("unexpected ELF header layout")
    if not 1 <= shnum <= limits.max_sections or shstrndx >= shnum:
        raise InputRejected("section count or name-table index outside boundary")
    if shoff > len(data) or shnum * shentsize > len(data) - shoff:
        raise InputRejected("section header table outside file")
    raw_sections = [SECTION_HEADER.unpack_from(data, shoff + i * shentsize) for i in range(shnum)]
    for row in raw_sections:
        kind, offset, size = row[1], row[4], row[5]
        if kind != 8 and (offset > len(data) or size > len(data) - offset):
            raise InputRejected("section contents outside file")
    names_row = raw_sections[shstrndx]
    if names_row[1] != 3:
        raise InputRejected("section name table is not a string table")
    name_table = data[names_row[4]:names_row[4] + names_row[5]]
    sections = [
        Section(i, _string(name_table, row[0], "section"), row[1], row[2],
                row[4], row[5], row[6], row[7], row[9])
        for i, row in enumerate(raw_sections)
    ]
    texts = [section for section in sections if section.name == ".text"]
    if len(texts) != 1 or texts[0].kind != 1 or not (texts[0].flags & 4):
        raise InputRejected("expected one executable .text section")
    text = texts[0]
    if text.size == 0 or text.size > limits.max_text_bytes:
        raise InputRejected(".text size outside configured boundary")
    if any(section.kind in (4, 9) and section.info == text.index and section.size
           for section in sections):
        raise InputRejected("relocations targeting .text are unsupported")
    symtabs = [section for section in sections if section.kind == 2]
    if len(symtabs) != 1:
        raise InputRejected("expected one static symbol table")
    symtab = symtabs[0]
    if symtab.entsize != SYMBOL.size or symtab.size % SYMBOL.size or symtab.link >= len(sections):
        raise InputRejected("symbol table layout outside boundary")
    if symtab.size // SYMBOL.size > 512 or sections[symtab.link].kind != 3:
        raise InputRejected("symbol count or linked string table outside boundary")
    linked = sections[symtab.link]
    symbol_names = data[linked.offset:linked.offset + linked.size]
    functions: list[Function] = []
    for i in range(symtab.size // SYMBOL.size):
        if i % 32 == 0:
            _deadline_check(deadline)
        name_off, info, _other, section_index, offset, size = SYMBOL.unpack_from(
            data, symtab.offset + i * SYMBOL.size
        )
        if info & 15 != 2 or section_index != text.index or size == 0:
            continue
        if offset > text.size or size > text.size - offset or size > limits.max_function_bytes:
            raise InputRejected("function range outside .text or byte budget")
        functions.append(Function(_string(symbol_names, name_off, "function"), offset, size))
        if len(functions) > limits.max_functions:
            raise BudgetExceeded("function-count budget exceeded")
    functions.sort(key=lambda function: (function.offset, function.name))
    if not functions:
        raise InputRejected("no sized function symbols in .text")
    for left, right in zip(functions, functions[1:]):
        if left.offset + left.size > right.offset:
            raise InputRejected("overlapping function ranges")
    return text, functions


def _signed_disp(raw: int) -> int:
    return raw - 256 if raw >= 128 else raw


def _require_local_slot(slot: int, width: int, cursor: int) -> None:
    if slot < -128 or slot + width - 1 > -1:
        raise UnsupportedInstruction(cursor, "stack address is outside local frame slots")


def _extract_strings(
    function: Function, text: Section, memory: dict[int, Cell], limits: Limits
) -> list[dict]:
    findings: list[dict] = []
    for start in sorted(memory):
        if start - 1 in memory and 32 <= memory[start - 1].value <= 126:
            continue
        cells: list[tuple[int, Cell]] = []
        for slot in range(start, start + limits.max_string_bytes + 1):
            cell = memory.get(slot)
            if cell is None:
                break
            if cell.value == 0:
                if len(cells) >= 4:
                    provenance = [
                        {
                            "index": index,
                            "stack_offset": stack_offset,
                            "initial_file_offset": entry.initial_file_offset,
                            "last_write_file_offset": entry.last_write_file_offset,
                            "transform_file_offsets": list(entry.transform_file_offsets),
                        }
                        for index, (stack_offset, entry) in enumerate(cells + [(slot, cell)])
                    ]
                    transforms = sorted({offset for row in provenance
                                         for offset in row["transform_file_offsets"]})
                    findings.append({
                        "function": function.name,
                        "value": bytes(entry.value for _, entry in cells).decode("ascii"),
                        "classification": "decoded" if transforms else "plain_stack",
                        "stack_start": start,
                        "text_section_file_offset": text.offset,
                        "function_section_offset": function.offset,
                        "byte_provenance": provenance,
                        "transform_file_offsets": transforms,
                        "uncertainty": "Runtime reachability and behavior outside the accepted straight-line subset are unproven.",
                    })
                break
            if not 32 <= cell.value <= 126:
                break
            cells.append((slot, cell))
    return findings


def _interpret(
    data: bytes, text: Section, function: Function, limits: Limits,
    budget: dict[str, int], deadline: float,
) -> list[dict]:
    code = data[text.offset + function.offset:text.offset + function.offset + function.size]
    memory: dict[int, Cell] = {}
    register: tuple[int, int, Cell] | None = None
    if not code.startswith(b"\x55\x48\x89\xe5"):
        raise UnsupportedInstruction(0, "unsupported function prologue")
    cursor = 4
    budget["instructions"] += 2
    if code[cursor:cursor + 3] == b"\x48\x83\xec":
        cursor += 4
        budget["instructions"] += 1
    elif code[cursor:cursor + 3] == b"\x48\x81\xec":
        cursor += 7
        budget["instructions"] += 1
    epilogue = False
    while cursor < len(code):
        _deadline_check(deadline)
        if budget["instructions"] >= limits.max_instructions:
            raise BudgetExceeded("instruction-count budget exceeded")
        budget["instructions"] += 1
        file_offset = text.offset + function.offset + cursor
        remaining = code[cursor:]
        if remaining == b"\xc3" and epilogue:
            return _extract_strings(function, text, memory, limits)
        if epilogue:
            raise UnsupportedInstruction(cursor, "unexpected bytes after epilogue")
        if remaining.startswith((b"\x5d\xc3", b"\xc9\xc3")) and len(remaining) == 2:
            epilogue = True
            cursor += 1
            continue
        if remaining.startswith(b"\xc6\x45") and len(remaining) >= 4:
            slot, value = _signed_disp(remaining[2]), remaining[3]
            _require_local_slot(slot, 1, cursor)
            memory[slot] = Cell(value, file_offset, file_offset)
            cursor += 4
            budget["writes"] += 1
        elif remaining.startswith(b"\x8a\x45") and len(remaining) >= 3:
            slot = _signed_disp(remaining[2])
            _require_local_slot(slot, 1, cursor)
            cell = memory.get(slot)
            if cell is None:
                raise UnsupportedInstruction(cursor, "load from unknown stack byte")
            register = (cell.value, slot, cell)
            cursor += 3
        elif remaining.startswith(b"\x0f\xb6\xc0") and len(remaining) >= 3:
            if register is None:
                raise UnsupportedInstruction(cursor, "zero extension of unknown AL")
            cursor += 3
        elif remaining.startswith(b"\x83\xf0") and len(remaining) >= 3:
            if register is None:
                raise UnsupportedInstruction(cursor, "arithmetic on unknown AL")
            value, slot, cell = register
            register = (value ^ remaining[2], slot,
                        Cell(cell.value, cell.initial_file_offset, cell.last_write_file_offset,
                             cell.transform_file_offsets + (file_offset,)))
            cursor += 3
        elif remaining.startswith(b"\x88\x45") and len(remaining) >= 3:
            slot = _signed_disp(remaining[2])
            _require_local_slot(slot, 1, cursor)
            if register is None or register[1] != slot:
                raise UnsupportedInstruction(cursor, "store without same-slot provenance")
            value, _origin_slot, cell = register
            memory[slot] = Cell(value, cell.initial_file_offset, file_offset,
                                cell.transform_file_offsets)
            register = None
            cursor += 3
            budget["writes"] += 1
        elif remaining.startswith(b"\x90"):
            cursor += 1
        else:
            raise UnsupportedInstruction(cursor, "instruction outside the accepted subset")
        if len(memory) > limits.max_stack_cells or budget["writes"] > limits.max_writes:
            raise BudgetExceeded("stack-cell or write-count budget exceeded")
    raise UnsupportedInstruction(cursor, "function has no accepted return")


def scan_bytes(data: bytes, limits: Limits | None = None, *, _started: float | None = None) -> dict:
    """Statically inspect a bounded object; never execute its contents."""
    limits = limits or Limits()
    started = time.monotonic() if _started is None else _started
    deadline = started + limits.max_wall_ms / 1000
    text, functions = _parse_elf(data, limits, deadline)
    budget = {"instructions": 0, "writes": 0}
    findings: list[dict] = []
    skipped: list[dict] = []
    for function in functions:
        _deadline_check(deadline)
        try:
            findings.extend(_interpret(data, text, function, limits, budget, deadline))
        except UnsupportedInstruction as exc:
            skipped.append({
                "function": function.name,
                "file_offset": text.offset + function.offset + exc.position,
                "reason": exc.reason,
            })
        if len(findings) > limits.max_strings:
            raise BudgetExceeded("finding-count budget exceeded")
    finished = time.monotonic()
    if finished > deadline:
        raise BudgetExceeded("wall-time budget exceeded")
    return {
        "status": "PASS_STATIC_ONLY",
        "format": "ELF64 little-endian x86-64 ET_REL",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "elapsed_ms": round((finished - started) * 1000, 3),
        "analysis": "bounded straight-line stack-byte interpretation",
        "limits": vars(limits),
        "counts": {
            "functions": len(functions),
            "instructions": budget["instructions"],
            "writes": budget["writes"],
            "findings": len(findings),
            "skipped_functions": len(skipped),
        },
        "findings": findings,
        "skipped_functions": skipped,
        "uncertainty": "No claim of runtime reachability, complete x86 coverage, or absence of other strings.",
    }


def scan_path(path: Path, limits: Limits | None = None) -> dict:
    limits = limits or Limits()
    started = time.monotonic()
    if path.stat().st_size > limits.max_file_bytes:
        raise InputRejected("file size outside configured boundary")
    data = path.read_bytes()
    if time.monotonic() > started + limits.max_wall_ms / 1000:
        raise BudgetExceeded("wall-time budget exceeded during bounded file read")
    return scan_bytes(data, limits, _started=started)
