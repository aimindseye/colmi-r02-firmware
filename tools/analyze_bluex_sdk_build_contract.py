#!/usr/bin/env python3
"""
Analyze the BlueX SDKm/SDK3 build and image-generation contract and compare it
with the accepted RY02 stock-application anchors.

The tool is intentionally offline and read-only. It:
  * compares SDKm and SDK3 boot/image-tool artifacts by size and SHA256;
  * parses Intel HEX address ranges and validates checksums;
  * parses ELF32 headers, program headers, sections, and symbols without
    external dependencies;
  * decodes the boot_ram 0x20-byte header;
  * parses image_tool_v2/config.ini;
  * extracts relevant Keil .uvprojx project settings and startup sources;
  * compares the two SDKm startup files after whitespace normalization;
  * inspects the accepted RY02 .38 container and searches for plausible vector
    tables in the application body;
  * reports generic-SDK versus R02 layout agreement and conflicts.

It never builds, flashes, patches, or communicates with the ring.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import platform
import re
import struct
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


TOOL_REVISION = "r1"

DEFAULT_SDKM = Path("reference/bluex-sdkm-v3.3-20210804")
DEFAULT_SDK3 = Path("reference/bluex-sdk3-v3.3.8-20250117")
DEFAULT_FW38 = Path(
    "release/ry02-3.00.38-faster-raw-r1/RY02_3.00.38_250403.bin"
)

OUTER_HEADER_SIZE = 0x50
RUNTIME_BASE = 0x00824000
INNER_CODE_OFFSET = 0x400
INNER_CODE_RUNTIME = RUNTIME_BASE + INNER_CODE_OFFSET

EXPECTED_FW38_SHA256 = (
    "dbf64e3dc9aef112a4d69e46e516efb27f2ed2e3dc1d2d3f1af75939cc46487e"
)
EXPECTED_FW38_CONTAINER = 0x1CD64
EXPECTED_FW38_PAYLOAD = 0x1CD14
EXPECTED_OUTER_MAGIC = 0x81BDC3E5
EXPECTED_INNER_MAGIC = 0x0981000C

ACCEPTED_R02_APP_PHYSICAL = 0x24400
ACCEPTED_R02_OTA_PHYSICAL = 0x4D000
ACCEPTED_R02_CFG_PHYSICAL = 0x1400

ARTIFACTS = (
    "tools/bluex/bootloader/bootloader.hex",
    "tools/bluex/image_tool_v2/boot_ram.bin",
    "tools/bluex/image_tool_v2/boot_ram.elf",
    "tools/bluex/image_tool_v2/boot_ram.hex",
    "tools/bluex/image_tool_v2/boot_ram.asm",
    "tools/bluex/image_tool_v2/config.ini",
    "tools/bluex/image_tool_v2/boot_ram_config.exe",
)

PROJECT_CANDIDATES = (
    "examples/base/base/mdk/base.uvprojx",
)

STARTUP_CANDIDATES = (
    "examples/base/base/code/startup_apollo00_mcu.s",
    "platform/bluex/apollo/apollo00/system/startup_apollo00.s",
)

PROJECT_TAGS = {
    "TargetName",
    "Device",
    "Vendor",
    "Cpu",
    "FlashUtilSpec",
    "StartupFile",
    "OutputDirectory",
    "OutputName",
    "CreateExecutable",
    "CreateLib",
    "CreateHexFile",
    "DebugInformation",
    "ListingPath",
    "ScatterFile",
    "MiscControls",
    "AdsLmac",
    "AdsLmap",
    "AdsLven",
    "AdsLcross",
    "uAC6",
    "uAC6Lang",
    "Optim",
    "wLevel",
    "pCCUsed",
    "pAsm",
}


@dataclass(frozen=True)
class Artifact:
    root_name: str
    relative: str
    path: Path
    exists: bool
    size: int | None
    sha256: str | None


@dataclass
class HexInfo:
    valid: bool
    errors: list[str]
    data: dict[int, int]
    ranges: list[tuple[int, int]]
    entry_linear: int | None
    entry_segment: tuple[int, int] | None
    record_counts: dict[int, int]


@dataclass
class ElfInfo:
    valid: bool
    errors: list[str]
    elf_class: int | None = None
    endian: str | None = None
    machine: int | None = None
    entry: int | None = None
    program_headers: list[dict] | None = None
    sections: list[dict] | None = None
    symbols: list[dict] | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def u16(data: bytes, offset: int, endian: str = "<") -> int | None:
    if not 0 <= offset <= len(data) - 2:
        return None
    return struct.unpack_from(endian + "H", data, offset)[0]


def u32(data: bytes, offset: int, endian: str = "<") -> int | None:
    if not 0 <= offset <= len(data) - 4:
        return None
    return struct.unpack_from(endian + "I", data, offset)[0]


def collect_artifact(root_name: str, root: Path, relative: str) -> Artifact:
    path = root / relative
    if not path.is_file():
        return Artifact(root_name, relative, path, False, None, None)
    return Artifact(
        root_name=root_name,
        relative=relative,
        path=path,
        exists=True,
        size=path.stat().st_size,
        sha256=sha256_file(path),
    )


def contiguous_ranges(addresses: Iterable[int]) -> list[tuple[int, int]]:
    sorted_addresses = sorted(set(addresses))
    if not sorted_addresses:
        return []

    ranges = []
    start = previous = sorted_addresses[0]

    for address in sorted_addresses[1:]:
        if address == previous + 1:
            previous = address
            continue
        ranges.append((start, previous))
        start = previous = address

    ranges.append((start, previous))
    return ranges


def parse_intel_hex(path: Path) -> HexInfo:
    data: dict[int, int] = {}
    errors: list[str] = []
    record_counts: dict[int, int] = {}
    upper_linear = 0
    upper_segment = 0
    entry_linear = None
    entry_segment = None
    eof_seen = False

    try:
        lines = path.read_text(encoding="ascii", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        return HexInfo(False, [str(exc)], {}, [], None, None, {})

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        if not line.startswith(":"):
            errors.append(f"line {line_number}: missing ':'")
            continue

        try:
            raw = bytes.fromhex(line[1:])
        except ValueError:
            errors.append(f"line {line_number}: invalid hex")
            continue

        if len(raw) < 5:
            errors.append(f"line {line_number}: record too short")
            continue

        count = raw[0]
        if len(raw) != count + 5:
            errors.append(
                f"line {line_number}: length {len(raw)} != declared {count + 5}"
            )
            continue

        if sum(raw) & 0xFF:
            errors.append(f"line {line_number}: checksum mismatch")
            continue

        address16 = (raw[1] << 8) | raw[2]
        record_type = raw[3]
        payload = raw[4 : 4 + count]
        record_counts[record_type] = record_counts.get(record_type, 0) + 1

        if record_type == 0x00:
            absolute = (upper_linear << 16) + (upper_segment << 4) + address16
            for index, byte in enumerate(payload):
                data[absolute + index] = byte
        elif record_type == 0x01:
            eof_seen = True
        elif record_type == 0x02 and count == 2:
            upper_segment = int.from_bytes(payload, "big")
            upper_linear = 0
        elif record_type == 0x03 and count == 4:
            entry_segment = (
                int.from_bytes(payload[:2], "big"),
                int.from_bytes(payload[2:], "big"),
            )
        elif record_type == 0x04 and count == 2:
            upper_linear = int.from_bytes(payload, "big")
            upper_segment = 0
        elif record_type == 0x05 and count == 4:
            entry_linear = int.from_bytes(payload, "big")

    if lines and not eof_seen:
        errors.append("EOF record not found")

    return HexInfo(
        valid=not errors,
        errors=errors,
        data=data,
        ranges=contiguous_ranges(data),
        entry_linear=entry_linear,
        entry_segment=entry_segment,
        record_counts=record_counts,
    )


def read_c_string(data: bytes, offset: int) -> str:
    if not 0 <= offset < len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_elf32(path: Path) -> ElfInfo:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return ElfInfo(False, [str(exc)])

    errors: list[str] = []
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return ElfInfo(False, ["not an ELF file"])

    elf_class = data[4]
    data_encoding = data[5]
    if elf_class != 1:
        return ElfInfo(False, [f"unsupported ELF class {elf_class}"], elf_class=elf_class)

    if data_encoding == 1:
        endian = "<"
        endian_name = "little"
    elif data_encoding == 2:
        endian = ">"
        endian_name = "big"
    else:
        return ElfInfo(False, [f"unsupported ELF encoding {data_encoding}"], elf_class=elf_class)

    try:
        (
            _ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from(endian + "16sHHIIIIIHHHHHH", data, 0)
    except struct.error as exc:
        return ElfInfo(False, [f"ELF header parse failed: {exc}"])

    program_headers: list[dict] = []
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + 32 > len(data):
            errors.append(f"program header {index} outside file")
            break
        fields = struct.unpack_from(endian + "IIIIIIII", data, offset)
        program_headers.append(
            {
                "index": index,
                "type": fields[0],
                "offset": fields[1],
                "vaddr": fields[2],
                "paddr": fields[3],
                "filesz": fields[4],
                "memsz": fields[5],
                "flags": fields[6],
                "align": fields[7],
            }
        )

    raw_sections = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        if offset + 40 > len(data):
            errors.append(f"section header {index} outside file")
            break
        fields = struct.unpack_from(endian + "IIIIIIIIII", data, offset)
        raw_sections.append(
            {
                "index": index,
                "name_offset": fields[0],
                "type": fields[1],
                "flags": fields[2],
                "addr": fields[3],
                "offset": fields[4],
                "size": fields[5],
                "link": fields[6],
                "info": fields[7],
                "addralign": fields[8],
                "entsize": fields[9],
            }
        )

    shstr = b""
    if 0 <= e_shstrndx < len(raw_sections):
        section = raw_sections[e_shstrndx]
        start = section["offset"]
        end = start + section["size"]
        if end <= len(data):
            shstr = data[start:end]

    sections: list[dict] = []
    for section in raw_sections:
        named = dict(section)
        named["name"] = read_c_string(shstr, section["name_offset"]) if shstr else ""
        sections.append(named)

    symbols: list[dict] = []
    for section in sections:
        if section["type"] not in {2, 11} or not section["entsize"]:
            continue
        if not 0 <= section["link"] < len(sections):
            continue

        string_section = sections[section["link"]]
        string_start = string_section["offset"]
        string_end = string_start + string_section["size"]
        if string_end > len(data):
            continue
        strings = data[string_start:string_end]

        count = section["size"] // section["entsize"]
        for index in range(count):
            offset = section["offset"] + index * section["entsize"]
            if offset + 16 > len(data):
                break
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                endian + "IIIBBH", data, offset
            )
            name = read_c_string(strings, st_name)
            if not name:
                continue
            symbols.append(
                {
                    "name": name,
                    "value": st_value,
                    "size": st_size,
                    "info": st_info,
                    "other": st_other,
                    "section_index": st_shndx,
                }
            )

    return ElfInfo(
        valid=not errors,
        errors=errors,
        elf_class=elf_class,
        endian=endian_name,
        machine=e_machine,
        entry=e_entry,
        program_headers=program_headers,
        sections=sections,
        symbols=symbols,
    )


def normalized_asm(text: str) -> str:
    lines = []
    for line in text.splitlines():
        line = re.sub(r"\s+", " ", line.strip())
        if line:
            lines.append(line)
    return "\n".join(lines)


def parse_uvproj(path: Path) -> dict:
    result = {
        "valid": False,
        "error": None,
        "selected_tags": [],
        "files": [],
    }

    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        result["error"] = str(exc)
        return result

    result["valid"] = True

    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        text = (element.text or "").strip()

        if tag in PROJECT_TAGS and text:
            result["selected_tags"].append((tag, text))

        if tag in {"FileName", "FilePath", "FileType"} and text:
            result["files"].append((tag, text))

    return result


def parse_config(path: Path) -> dict:
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error) as exc:
        return {"valid": False, "error": str(exc), "sections": {}}

    sections = {
        section: dict(parser.items(section))
        for section in parser.sections()
    }
    return {"valid": True, "error": None, "sections": sections}


def decode_boot_ram_header(path: Path) -> dict:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"valid": False, "error": str(exc)}

    if len(data) < 0x20:
        return {"valid": False, "error": f"file too short: {len(data)}"}

    return {
        "valid": True,
        "error": None,
        "bx_flag_ascii": data[0:4].decode("ascii", errors="replace"),
        "bx_flag_hex": data[0:4].hex(),
        "base_addr": u32(data, 0x04),
        "length": u32(data, 0x08),
        "entry_point": u32(data, 0x0C),
        "ota_base": u32(data, 0x10),
        "data_base": u32(data, 0x14),
        "total_size_64k": u16(data, 0x18),
        "multi_read_param": u16(data, 0x1A),
        "quad_enable_config": u32(data, 0x1C),
        "file_size": len(data),
    }


def plausible_vector_tables(payload: bytes) -> list[dict]:
    candidates = []
    for offset in range(0, len(payload) - 35 * 4, 4):
        stack = u32(payload, offset)
        reset = u32(payload, offset + 4)
        if stack is None or reset is None:
            continue

        stack_ok = 0x00200000 <= stack < 0x00220000 and stack % 4 == 0
        reset_ok = (
            reset & 1
            and RUNTIME_BASE <= (reset & ~1) < RUNTIME_BASE + len(payload)
        )
        if not stack_ok or not reset_ok:
            continue

        words = [u32(payload, offset + index * 4) or 0 for index in range(35)]
        handler_like = 0
        zero_like = 0
        invalid = 0

        for word in words[2:]:
            if word == 0:
                zero_like += 1
            elif (
                word & 1
                and RUNTIME_BASE <= (word & ~1) < RUNTIME_BASE + len(payload)
            ):
                handler_like += 1
            else:
                invalid += 1

        score = handler_like * 3 + zero_like - invalid * 2
        candidates.append(
            {
                "payload_offset": offset,
                "runtime": RUNTIME_BASE + offset,
                "stack": stack,
                "reset": reset,
                "handler_like": handler_like,
                "zero_like": zero_like,
                "invalid": invalid,
                "score": score,
            }
        )

    candidates.sort(key=lambda item: (item["score"], item["handler_like"]), reverse=True)
    return candidates[:20]


def print_artifact_comparison(sdkm: Path, sdk3: Path) -> dict[str, dict[str, Artifact]]:
    print("=" * 116)
    print("ARTIFACT COMPARISON")

    result: dict[str, dict[str, Artifact]] = {}

    for relative in ARTIFACTS:
        left = collect_artifact("SDKm", sdkm, relative)
        right = collect_artifact("SDK3", sdk3, relative)
        result[relative] = {"SDKm": left, "SDK3": right}

        print()
        print(relative)
        for artifact in (left, right):
            if not artifact.exists:
                print(f"  {artifact.root_name}: MISSING")
            else:
                print(
                    f"  {artifact.root_name}: size=0x{artifact.size:X} "
                    f"({artifact.size}) sha256={artifact.sha256}"
                )

        if left.exists and right.exists:
            print(
                "  byte comparison: "
                + ("IDENTICAL" if left.sha256 == right.sha256 else "DIFFERENT")
            )

    print()
    return result


def print_hex_analysis(label: str, path: Path) -> None:
    print("=" * 116)
    print(f"INTEL HEX: {label}")
    print(f"path: {path}")

    if not path.is_file():
        print("status: MISSING")
        print()
        return

    info = parse_intel_hex(path)
    print(f"valid: {info.valid}")
    print(f"errors: {len(info.errors)}")
    for error in info.errors[:20]:
        print(f"  {error}")
    print(f"data bytes: 0x{len(info.data):X} ({len(info.data)})")
    print(f"ranges: {len(info.ranges)}")
    for start, end in info.ranges[:100]:
        print(f"  0x{start:08X}..0x{end:08X} size=0x{end - start + 1:X}")
    print(f"entry linear: {None if info.entry_linear is None else f'0x{info.entry_linear:08X}'}")
    print(f"entry segment: {info.entry_segment}")
    print(
        "record counts: "
        + ", ".join(
            f"0x{record_type:02X}={count}"
            for record_type, count in sorted(info.record_counts.items())
        )
    )
    print()


def print_elf_analysis(label: str, path: Path) -> None:
    print("=" * 116)
    print(f"ELF: {label}")
    print(f"path: {path}")

    if not path.is_file():
        print("status: MISSING")
        print()
        return

    info = parse_elf32(path)
    print(f"valid: {info.valid}")
    print(f"errors: {len(info.errors)}")
    for error in info.errors:
        print(f"  {error}")
    print(f"class: {info.elf_class}")
    print(f"endian: {info.endian}")
    print(f"machine: {info.machine}")
    print(f"entry: {None if info.entry is None else f'0x{info.entry:08X}'}")

    print("program headers:")
    for ph in info.program_headers or []:
        print(
            f"  [{ph['index']}] type={ph['type']} "
            f"off=0x{ph['offset']:X} vaddr=0x{ph['vaddr']:08X} "
            f"paddr=0x{ph['paddr']:08X} filesz=0x{ph['filesz']:X} "
            f"memsz=0x{ph['memsz']:X} flags=0x{ph['flags']:X} "
            f"align=0x{ph['align']:X}"
        )

    print("allocated/nonempty sections:")
    for section in info.sections or []:
        if not section["size"]:
            continue
        print(
            f"  [{section['index']}] {section['name']!r} "
            f"type={section['type']} flags=0x{section['flags']:X} "
            f"addr=0x{section['addr']:08X} off=0x{section['offset']:X} "
            f"size=0x{section['size']:X}"
        )

    high_value = {
        "boot_ram_head",
        "flash_program",
        "flash_erase",
        "flash_program_operation",
        "flash_erase_operation",
        "main",
        "Reset_Handler",
        "__Vectors",
    }

    symbols = [
        symbol
        for symbol in info.symbols or []
        if symbol["name"] in high_value
        or "boot_ram_head" in symbol["name"]
        or symbol["name"].startswith("flash_")
    ]

    print(f"selected symbols: {len(symbols)}")
    for symbol in sorted(symbols, key=lambda item: (item["value"], item["name"]))[:300]:
        print(
            f"  0x{symbol['value']:08X} size=0x{symbol['size']:X} "
            f"{symbol['name']}"
        )
    print()


def print_boot_ram_header(label: str, path: Path) -> dict:
    print("=" * 116)
    print(f"BOOT_RAM HEADER: {label}")
    print(f"path: {path}")

    info = decode_boot_ram_header(path)
    if not info["valid"]:
        print(f"status: {info['error']}")
        print()
        return info

    print(f"file size: 0x{info['file_size']:X}")
    print(f"bx_flag ASCII: {info['bx_flag_ascii']!r}")
    print(f"bx_flag hex: {info['bx_flag_hex']}")
    print(f"base_addr: 0x{info['base_addr']:08X}")
    print(f"length: 0x{info['length']:X}")
    print(f"entry_point: 0x{info['entry_point']:08X}")
    print(f"ota_base: 0x{info['ota_base']:X}")
    print(f"data_base: 0x{info['data_base']:X}")
    print(f"total_size_64k: 0x{info['total_size_64k']:X}")
    print(f"multi_read_param: 0x{info['multi_read_param']:04X}")
    print(f"quad_enable_config: 0x{info['quad_enable_config']:08X}")
    print()
    return info


def print_config(label: str, path: Path) -> dict:
    print("=" * 116)
    print(f"IMAGE CONFIG: {label}")
    print(f"path: {path}")

    info = parse_config(path)
    print(f"valid: {info['valid']}")
    if info["error"]:
        print(f"error: {info['error']}")
    for section, values in info["sections"].items():
        print(f"[{section}]")
        for key, value in values.items():
            print(f"  {key} = {value}")
    print()
    return info


def print_project(label: str, path: Path) -> None:
    print("=" * 116)
    print(f"KEIL PROJECT: {label}")
    print(f"path: {path}")

    if not path.is_file():
        print("status: MISSING")
        print()
        return

    info = parse_uvproj(path)
    print(f"valid: {info['valid']}")
    if info["error"]:
        print(f"error: {info['error']}")

    print("selected settings:")
    for tag, value in info["selected_tags"]:
        print(f"  {tag}: {value}")

    print("project file entries:")
    current = {}
    for tag, value in info["files"]:
        if tag == "FileName" and current:
            print("  " + json.dumps(current, sort_keys=True))
            current = {}
        current[tag] = value
    if current:
        print("  " + json.dumps(current, sort_keys=True))
    print()


def print_startup_comparison(sdkm: Path) -> None:
    print("=" * 116)
    print("SDKm STARTUP COMPARISON")

    paths = [sdkm / relative for relative in STARTUP_CANDIDATES]
    texts = []

    for relative, path in zip(STARTUP_CANDIDATES, paths):
        print()
        print(relative)
        if not path.is_file():
            print("  MISSING")
            texts.append(None)
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        texts.append(text)
        stack = re.search(r"Stack_Size\s+EQU\s+(0x[0-9A-Fa-f]+)", text)
        heap = re.search(r"Heap_Size\s+EQU\s+(0x[0-9A-Fa-f]+)", text)
        vectors = re.search(r"^__Vectors\s+(.*?)^__Vectors_End", text, re.M | re.S)
        vector_count = (
            sum(1 for line in vectors.group(0).splitlines() if re.search(r"\bDCD\b", line))
            if vectors
            else 0
        )
        print(f"  size: {path.stat().st_size}")
        print(f"  sha256: {sha256_file(path)}")
        print(f"  stack: {stack.group(1) if stack else 'unresolved'}")
        print(f"  heap: {heap.group(1) if heap else 'unresolved'}")
        print(f"  vector words: {vector_count}")
        print(f"  xip_section present: {'|xip_section|' in text}")
        print(
            "  Reset_Handler -> __main: "
            + str(bool(re.search(r"IMPORT\s+__main.*?BX\s+R4", text, re.S)))
        )

    if all(text is not None for text in texts):
        raw_identical = texts[0] == texts[1]
        normalized_identical = normalized_asm(texts[0]) == normalized_asm(texts[1])
        print()
        print(f"raw identical: {raw_identical}")
        print(f"whitespace-normalized identical: {normalized_identical}")
    print()


def print_firmware_analysis(path: Path) -> dict:
    print("=" * 116)
    print("RY02 STOCK FIRMWARE ALIGNMENT")
    print(f"path: {path}")

    if not path.is_file():
        print("status: MISSING")
        print()
        return {"valid": False}

    container = path.read_bytes()
    payload = container[OUTER_HEADER_SIZE:] if len(container) > OUTER_HEADER_SIZE else b""
    sha = hashlib.sha256(container).hexdigest()
    outer_magic = u32(container, 0)
    inner_magic = u32(payload, 0) if payload else None

    print(f"sha256: {sha}")
    print(f"expected SHA match: {sha == EXPECTED_FW38_SHA256}")
    print(f"container length: 0x{len(container):X}")
    print(f"expected container length: {len(container) == EXPECTED_FW38_CONTAINER}")
    print(f"payload length: 0x{len(payload):X}")
    print(f"expected payload length: {len(payload) == EXPECTED_FW38_PAYLOAD}")
    print(f"outer magic: {None if outer_magic is None else f'0x{outer_magic:08X}'}")
    print(f"outer magic match: {outer_magic == EXPECTED_OUTER_MAGIC}")
    print(f"inner magic: {None if inner_magic is None else f'0x{inner_magic:08X}'}")
    print(f"inner magic match: {inner_magic == EXPECTED_INNER_MAGIC}")
    print(f"accepted inner code offset: 0x{INNER_CODE_OFFSET:X}")
    print(f"accepted inner code runtime: 0x{INNER_CODE_RUNTIME:08X}")
    print(f"accepted app physical base: 0x{ACCEPTED_R02_APP_PHYSICAL:X}")
    print(f"accepted OTA physical base: 0x{ACCEPTED_R02_OTA_PHYSICAL:X}")
    print(f"accepted config physical base: 0x{ACCEPTED_R02_CFG_PHYSICAL:X}")

    candidates = plausible_vector_tables(payload)
    print(f"plausible vector-table candidates: {len(candidates)}")
    for candidate in candidates:
        print(
            f"  payload+0x{candidate['payload_offset']:05X} "
            f"runtime=0x{candidate['runtime']:08X} "
            f"stack=0x{candidate['stack']:08X} "
            f"reset=0x{candidate['reset']:08X} "
            f"handlers={candidate['handler_like']} "
            f"zero={candidate['zero_like']} invalid={candidate['invalid']} "
            f"score={candidate['score']}"
        )

    body = payload[INNER_CODE_OFFSET:] if len(payload) > INNER_CODE_OFFSET else b""
    print(f"body bytes after inner header: 0x{len(body):X}")
    print()
    return {
        "valid": True,
        "sha256": sha,
        "payload": payload,
        "vector_candidates": candidates,
    }


def config_int(config: dict, section: str, key: str) -> int | None:
    try:
        return int(config["sections"][section][key], 0)
    except (KeyError, TypeError, ValueError):
        return None


def print_layout_matrix(
    sdkm_config: dict,
    sdk3_config: dict,
    sdkm_header: dict,
    sdk3_header: dict,
) -> None:
    print("=" * 116)
    print("GENERIC SDK VS R02 LAYOUT MATRIX")

    sdkm_ota = config_int(sdkm_config, "App", "ota_base")
    sdkm_data = config_int(sdkm_config, "App", "data_base")
    sdkm_total = config_int(sdkm_config, "Flash", "total_size")

    sdk3_ota = config_int(sdk3_config, "App", "ota_base")
    sdk3_data = config_int(sdk3_config, "App", "data_base")
    sdk3_total = config_int(sdk3_config, "Flash", "total_size")

    def fmt(value: int | None) -> str:
        return "unresolved" if value is None else f"0x{value:X}"

    print(f"SDKm config ota_base: {fmt(sdkm_ota)}")
    print(f"SDK3 config ota_base: {fmt(sdk3_ota)}")
    print(f"accepted R02 OTA physical base: 0x{ACCEPTED_R02_OTA_PHYSICAL:X}")
    print()
    print(f"SDKm config data_base: {fmt(sdkm_data)}")
    print(f"SDK3 config data_base: {fmt(sdk3_data)}")
    print()
    print(f"SDKm config total_size: {fmt(sdkm_total)}")
    print(f"SDK3 config total_size: {fmt(sdk3_total)}")
    print()
    print(f"accepted R02 app physical base: 0x{ACCEPTED_R02_APP_PHYSICAL:X}")
    print(f"accepted R02 config physical base: 0x{ACCEPTED_R02_CFG_PHYSICAL:X}")

    if sdkm_ota is not None:
        print(
            "SDKm ota_base equals accepted R02 OTA base: "
            f"{sdkm_ota == ACCEPTED_R02_OTA_PHYSICAL}"
        )
    if sdk3_ota is not None:
        print(
            "SDK3 ota_base equals accepted R02 OTA base: "
            f"{sdk3_ota == ACCEPTED_R02_OTA_PHYSICAL}"
        )

    for label, header in (("SDKm", sdkm_header), ("SDK3", sdk3_header)):
        if not header.get("valid"):
            continue
        print()
        print(f"{label} boot_ram header versus config:")
        print(
            f"  ota_base header/config: "
            f"0x{header['ota_base']:X} / {fmt(sdkm_ota if label == 'SDKm' else sdk3_ota)}"
        )
        print(
            f"  data_base header/config: "
            f"0x{header['data_base']:X} / {fmt(sdkm_data if label == 'SDKm' else sdk3_data)}"
        )

    print()
    print("interpretation:")
    print("  generic SDK image-tool values are reference defaults")
    print("  they are not the accepted R02 partition map")
    print("  no generated image is safe to install based on this comparison alone")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze BlueX SDKm/SDK3 image-tool, boot, startup, Keil project, "
            "ELF/HEX, and accepted RY02 layout contracts."
        )
    )
    parser.add_argument("--sdkm", type=Path, default=DEFAULT_SDKM)
    parser.add_argument("--sdk3", type=Path, default=DEFAULT_SDK3)
    parser.add_argument("--firmware38", type=Path, default=DEFAULT_FW38)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    print("RY02 BLUEX SDK BUILD-CONTRACT REPORT")
    print(f"tool revision: {TOOL_REVISION}")
    print(f"Python: {platform.python_version()}")
    print(f"SDKm: {args.sdkm}")
    print(f"SDK3: {args.sdk3}")
    print(f"firmware38: {args.firmware38}")
    print()
    print("Interpretation boundary:")
    print("  this is an offline build/image comparison")
    print("  it does not establish bootloader acceptance")
    print("  it does not authorize flashing a generated image")
    print()

    print_artifact_comparison(args.sdkm, args.sdk3)

    for root_label, root in (("SDKm", args.sdkm), ("SDK3", args.sdk3)):
        print_hex_analysis(
            f"{root_label} bootloader.hex",
            root / "tools/bluex/bootloader/bootloader.hex",
        )
        print_hex_analysis(
            f"{root_label} boot_ram.hex",
            root / "tools/bluex/image_tool_v2/boot_ram.hex",
        )
        print_elf_analysis(
            f"{root_label} boot_ram.elf",
            root / "tools/bluex/image_tool_v2/boot_ram.elf",
        )

    sdkm_header = print_boot_ram_header(
        "SDKm",
        args.sdkm / "tools/bluex/image_tool_v2/boot_ram.bin",
    )
    sdk3_header = print_boot_ram_header(
        "SDK3",
        args.sdk3 / "tools/bluex/image_tool_v2/boot_ram.bin",
    )

    sdkm_config = print_config(
        "SDKm",
        args.sdkm / "tools/bluex/image_tool_v2/config.ini",
    )
    sdk3_config = print_config(
        "SDK3",
        args.sdk3 / "tools/bluex/image_tool_v2/config.ini",
    )

    for relative in PROJECT_CANDIDATES:
        print_project("SDKm", args.sdkm / relative)
        print_project("SDK3", args.sdk3 / relative)

    print_startup_comparison(args.sdkm)
    print_firmware_analysis(args.firmware38)
    print_layout_matrix(sdkm_config, sdk3_config, sdkm_header, sdk3_header)

    print("=" * 116)
    print("SUMMARY")
    print("completed artifact, HEX, ELF, header, config, project, startup, and R02 checks")
    print("next decision: build-only prototype after the report is reviewed")
    print("device action: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
