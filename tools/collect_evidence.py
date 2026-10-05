#!/usr/bin/env python3
"""Collect stock metadata and readable module ELF sections. No device writes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import uuid
import zipfile


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def elf_sections(data):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected ELF64 little-endian module")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 183:
        raise ValueError(f"Expected ARM64 ELF, found machine={machine}")
    table = struct.unpack_from("<Q", data, 40)[0]
    stride, count, names_index = struct.unpack_from("<HHH", data, 58)
    if stride != 64 or table + 64 > len(data):
        raise ValueError("Invalid ELF section table")
    zero = struct.unpack_from("<IIQQQQIIQQ", data, table)
    if count == 0:
        count = zero[5]
    if names_index == 0xffff:
        names_index = zero[6]
    if not count or names_index >= count or table + count * stride > len(data):
        raise ValueError("ELF section table out of bounds")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, table + i * stride)
               for i in range(count)]
    ns = headers[names_index]
    if ns[4] + ns[5] > len(data):
        raise ValueError("ELF section-name table out of bounds")
    names = data[ns[4]:ns[4]+ns[5]]
    result = []
    for index, section in enumerate(headers):
        name_at, kind, flags, address, offset, size, link, info, align, entry_size = section
        if name_at >= len(names):
            raise ValueError("ELF section name out of bounds")
        name_end = names.find(b"\0", name_at)
        if name_end < 0:
            raise ValueError("Unterminated ELF section name")
        name = names[name_at:name_end].decode("ascii")
        if kind != 8 and offset + size > len(data):
            raise ValueError(f"ELF section out of bounds: {name}")
        result.append({"index": index, "name": name, "type": kind, "offset": offset,
                       "size": size, "link": link, "info": info, "entry_size": entry_size,
                       "flags": flags, "address": address, "alignment": align})
    return result


def module_metadata(path, root, dest):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    sections = elf_sections(data)
    directory = dest / digest
    directory.mkdir(exist_ok=True)
    exported = []
    for section in sections:
        name = section["name"]
        keep = (name in {".modinfo", "__versions", "__version_ext_names", "__version_ext_crcs",
                         ".symtab", ".strtab", "__ksymtab_strings"}
                or "ksymtab" in name or "kcrctab" in name)
        if not keep or section["type"] == 8:
            continue
        payload = data[section["offset"]:section["offset"]+section["size"]]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        filename = f"{section['index']:05d}_{safe}.bin"
        (directory / filename).write_bytes(payload)
        exported.append({**section, "file": f"modules/{digest}/{filename}",
                         "sha256": hashlib.sha256(payload).hexdigest()})
    info = next((s for s in sections if s["name"] == ".modinfo"), None)
    modinfo = [] if info is None else data[info["offset"]:info["offset"]+info["size"]].decode(errors="replace").split("\0")
    return {"path": path.relative_to(root).as_posix(), "size": len(data), "sha256": digest,
            "modinfo": [v for v in modinfo if v], "all_sections": sections, "exported_sections": exported}


def image_metadata(path, dest):
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size < 4096:
        raise ValueError(f"Image too small: {path.name}")
    directory = dest / path.stem
    directory.mkdir()
    record = {"file": path.name, "size": size, "sha256": sha256(path)}
    with path.open("rb") as stream:
        header = stream.read(4096)
        (directory / "header.bin").write_bytes(header)
        stream.seek(-64, 2)
        footer = stream.read(64)
        (directory / "footer.bin").write_bytes(footer)
        if footer[:4] == b"AVBf":
            magic, major, minor, original, offset, length, reserved = struct.unpack("!4sIIQQQ28s", footer)
            if length == 0 or length > 4*1024*1024 or offset + length > size - 64 or original > offset:
                raise ValueError(f"Invalid AVB footer bounds: {path.name}")
            stream.seek(offset)
            vbmeta = stream.read(length)
            if len(vbmeta) != length or vbmeta[:4] != b"AVB0":
                raise ValueError(f"Invalid embedded vbmeta: {path.name}")
            (directory / "embedded_vbmeta.img").write_bytes(vbmeta)
            record["avb_footer"] = {"major": major, "minor": minor, "original_size": original,
                                    "vbmeta_offset": offset, "vbmeta_size": length}
        else:
            record["avb_footer"] = None
        if header[:4] == b"AVB0":
            if size > 4*1024*1024:
                raise ValueError("Unexpectedly large standalone vbmeta")
            stream.seek(0)
            (directory / "vbmeta.img").write_bytes(stream.read())
    return record


def adb(adb_path, serial, *args, required=True):
    command = [str(adb_path)] + (["-s", serial] if serial else []) + list(args)
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=300, text=True, encoding="utf-8", errors="replace")
    if required and result.returncode:
        raise RuntimeError(f"ADB {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def collect(args):
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer required")
    root = Path(args.stock_root)
    adb_path = Path(args.adb)
    work = Path(args.output_root) / f"evidence_{uuid.uuid4().hex[:12]}"
    work.mkdir(parents=True, exist_ok=False)
    payload = work / "payload"
    payload.mkdir()
    metadata = {"scope": "read-only metadata; not a full ABI or recovery pass", "images": [], "modules": []}
    devices = adb(adb_path, None, "devices").stdout.splitlines()
    ready = [line.split()[0] for line in devices if re.fullmatch(r"\S+\s+device\s*", line)]
    if len(ready) != 1:
        raise RuntimeError("Connect exactly one authorized ADB device")
    serial = ready[0]
    properties = {}
    for prop in ("ro.product.model", "ro.product.device", "ro.build.display.id", "ro.build.fingerprint", "ro.boot.slot_suffix"):
        properties[prop] = adb(adb_path, serial, "shell", "getprop", prop).stdout.strip()
    if properties["ro.product.model"] != "NP03J" or properties["ro.build.display.id"] != "REDMAGICOS11.0.6_NP03J_EU" or properties["ro.boot.slot_suffix"] != "_a":
        raise RuntimeError("Target model/firmware/slot changed")
    metadata["device_properties"] = properties
    image_dest = payload / "images"
    image_dest.mkdir()
    for name in ("boot_a.img", "init_boot_a.img", "vendor_boot_a.img", "recovery_a.img", "dtbo_a.img", "vbmeta_a.img", "vbmeta_system_a.img"):
        print(f"IMAGE {name}", flush=True)
        metadata["images"].append(image_metadata(root / "01_BOOTCHAIN" / name, image_dest))
    restore = root / "05_RESTORE" / "RESTORE.ps1"
    if not restore.is_file():
        raise FileNotFoundError(restore)
    shutil.copyfile(restore, payload / "RESTORE.ps1")
    metadata["restore_sha256"] = sha256(restore)
    metadata["resource_inventory"] = [{"path": p.relative_to(root).as_posix(), "size": p.stat().st_size}
        for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".img", ".json", ".txt", ".csv", ".md", ".ps1"}]
    modules_raw = work / "vendor_modules_raw"
    print("PULL readable vendor module directory", flush=True)
    pull = adb(adb_path, serial, "pull", "/vendor_dlkm/lib/modules", str(modules_raw), required=False)
    metadata["vendor_pull"] = {"exit_code": pull.returncode, "stdout": pull.stdout, "stderr": pull.stderr}
    module_dest = payload / "modules"
    module_dest.mkdir()
    if modules_raw.is_dir():
        for path in sorted(modules_raw.rglob("*.ko")):
            metadata["modules"].append(module_metadata(path, modules_raw, module_dest))
        for path in modules_raw.rglob("modules.*"):
            if path.is_file() and path.stat().st_size < 4*1024*1024:
                target = payload / "module_lists" / path.relative_to(modules_raw)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    metadata["unparsed_compressed_modules"] = [p.relative_to(modules_raw).as_posix()
        for p in modules_raw.rglob("*") if p.is_file() and any(
            p.name.endswith(suffix) for suffix in (".ko.xz", ".ko.gz", ".ko.zst"))] if modules_raw.is_dir() else []
    metadata["system_modules"] = "Not collected: shell access previously denied; offline super extraction needed"
    metadata["vendor_modules_complete"] = (pull.returncode == 0 and bool(metadata["modules"])
                                           and not metadata["unparsed_compressed_modules"])
    (payload / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    archive = work / "NP03J_EVIDENCE.zip"
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as zip_file:
        for path in sorted(payload.rglob("*")):
            if path.is_file():
                zip_file.write(path, path.relative_to(payload))
    print(f"VENDOR_MODULE_COUNT={len(metadata['modules'])}")
    print(f"VENDOR_MODULE_COLLECTION_COMPLETE={metadata['vendor_modules_complete']}")
    print(f"ZIP={archive}")
    print(f"ZIP_BYTES={archive.stat().st_size}")
    print(f"ZIP_SHA256={sha256(archive)}")
    if archive.stat().st_size > 32*1024*1024:
        raise RuntimeError("Evidence ZIP exceeds 32 MiB; keep files and report size before uploading")
    print("EVIDENCE_COLLECTION_COMPLETE; NO DEVICE WRITES")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-root", required=True)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--output-root", required=True)
    try:
        collect(parser.parse_args())
    except Exception as error:
        print(f"STOP: {error}", file=sys.stderr)
        sys.exit(1)
