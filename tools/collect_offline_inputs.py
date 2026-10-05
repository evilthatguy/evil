#!/usr/bin/env python3
"""Copy small, read-only stock inputs needed for offline module extraction."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid
import zipfile


def collect(stock, output):
    work = output / ("offline_inputs_" + uuid.uuid4().hex[:12])
    work.mkdir(parents=True, exist_ok=False)
    vendor = stock / "01_BOOTCHAIN" / "vendor_boot_a.img"
    super_image = stock / "03_SUPER" / "super.img"
    metadata = {"scope": "small stock inputs only; super payload integrity not checked", "files": {}}
    files = {}
    with vendor.open("rb") as stream:
        header = stream.read(4096)
        if len(header) != 4096 or header[:8] != b"VNDRBOOT":
            raise ValueError("Invalid vendor_boot header")
        version, page = struct.unpack_from("<II", header, 8)
        size = struct.unpack_from("<I", header, 24)[0]
        header_size = struct.unpack_from("<I", header, 2096)[0]
        if version != 4 or page != 4096 or header_size != 2128 or size != 8733415:
            raise ValueError("Stock vendor_boot parameters changed")
        offset = ((header_size + page - 1) // page) * page
        stream.seek(offset)
        ramdisk = stream.read(size)
        if len(ramdisk) != size:
            raise ValueError("Truncated vendor ramdisk")
        stream.seek(0)
        full_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        if full_hash != "2b7f9d700306e25d73324f843530d6e1f77678acea5c739e85fd77fa87e2b021":
            raise ValueError("vendor_boot stock SHA256 changed")
    files["vendor_ramdisk.bin"] = ramdisk
    metadata["vendor_boot_sha256"] = full_hash
    with super_image.open("rb") as stream:
        prefix = stream.read(1024*1024)
    if super_image.stat().st_size != 12884901888 or len(prefix) != 1024*1024:
        raise ValueError("Stock super size changed")
    if prefix[:4] == bytes.fromhex("3aff26ed"):
        raise ValueError("Sparse super is unsupported by this raw-metadata collection")
    files["super_first_1MiB.bin"] = prefix
    metadata["super_size"] = super_image.stat().st_size
    metadata["super_full_sha256"] = "NOT_RECOMPUTED; prefix hash does not authenticate all payloads"
    for relative in ("00_INFO/BUILD_INFO.txt", "00_INFO/UPDATE_PATH.txt", "04_HASHES/SHA256SUMS_MASTER.txt", "05_RESTORE/README.md"):
        path = stock / relative
        if path.is_file():
            if path.stat().st_size > 1024*1024:
                raise ValueError("Unexpectedly large stock text input")
            files[relative] = path.read_bytes()
    for name, data in files.items():
        metadata["files"][name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    archive = work / "NP03J_OFFLINE_INPUTS.zip"
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as zipped:
        for name, data in files.items():
            zipped.writestr(name, data)
        zipped.writestr("metadata.json", json.dumps(metadata, indent=2) + "\n")
    print("ZIP=" + str(archive))
    print("ZIP_BYTES=" + str(archive.stat().st_size))
    with archive.open("rb") as stream:
        print("ZIP_SHA256=" + hashlib.file_digest(stream, "sha256").hexdigest())
    print("OFFLINE_INPUTS_COMPLETE; NO DEVICE ACCESS OR WRITES")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-root", required=True)
    parser.add_argument("--output-root", required=True)
    try:
        args = parser.parse_args()
        if sys.version_info < (3, 11):
            raise ValueError("Python 3.11 or newer required")
        collect(Path(args.stock_root), Path(args.output_root))
    except Exception as error:
        print(f"STOP: {error}", file=sys.stderr)
        sys.exit(1)
