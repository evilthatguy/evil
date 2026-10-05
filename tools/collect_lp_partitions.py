#!/usr/bin/env python3
"""Read selected linear logical partitions from a hash-pinned raw LP image."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import uuid
import zipfile


def checked_geometry(prefix, offset):
    data = bytearray(prefix[offset:offset+52])
    if len(data) != 52 or struct.unpack_from("<II", data) != (0x616c4467, 52):
        raise ValueError("Unsupported LP geometry")
    checksum = bytes(data[8:40])
    data[8:40] = bytes(32)
    if hashlib.sha256(data).digest() != checksum:
        raise ValueError("LP geometry checksum mismatch")
    maximum, slots, block = struct.unpack_from("<III", data, 40)
    if maximum < 512 or maximum % 512 or not 1 <= slots <= 16 or block < 512 or block % 512:
        raise ValueError("Invalid LP geometry dimensions")
    return maximum, slots, block


def checked_metadata(prefix, offset, maximum):
    if offset+128 > len(prefix):
        raise ValueError("LP metadata outside collected prefix")
    magic, major, minor, size = struct.unpack_from("<IHHI", prefix, offset)
    if magic != 0x414c5030 or major != 10 or minor > 2 or size != (256 if minor == 2 else 128):
        raise ValueError("Unsupported LP metadata header")
    table_size = struct.unpack_from("<I", prefix, offset+44)[0]
    if size+table_size > maximum or offset+size+table_size > len(prefix):
        raise ValueError("LP metadata bounds invalid")
    header = bytearray(prefix[offset:offset+size])
    checksum = bytes(header[12:44]); header[12:44] = bytes(32)
    if hashlib.sha256(header).digest() != checksum:
        raise ValueError("LP header checksum mismatch")
    tables = prefix[offset+size:offset+size+table_size]
    if hashlib.sha256(tables).digest() != header[48:80]:
        raise ValueError("LP table checksum mismatch")
    entries = []
    intervals = []
    for number, expected_stride in enumerate((52, 24, 48, 64)):
        start, count, stride = struct.unpack_from("<III", header, 80+12*number)
        end = start + count*stride
        if stride != expected_stride or end > len(tables):
            raise ValueError("LP table descriptor invalid")
        entries.append([tables[start+i*stride:start+(i+1)*stride] for i in range(count)])
        if count:
            intervals.append((start, end))
    intervals.sort()
    if any(a[1] > b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError("Overlapping LP tables")
    return prefix[offset:offset+size+table_size], entries


def partition_maps(prefix, source_size, slot, names):
    geometry = checked_geometry(prefix, 4096)
    if geometry != checked_geometry(prefix, 8192):
        raise ValueError("LP geometry copies disagree")
    maximum, slots, _ = geometry
    if slot < 0 or slot >= slots:
        raise ValueError("Metadata slot outside geometry")
    primary, entries = checked_metadata(prefix, 12288+slot*maximum, maximum)
    backup, _ = checked_metadata(prefix, 12288+(slots+slot)*maximum, maximum)
    if primary != backup:
        raise ValueError("Selected primary and backup metadata disagree")
    partitions, extents, groups, devices = entries
    if len(devices) != 1:
        raise ValueError("Only a single raw backing image is supported")
    first, alignment, alignment_offset, size, device_name, flags = struct.unpack("<QIIQ36sI", devices[0])
    if size != source_size or flags or first*512 < 12288+2*slots*maximum:
        raise ValueError("Backing device does not match the raw image")
    mapping = {}
    for data in partitions:
        raw_name, attributes, begin, count, group = struct.unpack("<36sIIII", data)
        name = raw_name.split(b"\0", 1)[0].decode("ascii")
        if name not in names:
            continue
        if name in mapping or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("Duplicate or unsafe requested partition name")
        if attributes & (2|8) or not count or begin+count > len(extents) or group >= len(groups):
            raise ValueError("Unsupported selected partition attributes or bounds")
        selected = []
        for extent in extents[begin:begin+count]:
            sectors, kind, start, backing = struct.unpack("<QIQI", extent)
            if kind != 0 or backing != 0 or not sectors or start < first or (start+sectors)*512 > size:
                raise ValueError("Only valid linear extents on this image are supported")
            selected.append((start, sectors))
        mapping[name] = selected
    if set(mapping) != set(names):
        raise ValueError("Requested partitions missing from selected metadata slot")
    return mapping


def copy_extents(source, target, extents, source_size):
    if not extents:
        raise ValueError("No extents supplied")
    for sector, count in extents:
        if sector < 0 or count <= 0 or (sector+count)*512 > source_size:
            raise ValueError("Extent outside source image")
    digest = hashlib.sha256(); size = 0
    for sector, count in extents:
        source.seek(sector*512)
        remaining = count*512
        while remaining:
            block = source.read(min(1024*1024, remaining))
            if not block:
                raise ValueError("Truncated source extent")
            target.write(block); digest.update(block); size += len(block); remaining -= len(block)
    return {"size": size, "sha256": digest.hexdigest(), "extents": extents}


def report_archive(archive):
    parts = [archive]
    if archive.stat().st_size > 32*1024*1024:
        parts = []
        with archive.open("rb") as stream:
            number = 1
            while block := stream.read(24*1024*1024):
                part = archive.with_name(archive.name + f".part{number:03d}")
                with part.open("xb") as target:
                    target.write(block)
                parts.append(part); number += 1
        print("SPLIT_ARCHIVE=" + str(archive) + "; upload every listed part")
    for part in parts:
        print("UPLOAD=" + str(part)); print("BYTES=" + str(part.stat().st_size))
        with part.open("rb") as stream:
            print("SHA256=" + hashlib.file_digest(stream, "sha256").hexdigest())


def collect(args):
    source_path = Path(args.image); before = source_path.stat()
    work = Path(args.output_root) / ("lp_inputs_" + uuid.uuid4().hex[:12])
    work.mkdir(parents=True, exist_ok=False)
    with source_path.open("rb") as source:
        prefix = source.read(1024*1024)
        if hashlib.sha256(prefix).hexdigest() != args.prefix_sha256:
            raise ValueError("Audited image prefix changed")
        mapping = partition_maps(prefix, before.st_size, args.slot, args.partitions)
        print("VERIFY_FULL_IMAGE_SHA256; please wait", flush=True); source.seek(0)
        actual = hashlib.file_digest(source, "sha256").hexdigest()
        if actual != args.sha256:
            raise ValueError("Complete image SHA256 differs from the supplied pin")
        print("SOURCE_SHA256=" + actual, flush=True)
        archives = []
        for name, extents in mapping.items():
            archive = work / (name + ".zip")
            with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as zipped:
                with zipped.open(name + ".img", "w", force_zip64=True) as target:
                    record = copy_extents(source, target, extents, before.st_size)
                metadata = {"scope": "offline partition input; not a compatibility pass",
                            "source_sha256": actual, "source_prefix_sha256": args.prefix_sha256,
                            "metadata_slot": args.slot, "name": name, **record}
                zipped.writestr("metadata.json", json.dumps(metadata, indent=2) + "\n")
            print("PARTITION=" + name + "; BYTES=" + str(record["size"]), flush=True)
            archives.append(archive)
    after = source_path.stat()
    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        raise ValueError("Source changed during collection; discard the output")
    for archive in archives:
        report_archive(archive)
    print("LP_INPUTS_COMPLETE; NO DEVICE ACCESS OR WRITES")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--prefix-sha256", required=True)
    parser.add_argument("--slot", type=int, required=True)
    parser.add_argument("--partitions", nargs="+", required=True)
    parser.add_argument("--output-root", required=True)
    try:
        args = parser.parse_args()
        if sys.version_info < (3, 11):
            raise ValueError("Python 3.11 or newer required")
        for digest in (args.sha256, args.prefix_sha256):
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("A full lowercase SHA256 pin is required")
        collect(args)
    except Exception as error:
        print(f"STOP: {error}", file=sys.stderr); sys.exit(1)
