#!/usr/bin/env python3
"""Verify local images, archive them, split for transport; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

CHUNK = 24 * 1024 * 1024


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def collect(pairs, destination):
    records = []
    names = set()
    for filename, expected in pairs:
        path = Path(filename).resolve(strict=True)
        if not path.is_file() or not re.fullmatch(r'[a-fA-F0-9]{64}', expected):
            raise ValueError('Invalid image path or SHA256')
        if path.name in names:
            raise ValueError('Duplicate archive filename')
        names.add(path.name)
        before = path.stat()
        actual = digest(path)
        if actual != expected.lower():
            raise ValueError('IMAGE_HASH_MISMATCH: ' + path.name)
        records.append((path, before, {'file': path.name, 'bytes': before.st_size, 'sha256': actual}))
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / 'STOCK_BOOT_INPUTS.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as writer:
        for path, before, record in records:
            print('ARCHIVE=' + path.name, flush=True)
            writer.write(path, 'images/' + path.name)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError('Source changed during collection: ' + path.name)
        writer.writestr('manifest.json', json.dumps({'schema': 1, 'images': [x[2] for x in records]}, indent=2))
    archive_hash = digest(archive)
    transport = []
    if archive.stat().st_size <= CHUNK:
        transport.append(archive)
    else:
        with archive.open('rb') as source:
            while block := source.read(CHUNK):
                number = len(transport) + 1
                part = destination / ('STOCK_BOOT_INPUTS.part%03d.zip' % number)
                with zipfile.ZipFile(part, 'w', compression=zipfile.ZIP_STORED) as wrapper:
                    wrapper.writestr('STOCK_BOOT_INPUTS.zip.part%03d' % number, block)
                transport.append(part)
    receipt = {'archive': archive.name, 'bytes': archive.stat().st_size, 'sha256': archive_hash,
               'parts': [{'file': x.name, 'bytes': x.stat().st_size, 'sha256': digest(x)} for x in transport]}
    (destination / 'transport.json').write_text(json.dumps(receipt, indent=2)+'\n')
    for path in transport + [destination / 'transport.json']:
        print('UPLOAD=' + str(path))
        print('BYTES=' + str(path.stat().st_size))
        print('SHA256=' + digest(path))
    print('ALL_STOCK_BOOT_INPUTS_COMPLETE; NO DEVICE ACCESS OR WRITES')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', nargs=2, action='append', required=True, metavar=('PATH', 'SHA256'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        collect(args.image, args.output)
    except Exception as error:
        print('STOP: ' + str(error), file=sys.stderr)
        sys.exit(1)
