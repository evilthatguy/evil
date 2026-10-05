import hashlib
import io
import struct
import unittest

from collect_lp_partitions import copy_extents, partition_maps


def metadata_fixture(kind=0, start=64):
    prefix = bytearray(65536)
    geometry = bytearray(struct.pack("<II32sIII", 0x616c4467, 52, bytes(32), 4096, 1, 4096))
    geometry[8:40] = hashlib.sha256(geometry).digest()
    prefix[4096:4148] = prefix[8192:8244] = geometry
    tables = (struct.pack("<36sIIII", b"example_a", 1, 0, 1, 0)
              + struct.pack("<QIQI", 8, kind, start, 0)
              + struct.pack("<36sIQ", b"default", 0, 0)
              + struct.pack("<QIIQ36sI", 64, 4096, 0, len(prefix), b"super", 0))
    header = bytearray(256)
    struct.pack_into("<IHHI", header, 0, 0x414c5030, 10, 2, 256)
    struct.pack_into("<I", header, 44, len(tables))
    header[48:80] = hashlib.sha256(tables).digest()
    for i, (offset, stride) in enumerate(((0, 52), (52, 24), (76, 48), (124, 64))):
        struct.pack_into("<III", header, 80+12*i, offset, 1, stride)
    header[12:44] = hashlib.sha256(header).digest()
    content = header + tables
    prefix[12288:12288+len(content)] = content
    prefix[16384:16384+len(content)] = content
    return prefix


class CopyExtentsTest(unittest.TestCase):
    def test_metadata_selects_matching_backing_image_and_slot(self):
        prefix = metadata_fixture()
        self.assertEqual(partition_maps(prefix, 65536, 0, ["example_a"]),
                         {"example_a": [(64, 8)]})
        for size, slot, names in ((65535, 0, ["example_a"]), (65536, 1, ["example_a"]),
                                  (65536, 0, ["missing_a"])):
            with self.assertRaises(ValueError):
                partition_maps(prefix, size, slot, names)

    def test_corrupt_metadata_and_unsupported_extents_stop(self):
        for offset in (4096+8, 12288+12, 12288+256, 16384+12):
            prefix = metadata_fixture(); prefix[offset] ^= 1
            with self.assertRaises(ValueError):
                partition_maps(prefix, 65536, 0, ["example_a"])
        for prefix in (metadata_fixture(kind=1), metadata_fixture(start=125)):
            with self.assertRaises(ValueError):
                partition_maps(prefix, 65536, 0, ["example_a"])

    def test_discontiguous_physical_extents_keep_logical_order(self):
        raw = b"".join(bytes([n])*512 for n in range(10))
        output = io.BytesIO()
        record = copy_extents(io.BytesIO(raw), output, [(7, 2), (2, 1)], len(raw))
        expected = raw[7*512:9*512] + raw[2*512:3*512]
        self.assertEqual(output.getvalue(), expected)
        self.assertEqual(record["size"], len(expected))
        self.assertEqual(record["sha256"], hashlib.sha256(expected).hexdigest())

    def test_invalid_extents_stop_before_any_output(self):
        for extents in ([], [(-1, 1)], [(0, 0)], [(0, 1), (9, 2)]):
            output = io.BytesIO()
            with self.assertRaises(ValueError):
                copy_extents(io.BytesIO(bytes(5120)), output, extents, 5120)
            self.assertEqual(output.getvalue(), b"")
        with self.assertRaises(ValueError):
            copy_extents(io.BytesIO(bytes(100)), io.BytesIO(), [(0, 1)], 512)


if __name__ == "__main__":
    unittest.main()
