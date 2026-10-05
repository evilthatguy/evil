from pathlib import Path
import struct
import tempfile
import unittest

from collect_evidence import elf_sections, image_metadata, module_metadata


def module_fixture():
    names = b"\0.shstrtab\0.modinfo\0__versions\0"
    info = b"vermagic=6.1.145-android14-11 SMP preempt mod_unload modversions aarch64\0"
    versions = struct.pack("<Q56s", 0x12345678, b"module_layout")
    payload = names + info + versions
    table_offset = (64 + len(payload) + 7) & ~7
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 16, 1)
    struct.pack_into("<H", header, 18, 183)
    struct.pack_into("<Q", header, 40, table_offset)
    struct.pack_into("<HHH", header, 58, 64, 4, 1)
    def sh(name, kind, offset, size):
        return struct.pack("<IIQQQQIIQQ", name, kind, 0, 0, offset, size, 0, 0, 1, 0)
    sections = bytes(64) + sh(1, 3, 64, len(names))
    sections += sh(names.index(b".modinfo"), 1, 64 + len(names), len(info))
    sections += sh(names.index(b"__versions"), 1, 64 + len(names) + len(info), len(versions))
    return bytes(header) + payload + bytes(table_offset - 64 - len(payload)) + sections


class CollectorTest(unittest.TestCase):
    def test_module_sections_retain_exact_crc_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "vendor.ko"
            path.write_bytes(module_fixture())
            output = root / "metadata"
            output.mkdir()
            record = module_metadata(path, root, output)
            self.assertTrue(record["modinfo"][0].startswith("vermagic="))
            section = next(s for s in record["exported_sections"] if s["name"] == "__versions")
            raw = (output / record["sha256"] / Path(section["file"]).name).read_bytes()
            self.assertEqual(struct.unpack_from("<Q", raw)[0], 0x12345678)
            self.assertEqual(raw[8:21], b"module_layout")

    def test_invalid_module_bounds_and_architecture_fail(self):
        data = bytearray(module_fixture())
        struct.pack_into("<H", data, 18, 62)
        with self.assertRaises(ValueError):
            elf_sections(data)
        data = bytearray(module_fixture())
        struct.pack_into("<Q", data, 40, len(data))
        with self.assertRaises(ValueError):
            elf_sections(data)

    def test_avb_footer_extracts_embedded_metadata_and_rejects_bad_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot_a.img"
            data = bytearray(8192)
            data[:8] = b"ANDROID!"
            data[4096:4100] = b"AVB0"
            data[-64:] = struct.pack("!4sIIQQQ28s", b"AVBf", 1, 0, 4096, 4096, 256, bytes(28))
            source.write_bytes(data)
            out = root / "good"
            out.mkdir()
            record = image_metadata(source, out)
            self.assertEqual(record["avb_footer"]["vbmeta_offset"], 4096)
            self.assertEqual((out / "boot_a" / "embedded_vbmeta.img").read_bytes(), bytes(data[4096:4352]))
            data[-64:] = struct.pack("!4sIIQQQ28s", b"AVBf", 1, 0, 4096, 8180, 256, bytes(28))
            source.write_bytes(data)
            bad = root / "bad"
            bad.mkdir()
            with self.assertRaises(ValueError):
                image_metadata(source, bad)


if __name__ == "__main__":
    unittest.main()
