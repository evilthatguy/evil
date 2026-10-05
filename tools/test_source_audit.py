import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from source_audit import acquire, audit, write_blob


class SourceAuditTest(unittest.TestCase):
    def test_pinned_export_and_patch_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin = root / "origin"
            origin.mkdir()
            subprocess.run(["git", "init", "-q", str(origin)], check=True)
            content = {
                "Makefile": "VERSION = 6\nPATCHLEVEL = 1\nSUBLEVEL = 177\nEXTRAVERSION =\n",
                "KMI_GENERATION": "11\n",
                "fs/namei.c": "original\n",
                "test.patch": "diff --git a/fs/namei.c b/fs/namei.c\n"
                              "diff --git a/fs/missing.c b/fs/missing.c\n",
                "kernel/Kconfig": "config KSU\n",
            }
            for name, text in content.items():
                path = origin / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            subprocess.run(["git", "-C", str(origin), "add", "."], check=True)
            subprocess.run(["git", "-C", str(origin), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
            sha = subprocess.check_output(["git", "-C", str(origin), "rev-parse", "HEAD"]).decode().strip()
            config = {"sources": {
                "ack_lts": {"kind": "ack", "url": str(origin), "commit": sha},
                "susfs": {"kind": "susfs", "url": str(origin), "commit": sha},
                "next_official": {"kind": "next", "url": str(origin), "commit": sha},
            }}
            dest = root / "report"
            audit(config, dest)
            report = json.loads((dest / "report.json").read_text())
            ack = report["sources"]["ack_lts"]
            self.assertEqual(ack["kmi_generation"], "11")
            self.assertEqual(ack["makefile_version"]["SUBLEVEL"], "177")
            self.assertEqual(report["patch_target_missing"]["ack_lts"], ["fs/missing.c"])
            blob = next(p for p in ack["exported_blobs"] if p["path"] == "fs/namei.c")
            self.assertEqual(blob["sha256"], hashlib.sha256(b"original\n").hexdigest())
            self.assertFalse((dest / "next_official" / "fs/namei.c").exists())

    def test_invalid_pin_and_unsafe_path_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                acquire(root / "repo", {"url": "unused", "commit": "main"})
            with self.assertRaises(ValueError):
                write_blob(root, "unused", "../outside", root / "out")


if __name__ == "__main__":
    unittest.main()
