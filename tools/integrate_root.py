"""Apply the pinned SUSFS common patch with an explicit ACK context adaptation."""
from pathlib import Path
import hashlib
import shutil
import subprocess

NEXT = "a358a49e697e2bab057af9145493d5a3e13f5324"
NEXT_BASE = "9ba1a51e46d0e4a88ba502a80eda1351a6ce1cd8"
NEXT_TAG = "1a879d6a866f80b1fa1c1009a2ffa747873cbb5e"
SUSFS = "24743360ea08d98f6ad72b856851abed8de5854f"


def adapt_patch(text):
    start = text.index('--- a/fs/namespace.c\n+++ b/fs/namespace.c\n')
    end = text.find('\n--- a/', start + 1)
    if end == -1:
        end = len(text)
    section = text[start:end]
    header = "@@ -32,10 +32,20 @@\n"
    context = ' #include "internal.h"\n \n+#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT'
    if section.count(header) != 1 or section.count(context) != 1:
        raise ValueError("Unexpected upstream patch; context adaptation needs review")
    section = section.replace(header, "@@ -32,11 +32,21 @@\n", 1)
    section = section.replace(context, ' #include "internal.h"\n #include <trace/hooks/blk.h>\n \n+#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT', 1)
    return text[:start] + section + text[end:]


def integrate(common, next_root, susfs_root, record_dir):
    original = (susfs_root / "kernel_patches/50_add_susfs_in_gki-android14-6.1.patch").read_text()
    adapted = adapt_patch(original)
    patch = record_dir / "susfs-common.patch"
    patch.write_text(adapted)
    command = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)]
    subprocess.run(command + ["--dry-run"], cwd=common, check=True)
    subprocess.run(command, cwd=common, check=True)
    for name in ("fs/susfs.c", "include/linux/susfs.h", "include/linux/susfs_def.h"):
        shutil.copyfile(susfs_root / "kernel_patches" / name, common / name)
    link = common / "drivers/kernelsu"
    if link.exists() or link.is_symlink():
        raise ValueError("KernelSU integration already exists")
    link.symlink_to(next_root / "kernel", target_is_directory=True)
    with (common / "drivers/Kconfig").open("a") as stream:
        stream.write('\nsource "drivers/kernelsu/Kconfig"\n')
    with (common / "drivers/Makefile").open("a") as stream:
        stream.write('\nobj-$(CONFIG_KSU) += kernelsu/\n')
    return {"next_commit": NEXT, "next_official_base": NEXT_BASE,
            "next_stable_ancestor": NEXT_TAG, "susfs_commit": SUSFS,
            "upstream_patch_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "adapted_patch_sha256": hashlib.sha256(adapted.encode()).hexdigest(),
            "adaptation": "Preserve ACK trace/hooks/blk.h include; no patch fuzz"}
