#!/usr/bin/env python3
"""Compile pinned ACK baseline or integrated evil candidate; no device access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ACK = "4056c236e4c84d5fdc5c80409a8fa37ef82f53b9"
CLANG = "382db94fa9597402b69e252c36bf9902cc283b82"
CLANG_DIR = "clang-r487747c"


def run(command, *, cwd=None, env=None, timeout=1200):
    print("RUN " + " ".join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True, timeout=timeout)


def fetch(destination, url, sha, sparse=None):
    destination.mkdir()
    prefix = ["git", "-c", "credential.helper=", "-C", destination]
    run(prefix + ["init", "-q"])
    run(prefix + ["remote", "add", "origin", url])
    run(prefix + ["fetch", "--depth=1", "--no-tags", "--filter=blob:none", "origin", sha])
    resolved = subprocess.check_output(prefix + ["rev-parse", "FETCH_HEAD^{commit}"]).decode().strip()
    if resolved != sha:
        raise ValueError("Fetched commit differs from immutable pin")
    if sparse:
        run(prefix + ["sparse-checkout", "init", "--cone"])
        run(prefix + ["sparse-checkout", "set", sparse])
    run(prefix + ["checkout", "--detach", sha])


def build(variant):
    root = Path(variant + "-work").resolve()
    root.mkdir(exist_ok=False)
    common = root / "common"
    toolchain = root / "toolchain"
    metadata = Path(variant + "-metadata").resolve()
    metadata.mkdir(exist_ok=False)
    fetch(common, "https://android.googlesource.com/kernel/common", ACK)
    integration = None
    if variant == "evil":
        from integrate_root import NEXT, NEXT_BASE, NEXT_TAG, SUSFS, integrate
        next_root = root / "next"
        next_root.mkdir()
        prefix = ["git", "-c", "credential.helper=", "-C", next_root]
        run(prefix + ["init", "-q"])
        run(prefix + ["remote", "add", "origin", "https://github.com/pershoot/KernelSU-Next.git"])
        # Full ancestry prevents upstream Kbuild from performing an unpinned unshallow fetch.
        run(prefix + ["fetch", "--no-tags", "--filter=blob:none", "origin", NEXT])
        resolved = subprocess.check_output(prefix + ["rev-parse", "FETCH_HEAD^{commit}"], text=True).strip()
        if resolved != NEXT:
            raise ValueError("Next commit differs from pin")
        for ancestor in (NEXT_BASE, NEXT_TAG):
            run(prefix + ["merge-base", "--is-ancestor", ancestor, NEXT])
        run(prefix + ["update-ref", "refs/remotes/origin/dev", NEXT_BASE])
        run(prefix + ["update-ref", "refs/tags/v3.4.0", NEXT_TAG])
        run(prefix + ["sparse-checkout", "init", "--cone"])
        run(prefix + ["sparse-checkout", "set", "kernel", "uapi"])
        run(prefix + ["checkout", "-b", "dev-susfs", NEXT])
        if (next_root / ".git/shallow").exists():
            raise ValueError("KernelSU version ancestry is incomplete")
        for header in ("app_profile.h", "feature.h", "ksu.h", "selinux.h", "sulog.h", "supercall.h"):
            if not (next_root / "kernel/include/uapi" / header).is_file():
                raise ValueError("Incomplete KernelSU UAPI checkout: " + header)
        susfs_root = root / "susfs"
        fetch(susfs_root, "https://gitlab.com/simonpunk/susfs4ksu.git", SUSFS)
        integration = integrate(common, next_root, susfs_root, metadata)
    fetch(toolchain, "https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86", CLANG, CLANG_DIR)
    compiler = toolchain / CLANG_DIR / "bin" / "clang"
    if not compiler.is_file():
        raise ValueError("Pinned prebuilt lacks the compiler required by ACK")
    version = subprocess.check_output([compiler, "--version"], text=True)
    if "r487747c" not in version:
        raise ValueError("Clang identity does not match ACK build.config.constants")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from source_audit import ack_version
    fields, generation, generation_sources = ack_version(common)
    if (fields["VERSION"], fields["PATCHLEVEL"], fields["SUBLEVEL"], generation) != ("6", "1", "177", "11"):
        raise ValueError("Unexpected ACK baseline version/KMI")
    env = dict(os.environ)
    env.update(PATH=str(compiler.parent)+os.pathsep+env["PATH"],
               KBUILD_BUILD_USER="evil", KBUILD_BUILD_HOST="github",
               KBUILD_BUILD_TIMESTAMP="2026-10-05 00:00:00 +0000",
               KBUILD_BUILD_VERSION="1", LOCALVERSION="")
    output = root / "out"
    make = ["make", "-C", common, f"O={output}", "ARCH=arm64", "LLVM=1", "LLVM_IAS=1",
            "KCFLAGS=-D__ANDROID_COMMON_KERNEL__"]
    if variant == "evil":
        # Trust only the official Next manager certificate pair, without package-name pinning.
        make.append("KSU_NEXT_MANAGER_LIST=0x3e6:79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7")
    run(make + ["gki_defconfig"], env=env)
    run([common / "scripts/config", "--file", output / ".config", "--set-str",
         "LOCALVERSION", "-android14-11-" + variant], env=env)
    if variant == "evil":
        settings = ["KSU", "KSU_SUSFS", "KSU_SUSFS_SUS_PATH", "KSU_SUSFS_SUS_MOUNT",
                    "KSU_SUSFS_SUS_KSTAT", "KSU_SUSFS_SPOOF_UNAME", "KSU_SUSFS_ENABLE_LOG",
                    "KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS", "KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG",
                    "KSU_SUSFS_OPEN_REDIRECT", "KSU_SUSFS_SUS_MAP"]
        for symbol in settings:
            run([common / "scripts/config", "--file", output / ".config", "--enable", symbol], env=env)
        for symbol in ("KSU_THRONE_TRACKER_ALWAYS_THREADED", "KSU_DEBUG", "KSU_DISABLE_MANAGER", "KSU_DISABLE_POLICY"):
            run([common / "scripts/config", "--file", output / ".config", "--disable", symbol], env=env)
    run(make + ["olddefconfig"], env=env)
    config = (output / ".config").read_text()
    for setting in ("CONFIG_ARM64=y", "CONFIG_ARM64_4K_PAGES=y", "CONFIG_MODVERSIONS=y",
                    "CONFIG_MODULE_SIG=y", "CONFIG_MODULE_SIG_PROTECT=y", "CONFIG_CFI_CLANG=y"):
        if setting not in config.splitlines():
            raise ValueError("Required baseline configuration missing: " + setting)
    if "CONFIG_MODULE_FORCE_LOAD=y" in config.splitlines():
        raise ValueError("Force module loading must remain disabled")
    if variant == "evil":
        for symbol in settings + ["THREAD_INFO_IN_TASK", "KPROBES"]:
            if f"CONFIG_{symbol}=y" not in config.splitlines():
                raise ValueError("Required integration option missing: " + symbol)
    print(variant.upper() + " COMPILATION; NOT A DEVICE COMPATIBILITY PASS", flush=True)
    started = time.monotonic()
    jobs = max(1, min(os.cpu_count() or 1, 4))
    if variant == "evil":
        # Fail early on integration compile errors; objects are reused by the full build.
        run(make + [f"-j{jobs}", "drivers/kernelsu/", "fs/susfs.o"], env=env, timeout=1800)
    run(make + [f"-j{jobs}", "Image", "modules"], env=env, timeout=7200)
    image_dest = Path(variant + "-image"); image_dest.mkdir(exist_ok=False)
    names = [".config", "Module.symvers", "System.map", "include/config/kernel.release"]
    manifest = {}
    for name in names:
        source = output / name
        target = metadata / Path(name).name
        shutil.copyfile(source, target)
        manifest[name] = {"bytes": source.stat().st_size,
                          "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    image = output / "arch/arm64/boot/Image"
    with image.open("rb") as stream:
        image_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    shutil.copyfile(image, image_dest / "Image")
    manifest["arch/arm64/boot/Image"] = {"bytes": image.stat().st_size, "sha256": image_hash}
    record = {"scope": "compilation only; no boot packaging, device writes or ABI approval",
              "variant": variant, "integration": integration,
              "ack_commit": ACK, "clang_commit": CLANG, "compiler_version": version,
              "version": fields, "kmi_generation": generation,
              "kmi_generation_sources": generation_sources,
              "elapsed_build_seconds": round(time.monotonic()-started, 1),
              "make_arguments": list(map(str, make)), "files": manifest}
    (metadata / "build.json").write_text(json.dumps(record, indent=2)+"\n")
    # Keep a compressed vmlinux for ABI/type and trusted-certificate analysis.
    with (image_dest / "vmlinux.gz").open("wb") as target:
        subprocess.run(["gzip", "-n", "-1", "-c", output / "vmlinux"], stdout=target, check=True, timeout=600)
    print(variant.upper() + "_BUILD_COMPLETE; NO DEVICE ACCESS OR WRITES", flush=True)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--variant', choices=('baseline', 'evil'), required=True)
        build(parser.parse_args().variant)
    except Exception as error:
        print(f"STOP: {error}", file=sys.stderr)
        sys.exit(1)
