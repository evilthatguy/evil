#!/usr/bin/env python3
"""Compile the unchanged ARM host tests and run them through QEMU userspace."""
import os
from pathlib import Path
import shlex
import subprocess
import sys

args = sys.argv[1:]
compiler = os.environ.get("R3_HOST_COMPILER", "aarch64-linux-gnu-g++")
output = Path(args[args.index("-o") + 1]).resolve()
link = "-c" not in args
if link:
    args[args.index("-o") + 1] = str(output) + ".arm64"
subprocess.run([compiler, *args], check=True)
if link:
    output.write_text("#!/bin/sh\nexec qemu-aarch64 -L /usr/aarch64-linux-gnu "
                      + shlex.quote(str(output) + ".arm64") + ' "$@"\n')
    output.chmod(0o755)
