#!/usr/bin/env python3
"""Fetch pinned sources and export research inputs. Never build or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile


def git(repo, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1")
    result = subprocess.run(
        ["git", "-c", "credential.helper=", "-c", "http.lowSpeedLimit=1",
         "-c", "http.lowSpeedTime=90", "-C", str(repo), *args],
        check=True, stdout=subprocess.PIPE, env=env, timeout=600)
    return result.stdout


def acquire(repo, spec):
    sha = spec["commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("A full immutable commit SHA is required")
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "remote", "add", "origin", spec["url"])
    git(repo, "fetch", "--no-tags", "--depth=1", "--filter=blob:none", "origin", sha)
    resolved = git(repo, "rev-parse", "FETCH_HEAD^{commit}").decode().strip()
    if resolved != sha:
        raise ValueError(f"Fetched revision mismatch: {resolved} != {sha}")
    return git(repo, "ls-tree", "-r", "--name-only", sha).decode().splitlines()


def write_blob(repo, sha, path, dest):
    rel = PurePosixPath(path)
    if rel.is_absolute() or ".." in rel.parts or "\\" in path:
        raise ValueError(f"Unsafe source path: {path!r}")
    data = git(repo, "show", f"{sha}:{path}")
    target = dest.joinpath(*rel.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def ack_metadata(path):
    return (
        path in {"Makefile", "KMI_GENERATION", "BUILD.bazel", "WORKSPACE",
                 "MODULE.bazel", ".bazelrc", ".bazelversion",
                 "arch/arm64/configs/gki_defconfig"}
        or ("/" not in path and path.startswith("build.config"))
        or path.startswith("android/abi_gki_aarch64")
        or path.startswith("android/gki_aarch64_modules")
        or path.startswith("android/abi_gki_modules")
    )


def patch_targets(repo, sha, paths):
    targets = set()
    for path in paths:
        if not path.endswith(".patch"):
            continue
        content = git(repo, "show", f"{sha}:{path}").decode(errors="replace")
        for match in re.finditer(r"^diff --git a/(\S+) b/(\S+)$", content, re.M):
            targets.update(match.groups())
    return targets


def ack_version(dest):
    """Read literal source metadata without sourcing shell configuration."""
    text = (dest / "Makefile").read_text()
    fields = {}
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"):
        match = re.search(rf"^{key}[ \t]*=[ \t]*([^\r\n]*)$", text, re.M)
        if not match:
            raise ValueError(f"Missing {key} in {dest}/Makefile")
        fields[key] = match.group(1).strip()
    candidates = []
    generation = dest / "KMI_GENERATION"
    if generation.exists():
        value = generation.read_text().strip()
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError("Nonliteral KMI_GENERATION")
        candidates.append((value, "KMI_GENERATION"))
    common = dest / "build.config.common"
    if common.exists():
        match = re.search(r"^KMI_GENERATION[ \t]*=[ \t]*([0-9]+)[ \t]*$",
                          common.read_text(), re.M)
        if match:
            candidates.append((match.group(1), "build.config.common"))
    if len({value for value, _ in candidates}) > 1:
        raise ValueError("Conflicting KMI generation metadata")
    return fields, (candidates[0][0] if candidates else None), [p for _, p in candidates]


def audit(config, output):
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "source research only; no build/device compatibility claim",
              "sources": {}, "patch_target_missing": {}}
    (output / "research-inputs.json").write_text(json.dumps(config, indent=2) + "\n")
    with tempfile.TemporaryDirectory() as temp:
        repositories = {}
        trees = {}
        for name, spec in config["sources"].items():
            print(f"FETCH {name} {spec['commit']}", flush=True)
            repo = Path(temp) / name
            paths = acquire(repo, spec)
            repositories[name], trees[name] = repo, paths
            dest = output / name
            dest.mkdir()
            (dest / "tree-paths.txt").write_text("\n".join(paths) + "\n")
            entry = {**spec, "tree_entries": len(paths)}
            entry["git_identity"] = git(repo, "show", "-s", "--format=fuller", spec["commit"]).decode()
            report["sources"][name] = entry

        susfs = config["sources"]["susfs"]
        targets = patch_targets(repositories["susfs"], susfs["commit"], trees["susfs"])
        report["susfs_patch_targets"] = sorted(targets)

        for name, spec in config["sources"].items():
            repo, paths = repositories[name], trees[name]
            dest = output / name
            if spec["kind"] == "ack":
                selected = sorted(p for p in paths if ack_metadata(p) or p in targets)
                report["patch_target_missing"][name] = sorted(targets - set(paths))
            elif spec["kind"] == "next":
                selected = [p for p in paths if p.startswith("kernel/") or p in {
                    "README.md", "LICENSE", "LICENSE.md", "userspace/ksud/src/susfsd.rs",
                    "userspace/ksud/Cargo.toml", "userspace/ksud/src/uapi.rs"}]
            else:
                selected = paths
            entry = report["sources"][name]
            entry["exported_blobs"] = [write_blob(repo, spec["commit"], p, dest) for p in selected]
            makefile = dest / "Makefile"
            if makefile.exists() and spec["kind"] == "ack":
                fields, generation, generation_sources = ack_version(dest)
                entry["makefile_version"] = fields
                entry["kmi_generation"] = generation
                entry["kmi_generation_sources"] = generation_sources
                print(f"ACK {name}: {json.dumps(fields)} KMI={entry['kmi_generation']}", flush=True)

    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("SOURCE_AUDIT_COMPLETE; NOT A BUILD OR DEVICE PASS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", default="sources/research-inputs.json")
    parser.add_argument("--output", default="source-audit")
    args = parser.parse_args()
    audit(json.loads(Path(args.inputs).read_text()), Path(args.output))
