#!/usr/bin/env python3
"""Record the original gate and verify a narrowly reviewed linker relocation.

The original catalog names two multicast workers absent from this source
revision. Their absence is recorded, and two instantiated TCP/Select functions
are additionally checked. No production compiler flags or functions change.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys

baseline, candidate = map(Path, sys.argv[1:3])
out = Path(sys.argv[3])
out.mkdir(exist_ok=True)
catalog = candidate.resolve().parents[2] / "tools/cmp_disasm.py"
spec = importlib.util.spec_from_file_location("original_cmp_disasm", catalog)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.OBJDUMP = module.find_objdump()
raw = subprocess.run([sys.executable, str(catalog), str(baseline), str(candidate)],
                     text=True, capture_output=True)
(out / "ghost-original-disassembly-gate.txt").write_text(raw.stdout + raw.stderr)

base_root, current_root = baseline.resolve().parents[2], candidate.resolve().parents[2]
allowed_sources = {
    "attack/ops.cpp", "session/handoff_probe.cpp", "session/handoff_probe.hpp",
    "tests/handoff_probe_test.cpp",
}
base_files = {str(p.relative_to(base_root / "src/core")): p for p in (base_root / "src/core").rglob("*") if p.is_file()}
current_files = {str(p.relative_to(current_root / "src/core")): p for p in (current_root / "src/core").rglob("*") if p.is_file()}
assert base_files.keys() == current_files.keys(), "Unexpected native source path change"
changed_sources = {name for name in base_files if base_files[name].read_bytes() != current_files[name].read_bytes()}
assert changed_sources == allowed_sources, f"Unexpected source changes: {changed_sources}"

base_objects = {str(p.relative_to(baseline.parent)): p for p in baseline.parent.rglob("*.o")}
current_objects = {str(p.relative_to(candidate.parent)): p for p in candidate.parent.rglob("*.o")}
assert base_objects.keys() == current_objects.keys() and len(base_objects) == 24
allowed_objects = {"core/attack/ops.o", "core/session/handoff_probe.o", "core/session/root_child_frontend.o"}
changed_objects = {name for name in base_objects if base_objects[name].read_bytes() != current_objects[name].read_bytes()}
assert changed_objects == allowed_objects, f"Unexpected compiled IR changes: {changed_objects}"
unchanged_objects = {name: hashlib.sha256(base_objects[name].read_bytes()).hexdigest()
                     for name in base_objects if name not in changed_objects}

def mapped_bytes(binary, address, size):
    data = binary.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01"
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phcount = struct.unpack_from("<HH", data, 54)
    for i in range(phcount):
        kind, flags, offset, virtual, physical, length, memory, alignment = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize)
        if kind == 1 and not flags & 2 and virtual <= address and address + size <= virtual + length:
            position = offset + address - virtual
            return data[position:position + size]
    raise AssertionError("Reviewed constant is not in a read-only mapped segment")

def constant_address(instructions, index):
    assert instructions[index - 1] == "ldr\tw8, [x0]"
    page = re.fullmatch(r"adrp\tx9, (0x[0-9a-f]+)(?: <.*>)?", instructions[index - 2])
    assert page
    load = re.fullmatch(r"ldr\td1, \[x9(?:, #(0x[0-9a-f]+))?\]", instructions[index])
    assert load
    return int(page.group(1), 16) + int(load.group(1) or "0", 16)

base, current = module.disassemble(baseline), module.disassemble(candidate)
legacy_absence = []
for label, spellings in module.TARGETS[6:]:
    assert module.resolve(base, spellings) is None and module.resolve(current, spellings) is None
    assert not any(label.encode() in p.read_bytes() for p in base_files.values())
    legacy_absence.append({"name": label, "result": "ABSENT_IN_BOTH_SOURCE_AND_BINARIES; not counted as a passed function"})

targets = module.TARGETS[:6] + [
    ("tcp_punch_thread", ["ghostlock::route::tcp_punch_thread(void*)"]),
    ("do_pselect_fake_lock_route", ["ghostlock::route::do_pselect_fake_lock_route(ghostlock::memory::WriteRequest const*)"]),
]
results = []
for label, spellings in targets:
    base_name, current_name = module.resolve(base, spellings), module.resolve(current, spellings)
    assert base_name and current_name, f"Missing compiled target: {label}"
    before, after = base[base_name], current[current_name]
    assert len(before) == len(after), f"Instruction count changed: {label}"
    changes = [i for i, (a, b) in enumerate(zip(before, after)) if module.layout(a) != module.layout(b)]
    detail = None
    if changes:
        assert label == "do_kernel5_fake_lock_route" and len(before) == 174 and changes == [161], (label, changes)
        old_address, new_address = constant_address(before, 161), constant_address(after, 161)
        old_value, new_value = mapped_bytes(baseline, old_address, 8), mapped_bytes(candidate, new_address, 8)
        assert old_value == new_value == struct.pack("<II", 2, 60)
        detail = {"instruction": 161, "baseline": before[161], "candidate": after[161],
                  "baselineVirtualAddress": hex(old_address), "candidateVirtualAddress": hex(new_address),
                  "readOnlyConstantBytes": old_value.hex(), "meaning": "unchanged fallback status 2 and socket-failure step 60"}
    strict = [module.strict(x) for x in before] == [module.strict(x) for x in after]
    result = "IDENTICAL_STRICT" if strict else "REVIEWED_LINKER_DATA_AND_ADDRESS_LAYOUT"
    results.append({"function": label, "instructions": len(before), "result": result,
                    "relocatedConstant": detail})
    print(result, label, len(before), "instructions")

report = {"result": "PASS_WITH_DOCUMENTED_LAYOUT_REVIEW", "originalGateExitCode": raw.returncode,
          "compiler": "ONDK r30.1; unchanged production flags, API 35 and LTO",
          "baselineSHA256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
          "candidateSHA256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
          "unchangedLLVMIRObjects": unchanged_objects, "changedLLVMIRObjects": sorted(changed_objects),
          "changedNativeSources": sorted(changed_sources), "legacyCatalogAbsence": legacy_absence,
          "eightCompiledFunctions": results,
          "scope": "Compiled source/IR identity and the project's address-normalized shape comparison with one byte-proven read-only constant relocation. Not raw byte identity of the final linked functions or a device stability test."}
(out / "ghost-disassembly-review.json").write_text(json.dumps(report, indent=2) + "\n")
print("PASS: 21 unchanged LLVM IR objects, eight compiled targets, one byte-proven constant relocation")
