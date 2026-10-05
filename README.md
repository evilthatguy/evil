# evil

Independent ACK-based kernel engineering for REDMAGIC Nova NP03J.
Target: compatible KernelSU Next built-in and SUSFS, with SELinux enforcement
and required vendor/GKI modules preserved. Optional features follow a working core.

**Status:** source research and stock compatibility analysis. No kernel build,
flashable artifact, runtime validation or release exists yet.

- [Current device and recovery evidence](docs/NP03J_STATE.md)
- [Pinned research inputs](sources/research-inputs.json)
- [Read-only source audit](tools/source_audit.py)

The source audit fetches immutable revisions, exports upstream files and records
hashes. Its success does not establish patch compatibility, module ABI compatibility,
device bootability or a proven restoration path. It executes no downloaded source.

No bootloader relocking, slot switching, firmware replacement, module enforcement
bypass or generic performance patch bundle is part of the first candidate.
