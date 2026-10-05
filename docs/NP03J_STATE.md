# NP03J evidence — 2026-10-05

Evidence origin: user-provided PowerShell/ADB/fastboot outputs in this session.
Observed device baseline at 15:16 Baghdad; bootloader audit at about 15:21.
This is an observed snapshot, not a claim of all-partition byte-for-byte stock identity.

## Current observations

- Manufacturer `nubia`, model `NP03J`, device `PQ83P01`, product `PQ83P01-EEA`.
- Bootloader product `pineapple`; Android board platform also `pineapple`.
  This is not the same value as the Android product/device identifier.
- `REDMAGICOS11.0.6_NP03J_EU`, Android 16, SDK 36, reported SPL `2026-05-01`.
- Fingerprint `nubia/PQ83P01-EEA/PQ83P01:16/BQ2A.250705.001-BP2A.250605.031.A3/20260603.025850:user/release-keys`.
- Kernel `6.1.145-android14-11-g11c274d0441f-ab14259673`, ARM64, page size 4096.
- SELinux reports Enforcing; ADB executes as shell, not root.
- Slot A active, successful=yes, unbootable=no.
- Slot B successful=yes **and** unbootable=yes. Treat B as unavailable for fallback;
  the successful flag alone does not override the unbootable flag. Do not switch slots.
- Unlocked=yes, Android verified boot=orange, veritymode=enforcing.
- Bootloader secure=yes is a separate reported variable; it does not contradict unlocked=yes.
- Virtual A/B reported enabled; fastboot snapshot-update-status=none at observation time.
- Root absence has not been independently proved. No relevant names matched `/sys/module`;
  that negative observation cannot rule out built-in kernel root. Initial `which su`
  output was invalid because no device was connected; discard that result.

## Stock image inventory and headers

Local directory `E:\11.0.6NP03J_EU\01_BOOTCHAIN` exists in the supplied output.
Hashes were calculated from local files; firmware provenance is not yet verified
against an OEM package/manifest or live partition contents.

| Image | Bytes | SHA-256 |
|---|---:|---|
| boot_a.img | 100663296 | BA131890119FA311DCEF5DE44E32EB3B1EECD57C1438E3C3D314D79A07BA5490 |
| init_boot_a.img | 8388608 | 3CB299086D5965833AB32BD69F356A48D3B4B950ECE302E1BE1CCB325A6951AE |
| vendor_boot_a.img | 100663296 | 2B7F9D700306E25D73324F843530D6E1F77678ACEA5C739E85FD77FA87E2B021 |
| recovery_a.img | 104857600 | 63B93F90B685C0900411897B3E9BBAAF65632DC040D5AD6E8E235BCAF6470328 |
| dtbo_a.img | 25165824 | EE822DC17F9830189465D121FF994D02FAB0EF66F44391095F1B838C9BDA0549 |
| vbmeta_a.img | 65536 | 04F39E1175797B5EEE32F3BC238E3DD79C233A211FCDC9B841B6C88894038FD0 |
| vbmeta_system_a.img | 65536 | 3976F88D0DBC353183DF0DB25143A7D77ACB4852FC92E4EAFC742E17AC57279B |

All inspected boot/vendor headers are v4. `boot_a` kernel size=35564032,
ramdisk=0; `init_boot_a` kernel=0, ramdisk=2116450; `recovery_a` kernel=0,
ramdisk=20012629. Their boot-header signature sizes are zero; this says nothing
about AVB descriptors/footer/signatures. `vendor_boot_a` page=4096,
ramdisk=8733415, DTB=2764938, one table entry of 108 bytes, bootconfig=198.
The recovery image contains no kernel; it cannot by itself provide an independent
known-good recovery kernel. Bootloader kernel selection still requires evidence.

Actual bootloader-reported sizes match those four files: boot/vendor_boot=0x6000000,
init_boot=0x800000, recovery=0x6400000. `boot_a` type=raw; is-logical was unsupported.
Physical block links exist for boot/init_boot/vendor_boot/recovery/dtbo/vbmeta A/B,
and vbmeta_system A/B. No separate vbmeta_vendor appeared in the filtered listing;
do not invent one in the restoration scope.

## Recovery limits and remaining inputs

- Entered bootloader fastboot from Android; is-userspace=no; exact ADB serial matched.
- Read variables and rebooted normally; user confirmed Android/USB returned.
- This proves reachable bootloader fastboot from working stock Android. It does not
  yet prove hardware-key entry from a failed kernel, permission to restore boot_a
  from that mode, or temporary-boot support. Do not flash merely to test access.
- `E:\11.0.6NP03J_EU\03_SUPER\super.img`: 12884901888 bytes; not yet parsed/hashed.
- `E:\11.0.6NP03J_EU\05_RESTORE\RESTORE.ps1`: 14215 bytes; not yet read in this review.
- `/vendor/lib/modules` points to `/vendor_dlkm/lib/modules`, directory readable.
- `/system/lib/modules` points to `/system_dlkm/lib/modules`; listing its target
  was denied to ADB shell. System modules must be inspected offline from stock inputs.
- Need AVB topology, stock provenance/restoration log or script review, module ELF
  version/import/export evidence and an independent recovery entry/restore route.
- Device writes remain NO-GO. Offline source research may continue.

## Primary technical references

- https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h
- https://android.googlesource.com/platform/system/core/+/refs/heads/main/fastboot/README.md
- https://source.android.com/docs/core/architecture/partitions/generic-boot
- https://source.android.com/docs/core/architecture/kernel/abi-monitor

References define formats/mechanisms; device-specific conclusions use the actual
outputs above. New firmware/slot/source/artifact changes invalidate affected checks.
