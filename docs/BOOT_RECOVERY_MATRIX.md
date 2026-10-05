# Boot topology and recovery evidence

Observed 2026-10-05. Inputs: `NP03J_EVIDENCE.zip`, SHA256
`604d2744c6fbc61ae6016164bcb4148154ec0be54dc32f484a2fa8849e3e4695`.
Its original image hashes match the earlier local inventory. No full partition
payloads were uploaded; hash/hashtree descriptors have not been verified against
all image bytes in this review.

## AVB metadata

| Container | Protection described by supplied metadata |
|---|---|
| vbmeta_a | Chains boot (rollback location 3), recovery (1), vbmeta_system (2) |
| vbmeta_a | Direct hashes: dtbo, init_boot, vendor_boot |
| vbmeta_a | Hashtrees: odm, system_dlkm, vendor, vendor_dlkm |
| boot_a embedded vbmeta | SHA256_RSA4096; boot hash; rollback index 1740787200 |
| recovery_a embedded vbmeta | SHA256_RSA4096; recovery hash; rollback index 1 |
| vbmeta_system_a | SHA256_RSA2048; product/system/system_ext hashtrees; pvmfw hash |
| init_boot/vendor_boot embedded vbmeta | Algorithm NONE; their descriptors are authenticated through top-level vbmeta |

All inspected vbmeta flags are zero. Top-level, boot and recovery key SHA256 is
`cb1d6118fa04f2634e9d837796033b13df1d086d14a8c49a1874e622321a58c6`.
vbmeta_system key SHA256 is
`d60f62dc3ceb8816876477d265873c8b7b78c65f51d0338cfc1a850603adc85f`.
The supplied chain descriptors match those embedded key blobs. RSA metadata
signatures and authentication hashes were checked against those embedded keys
and are internally consistent. OEM trust-anchor enrollment was not inspected;
this is not a hardware trust or full-image verification result.

`dtbo_a` has no end-of-file AVB footer in the supplied 64 bytes; its signed hash
descriptor occurs in top-level vbmeta. A footer is not required to put a direct
hash descriptor in another vbmeta container.

Boot/vendor AVB properties describe Android 14, vendor/boot SPL 2025-03-01 and
fingerprint `nubia/PQ83P01-EEA/PQ83P01:14/UKQ1.230917.001/20260603.031634:user/release-keys`.
System/product properties describe Android 16 and SPL 2026-05-01, matching the
current system fingerprint. These partition-scoped properties are distinct from
the current Android release/SPL. Their differing values alone do not prove an
incorrect firmware mix. Kernel/vendor security coverage remains a separate question.

## Restoration constraints

`RESTORE.ps1` SHA256 is
`05e9436e6bba86957ffd057188dc9324bc382477ed18c23c22aa05e13f7e7315`.
Source review shows it requires fastbootd (`is-userspace=yes`), checks product
`PQ83P01`, flashes seven boot-chain images, always flashes `super` and sets slot A.
Its default run is dry-run, but it is not a minimal kernel rollback procedure.
Do not invoke its execution mode for a boot-only candidate rollback or change the
archived script as part of this narrow kernel project.

Bootloader fastboot reports product `pineapple`, distinct from the fastbootd
product expected by that archived script. Do not loosen identity checks to accept
arbitrary products. Actual restoration mode/product/scope must be specified together.

The observed recovery image has no kernel. Reachable bootloader fastboot is proven
from working Android; hardware-key entry after a failed candidate and bootloader
boot/flash support remain unproven. Slot B is marked unbootable. Device writes NO-GO.

## Module collection limit

ADB pull exited zero but returned `0 files pulled, 0 skipped`; zero module payloads
were obtained. That is not proof the firmware contains no vendor modules. Read
stock vendor ramdisk and logical module partitions offline. Signed hashtree
descriptors report system_dlkm data size 12005376 bytes and vendor_dlkm data size
66662400 bytes. These are not their complete logical partition sizes.

Formats checked against primary AOSP sources:

- https://android.googlesource.com/platform/external/avb/+/refs/heads/main/avbtool.py
- https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h
- https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/include/liblp/metadata_format.h
