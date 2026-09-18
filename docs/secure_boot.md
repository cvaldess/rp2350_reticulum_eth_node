# Secure boot and the OTP vault

Turns the board into a real vault, not just an anti-bus-sniffer: without this, the per-device
SCP03 master that opens the SE050 lives in the firmware image and `picotool save` reads it off the
flash (see `scp03_rotation.md`). With it, only firmware signed by our key runs, the SCP03 master is
a per-device seed in OTP that no debugger or BOOTSEL can read, and debug is off.

Every irreversible step is a separate, read-back-checked command. This is the whole point: a typo
in a fingerprint or a wrong flag is a brick, so nothing is burned in a batch.

## The pieces

- **Signing.** `tools/seal.py` runs after the build: `picotool seal --hash --sign` appends the
  signed `IMAGE_DEF` block the RP2350 bootrom checks (datasheet 5.9, 5.10.2), so `firmware.uf2`/
  `.bin` become the signed image (the unsigned ones are kept as `firmware.unsigned.*`). The keys
  are secp256k1 PEMs in `~/.rp2350-keys` (`NODE_KEYS_DIR`), never in the repo; only the public
  halves are, in `include/boot_pubkeys.h` (`tools/keys.py export`). `tools/picobin.py` reproduces
  the bootrom's check (SHA-256 over the LOAD_MAP regions + the block, then ECDSA) and the boot key
  fingerprint (SHA-256 of the 64-byte pubkey) it burns; the build fails if the sealed image would
  not verify.
- **OTA signature.** `tools/ota_upload.py` refuses an unsealed image and signs the gzip body
  (`X-OTA-Sig`, ECDSA over its SHA-256) with `bootkey0.pem`. The firmware (`Ota.cpp`) verifies it
  with micro-ecc against `boot_pubkeys.h` and refuses an upload with no/!bad signature (403).
  A rollback cannot run on an image that never boots, so this keeps a secured node from ever
  staging one. `--allow-unsigned` is only for a board that has not been secured yet
  (`-D NODE_OTA_ALLOW_UNSIGNED`), and the host refuses it once `/ota/status` says `secure_boot`.
- **The seed vault.** `src/OtpVault.{h,cpp}`: a 32-byte per-device seed in OTP page 32, rows
  `0x800..0x80f` (ECC) with its bitwise complement in `0x820..0x82f` (raw). Rows i and 32+i share
  bit cells, so seed+complement make every cell pair `{0,1}`/`{1,0}` and an FIB/PVC image cannot
  tell them apart (datasheet 13.8 chaff). The SCP03 keys derive from it
  (`key = SHA256(seed || "SCP03-ENC/MAC/DEK")[:16]`, `SE050.cpp`), the seed is wiped from RAM and
  the page is soft-locked for the rest of the boot. Hard-locked S=read-only, NS+PicoBoot
  inaccessible, so `picotool` cannot read it.

## Provisioning a board (`-D NODE_OTP_PROVISION`, console `O`)

The `*_otp_provision` envs add the console and the SE050 rotation send. Upload with
`--board <production env>` (the OTA checks the name, not the build dir). Each sub-command that
burns needs a trailing `!`. `Oi` shows everything (chip stepping, flags, locks, running image's
signature, SE050 key source) — read it between steps.

1. `Os!` — random seed from the TRNG into the blank page; reads back and checks the complement.
2. `R` `!` (main console) — re-rotate the SE050's Platform SCP03 keys to the OTP-derived ones
   (`scp03_rotation.md`). Reboot; `Oi` must show `SE050 keys in use: OTP-derived`.
3. `Ol!` then `Ow` — hard-lock the seed page, then soft-lock it this boot. After `Ol!`,
   `picotool otp get -r 0x800` is a permission failure.
4. `Ok0 <fp>!` / `Ok1 <fp>!` — burn the two boot key fingerprints (or `picotool otp load` a
   `{"bootkey0": …}` from the build's `firmware.otp.json`, **not on the EVB**). Only a fingerprint
   from `boot_pubkeys.h` is accepted.
5. `Ov!` — KEY_VALID for slots 0 and 1.
6. `OS!` — SECURE_BOOT_ENABLE. **Reboot and confirm the signed image boots before burning more.**
   To prove the gate: `picotool load firmware.unsigned.uf2` — the bootrom refuses it (falls to
   BOOTSEL); restore with the signed UF2.
7. `Ox!` — KEY_INVALID for slots 2, 3 (no key can ever be added).
8. `Od!` — DEBUG_DISABLE, SECURE_DEBUG_DISABLE, UART boot, OTP boot, watchdog-scratch reboot off.
9. `Op!` — pages 1 and 2 (flags, boot keys) NS/PicoBoot read-only. Secure stays writable so signed
   firmware can still revoke a key later.

## What this does not cover

- **Silicon stepping.** On A2, errata E16/E20/E24/E25 let a lab with glitching/laser extract the
  OTP regardless of firmware; A3 mitigates E20/E21/E22/E24, A4 also E25. Read the stepping in `Oi`
  before trusting the vault (`Oi` prints `chip revision A<n>`; the bench boards are A3).
- **Firmware RCE.** The derived keys live in RAM while the node runs; a bug in the running firmware
  can still reach them. Secure boot stops *other* code running, not this code misbehaving.
- **Recovery.** The PICOBOOT interface is left enabled on purpose, so a signed UF2 can always be
  dragged onto the BOOTSEL drive. Losing every `bootkey*.pem` means the board is frozen on its last
  signed image forever — hence two keys, the spare kept offline (`linbox:~/rp2350-keys`).
