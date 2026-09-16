# Rotating the SE050 Platform SCP03 keys

Written for: whoever runs the rotation on the bench (probably future me).

## Why

The SCP03 channel opens today with NXP's **public** factory keys (AN12436 rev 2.4, OEF
`0xA921`): ENC `d2db63e7…`, MAC `738d5b79…`, DEK `6702dac3…`. They are in the driver and in
this repo. Consequences while they stand:

- Anyone with access to the I²C bus can open the channel and **use** the keys in the chip
  (sign as this node, run ECDH). The chip stops key *extraction*, not key *use*.
- A passive sniffer who knows the static keys derives the session keys from the challenges
  (which travel in clear) and reads the encrypted traffic.

Rotating to per-device keys closes both. It does **not** protect the keys the RP2350 stores
to talk to the chip — that is a separate decision (secure boot / OTP; see "Open" below).

## This is irreversible

`PUT KEY` replaces the SSD keys. If the new keys are wrong (bad encryption, wrong framing) or
lost, the secure channel can never be opened again. No factory reset touches the SSD keys
(`RESERVED_ID_FACTORY_RESET` deletes applet objects only), and this SE050E mandates Platform
SCP, so without a channel there is no way back. On bench 1 that means losing the two
identities in the chip. **Bench 1 is the chosen sacrificial chip** (spare breakout PCBs and
virgin SE050s on hand); never run the first send on a chip that matters.

## Confirmed parameters (authoritative)

From the public NXP Plug&Trust headers and AN12436/AN12543:

| Field | Value | Source |
|---|---|---|
| INS | `0xD8` PUT KEY | `nxScp03_Const.h INS_GP_PUT_KEY` |
| P1 | `0x0B` key version | `ex_sss_auth.h EX_SSS_AUTH_SE05X_KEY_VERSION_NO` (= driver `SCP03_KEYVER`) |
| P2 | `0x81` = `0x80` multiple \| `0x01` key id | `scp.h PUT_KEYS_KEY_IDENTIFIER` |
| key type | `0x88` AES | `nxScp03_Const.h GPCS_KEY_TYPE_AES` |
| KCV length | 3 | `nxScp03_Const.h CRYPTO_KEY_CHECK_LEN` |
| KCV | AES-ECB(key, `01`×16)[:3] | GP Amd D / demo |
| component encryption | AES-CBC(current DEK, IV 0, no pad) | GP Amd D / demo |
| per-key block | `88 11 10 <16 enc> 03 <3 kcv>` (23 B) | `se05x_TP_PlatformSCP03keys.c` createKeyData |
| data field | `KVN ‖ block×3` (70 B), keys in ENC/MAC/DEK order | same |
| success response | `KVN ‖ KCV_enc ‖ KCV_mac ‖ KCV_dek` (10 B) | same (memcmp verify-after-send) |

The framing was confirmed against NXP's own rotation demo
`se05x_RotatePlatformSCP03Keys/se05x_TP_PlatformSCP03keys.c` (`createKeyData`): two length
bytes per key (`0x11` = keyLen+1, then `0x10` = keyLen), which is the one thing the earlier
draft had wrong (it omitted the first). `tools/scp03_rotate.py plan` now emits 70 bytes and the
expected response to compare after the send.

Verified twice: first against a public GitHub mirror, then against the official package
`se05x_mw_v04.08.01` (Plug&Trust MW, NXP account). The demo source is byte-identical between
the two, and every constant matches from the official headers: `GP_CLA_BYTE 0x80`,
`GP_INS_PUTKEY 0xD8`, `GP_P2_MULTIPLEKEYS 0x81`, `GPCS_KEY_TYPE_AES 0x88`,
`CRYPTO_KEY_CHECK_LEN 3`, `SCP03_KEY_ID 0x01`, `EX_SSS_AUTH_SE05X_KEY_VERSION_NO 0x0B`. The
official file also notes the SE050 authenticates PlatformSCP with KVN 11 (`0x0B`), which is the
version this rotation replaces (P1) and keeps. The zip and any extraction are gitignored; NXP
source is not redistributed in this repo.

## Validated offline (non-destructive)

`tools/scp03_rotate.py` reproduces the SCP03 primitives; the firmware `k` command
(`SE050::benchScp03Kat`) runs the driver's `cmac()`/`kdf()` on the same fixed vector.

- **CMAC** matches RFC 4493 vectors, pycryptodome, and the driver (`k`): all three agree on
  the KAT (`5328320c…`, `769d7643…`, `ef5625bf…`).
- **Whole SCP03 chain** proven against the real silicon: `verify` takes one live session's
  challenges from `k` and reproduces the card cryptogram the chip sent
  (`c2ab67bf… 0bff96ae… → 01c629682932efda`). The chip only produces that with the right
  keys + KDF + session-key + cryptogram derivation, so the Python is byte-identical to what
  the chip and driver agree on. The DEK is from the same datasheet table, on the same footing.
- **KCV / DEK-encryption** validated against pycryptodome in `selftest`.

## What remains before the send (still non-destructive until the last step)

1. ~~Confirm the data-field length framing.~~ **Done** — matched to NXP's demo (above); `plan`
   now emits the correct 70-byte field `KVN ‖ {88,11,10,<enc>,03,<kcv>}×3`.
2. **Decide where the RP2350 keeps the new keys.** In LittleFS they are readable with
   `picotool save`; rotation then raises the bar from "public" to "dump the MCU flash", which
   is real but not a vault. A vault needs RP2350 secure boot + keys in OTP (its own decision:
   signed firmware, debug fused off, restricted picotool).
2b. **Per-device UserID PIN too** (today a fixed `01…08` in the driver), with the known gotcha
   that an exhausted UserID cannot be deleted.
3. **Write and read back the new keys on the RP2350 before the send**, so a storage failure is
   caught before the chip is changed.
4. **Send, then verify in the same breath:** check the PUT KEY status word, compare the KCVs
   the chip returns with the computed ones, and immediately open a fresh channel with the new
   keys. Only if that succeeds is the rotation good; the old keys are already gone.

The `plan`/`verify`/`selftest` tool and the `k` command never write to the chip. The send step
is deliberately not implemented in either.
