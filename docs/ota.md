# Ethernet OTA with a trial boot

Update a node over the LAN, not over USB. The new image has to prove itself after it boots or the
node puts the previous one back, so a bad build does not leave a node in the switch bricked.

USB stays for the console (`bench/serial_*.py`) and for the very first flash of a board (the image
that is running has to already contain the OTA server). Everything after that is over Ethernet.

## Push a build

```bash
export PYTHONIOENCODING=utf-8   # Windows/Git Bash: the uploader prints a hash, not a progress bar
python tools/ota_upload.py .pio/build/pico2_w5500_e22/firmware.uf2 --host 192.168.1.191 --wait
python tools/ota_upload.py --host 192.168.1.191 --status     # what is running now, no upload
```

`--wait` polls `/ota/status` until the node reports the uploaded image as `confirmed` (or fails).
Without it the uploader returns as soon as the image is staged and the node reboots on its own.

The uploader turns the UF2 back into the flat image the OTA stub writes (verified byte-for-byte
against `objcopy -O binary` of the ELF), gzips it, and PUTs it. The board name comes from the UF2
path (`.pio/build/<env>/`); the node refuses an image built for the other carrier.

## The wire

Same shape as the Meshtastic fork's HTTP OTA. Minimal HTTP/1.1 on `NODE_OTA_PORT` (4244):

- `GET /ota/nonce` → 32 hex bytes, one shot, `NODE_OTA_NONCE_TTL_S` to use it.
- `GET /ota/status` → JSON: board, build, state, sha256, boots, uptime_s, fs_free, image_max.
- `PUT /ota` with headers `X-OTA-Nonce`, `X-OTA-Auth` (= SHA-256(nonce ‖ PSK)), `X-OTA-SHA256`
  (of the gzip body), `X-OTA-Board`; body = the gzip'd image. Reply is JSON, then reboot in 500 ms.

Auth is a pre-shared key, `NODE_API_PSK_HEX`, which is never in the repo: `tools/node_secrets.py`
builds it into the image from `~/.rp2350-keys/api_psk.hex` (or `NODE_API_PSK`), generating a random
one on the first build, and the host tools read the same file. One key per builder, shared by the
boards built with it; lose it and those boards only take a new image by USB. A wrong nonce/auth burns the nonce and
starts a `NODE_OTA_AUTH_COOLDOWN_S` cooldown. **This is LAN-only**: PSK auth is not enough to expose
the port to the internet.

The node checks the body's SHA-256, the gzip magic and the uncompressed size (against the sketch
area) before it hands the file to arduino-pico's OTA stub. The stub verifies nothing itself, so
every check lives in the firmware, before the command is committed.

## The trial boot

`Ota` (src/Ota.{h,cpp}) keeps a small state file (`/ota_state`) with `state`, the image `sha` and a
`boots` count.

1. `PUT /ota` stages the image (`firmware.bin` + `otacommand.bin`), keeps the running image as
   `firmware.prev.bin`, writes `state=pending`, reboots. The stub copies the new image into flash.
2. The new image boots. `Ota::begin()` (first thing in `setup()`) reads `pending`, counts the boot,
   and marks *this* boot as the trial. The image is on probation.
3. It confirms itself once the SE050 answered its probe **and** the first announce went out signed
   by it (`main.cpp`: `ota.confirm(...)`) — the vault works and the node is reachable. `state` →
   `confirmed`, and the previous image is dropped.
4. If it does not confirm within `NODE_OTA_TRIAL_TIMEOUT_S`, it reboots. After
   `NODE_OTA_TRIAL_BOOTS` unconfirmed boots, `begin()` stages `firmware.prev.bin` and reboots into
   it (`state=rolledback`).

Only the image that actually *booted* on trial may confirm or time itself out (`_trialThisBoot`,
set only in `begin()`). Without that, the image that *receives* an upload would confirm the trial it
just staged — its own loop already has `se050 && announcedOnce` true — before the new image ever
boots. That was the bug found and fixed on the bench 2026-09-16.

Not covered: a crash *before* `setup()` reaches `ota.confirm` on a later pass is caught by the boot
count and rolled back, but a crash so early that `begin()` never runs is not — that needs the stub
itself to count boots (a later hardening step, along with the RP2350 bootrom A/B partitions).

## Bench verification (2026-09-16, bench 1, build over Ethernet)

- Confirm path: upload → `pending boots 1` → `confirmed` in ~20 s, `rnprobe` 3/3 from the Pine64.
- Rollback path: an image built with `-D NODE_OTA_TEST_NO_CONFIRM -D NODE_OTA_TRIAL_TIMEOUT_S=45`
  never confirms; observed `boots 1 → 2 → 3`, then a reboot into the previous build (`rolledback`),
  and the recovered image answered `rnprobe` 3/3.

`-D NODE_OTA_TEST_NO_CONFIRM` (a build flag, never in a shipped image) skips the confirm call so the
rollback can be exercised; `-D NODE_OTA_TRIAL_TIMEOUT_S=<n>` shortens the wait.

## Flash sizes

The OTA keeps two gzip'd images (~330 kB each) next to the Reticulum store, so both envs use a 1 MB+
LittleFS (`board_build.filesystem_size`: bench 1 = 2m on 4 MB flash, bench 2 = 1m on 2 MB). Changing
that size moves `_FS_start`, so the first flash after the change reformats LittleFS — the path table
and time offset are lost and re-learned; the identities live in the SE050 and are unaffected.
