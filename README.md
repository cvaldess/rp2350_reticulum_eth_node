# rp2350_reticulum_eth_node

A self-contained [Reticulum](https://reticulum.network) transport node that plugs into an Ethernet
switch and needs no host computer: **RP2350 (Raspberry Pi Pico 2) + WIZnet W5500 Ethernet +
EBYTE E22-900M30S LoRa (SX1262) + NXP SE050E2 secure element**, running the
[microReticulum](https://github.com/attermann/microReticulum) network stack.

It routes between LoRa and a TCP connection to an `rnsd` on the LAN, and its identity keys are
generated inside the secure element and never leave it.

## Status

Working on two bench boards, 24/7. All the phases in [docs/PLAN.md](docs/PLAN.md) are done, each
checked on the hardware.

One-week unattended soak, 2026-09-18 → 2026-09-25 (167.9 h), probed every 5 minutes from `rnsd`:

| | bench 1 (1 hop, TCP) | bench 2 (2 hops, over LoRa through bench 1) |
|---|---|---|
| probes answered | 5637 / 5637 (0 % loss) | 5401 / 5637 (4.2 % loss) |
| round trip, median / p95 | 461 / 795 ms | 1342 / 1750 ms |
| resets | 0 | 0 |
| free heap | flat, ~419 kB | flat, ~421 kB |
| warnings / errors logged | 0 | 0 |

Every probe lost on bench 2 arrived while the receiving radio was transmitting (LoRa is
half-duplex): 235 of 235. This is a bench prototype, not a product: two boards, one maintainer,
one LAN.

## What it does

- **LoRa ↔ TCP transport.** A `TCPClientInterface` over the W5500 to an `rnsd` running a
  `TCPServerInterface`, and a `LoRaInterface` on RadioLib (869.525 MHz, SF8, 125 kHz, 4/5 by
  default: the EU 869.4–869.65 MHz sub-band).
- **Identity in the secure element.** The node's X25519 and Ed25519 keys (application and
  transport identities) are generated inside the SE050; announces are signed and link key
  agreements run on the chip. The I²C link to the chip is an SCP03 secure channel with
  per-device keys. Without an SE050 the node falls back to a software identity on LittleFS.
- **Secure boot (optional, irreversible).** Only images signed with your key boot; the SCP03
  keys derive from a per-device seed in a hard-locked OTP page; debug is disabled.
  See [docs/secure_boot.md](docs/secure_boot.md).
- **Updates over Ethernet** with a trial boot: a new image has to prove itself after it boots or
  the node puts the previous one back. Uploads are signed. See [docs/ota.md](docs/ota.md).
- **Settings without a rebuild,** over HTTP on the LAN ([docs/config.md](docs/config.md)) or over
  Reticulum itself for a node with no Ethernet, through microReticulum's Provisioning subsystem
  ([docs/provisioning.md](docs/provisioning.md), client `tools/rnprovision.py`).
- **Remote management** with `rnstatus -R` and `rnpath -R`, for the identities you allow.
- **Unattended operation:** 8 s hardware watchdog, reboot on low heap, TCP reconnect, DHCP with a
  static fallback, SNTP clock, entropy from the RP2350 hardware TRNG.

## Hardware

Two carriers with the same pin map ([include/board_pins.h](include/board_pins.h)):

| PlatformIO env | Board | Flash | Role on the bench | Carrier design |
|---|---|---|---|---|
| `pico2_w5500_e22` | Raspberry Pi Pico 2 on a carrier with a W5500 module | 4 MB | TCP + LoRa | [cvaldess/Pico2_W5500_E22](https://github.com/cvaldess/Pico2_W5500_E22) |
| `wiznet_5500_evb_pico2_e22p` | WIZnet W5500-EVB-Pico2 on a carrier | 2 MB | LoRa only (`NODE_DISABLE_TCP`) | [cvaldess/Wiznet_5500_EVB_Pico2_E22P](https://github.com/cvaldess/Wiznet_5500_EVB_Pico2_E22P) |

The SE050 sits on I²C. `SE050_ENA_PIN` lets the firmware power-cycle a hung chip, but only
define it on a carrier with the hardware change described in `board_pins.h`; on a board that ties
ENA to VIN, leave it out. Schematics, BOM and board images are in each carrier's repository
(linked in the table).

## Building

[PlatformIO](https://platformio.org). The toolchain and arduino-pico core are pinned in
`platformio.ini`.

```bash
pio run -e pico2_w5500_e22               # or -e wiznet_5500_evb_pico2_e22p
```

Before the first build, edit [include/node_config.h](include/node_config.h): the address of your
`rnsd`, the LoRa settings for your region, and the identity hashes allowed to manage the node.

Keys live outside the repo, in `~/.rp2350-keys` (or `NODE_KEYS_DIR`):

- `api_psk.hex`: the key for the HTTP API on the LAN. The first build generates a random one;
  keep it, because the host tools need it to talk to the boards built with it.
- `bootkey0.pem` / `bootkey1.pem`: secp256k1 keys that sign the image and the OTA uploads.
  `include/boot_pubkeys.h` holds the public halves of **this repo's** keys, so a node you build
  will only accept OTA uploads signed by them. Either generate your own and run
  `python tools/keys.py export` ([docs/secure_boot.md](docs/secure_boot.md)), or build with
  `-D NODE_OTA_ALLOW_UNSIGNED` and upload with `--allow-unsigned` on a board you do not secure.
  Without a `bootkey0.pem` the build is unsigned and says so.

The first flash is over USB: hold BOOTSEL, plug in, and copy `.pio/build/<env>/firmware.uf2` to
the drive (on the W5500-EVB-Pico2, copy it by hand rather than with `picotool`). After that:

```bash
python tools/ota_upload.py .pio/build/<env>/firmware.uf2 --host <node ip> --wait
python tools/ota_upload.py --host <node ip> --status      # the image the node is really running
python tools/node_config.py --host <node ip>              # show settings; --set key=value
```

The USB serial console (115200) takes one-letter commands: `i` identities, `e`
Ethernet/TCP/LoRa, `h` heap, `o` OTA state, `c` settings, `t` clock, `a` announce now, `r` reboot.

## Documentation

| | |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | architecture and the phases, with what proved each one |
| [docs/ota.md](docs/ota.md) | Ethernet OTA: wire format, trial boot, rollback |
| [docs/config.md](docs/config.md) | runtime settings over HTTP; addressing (DHCP, fallback, static) |
| [docs/provisioning.md](docs/provisioning.md) | the same settings over Reticulum |
| [docs/secure_boot.md](docs/secure_boot.md) | signed images, the OTP seed vault, provisioning a board |
| [docs/scp03_rotation.md](docs/scp03_rotation.md) | rotating the SE050's Platform SCP03 keys |
| [docs/se050_ecdh_nvm.md](docs/se050_ecdh_nvm.md) | does on-chip X25519 wear the SE050's NVM? (measured: no) |

`bench/` has the soak tooling: a serial logger, the probe loop run on the `rnsd` host, and the
report that produced the table above.

## Limitations

- The HTTP API authenticates with a pre-shared key and has no TLS: keep it on a trusted LAN.
- On RP2350 **A2** silicon the OTP can be read by a lab with fault injection, whatever the
  firmware does; A3 and later mitigate this. `Oi` on the console of a `*_otp_provision` build
  shows the stepping.
- Secure boot protects against other code running, not against a bug in this firmware: the
  SCP03 keys are in RAM while the node runs.
- Two changes to microReticulum are needed and have been offered upstream; until they are
  merged, the build takes the library from
  [cvaldess/microReticulum `rp2350-eth-node`](https://github.com/cvaldess/microReticulum/tree/rp2350-eth-node):
  private keys held outside the process (a secure element), and the `mtu`/`txdrp` fields that
  `rnstatus -R` expects in a remote status reply.

## Licensing

Firmware: GPL-3.0-or-later (see [LICENSE](LICENSE)). It links microReticulum and microStore
(Apache-2.0), rweather/Crypto (MIT), RadioLib (MIT), ArduinoJson (MIT), MsgPack (MIT),
micro-ecc (BSD-2-Clause), arduino-pico and the Arduino Ethernet library (LGPL-2.1).
`src/PicoLittleFSFileSystem.h` is a modified microStore adapter and keeps its Apache-2.0 header.
The SE050 driver in `src/se050/` is original to this project's author, ported from the author's
Meshtastic work on the same hardware; NXP's Plug & Trust middleware is not included.
