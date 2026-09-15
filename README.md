# rp2350_reticulum_eth_node

A self-contained [Reticulum](https://reticulum.network) transport node that hangs off an Ethernet
switch and needs no host computer: **RP2350 (Raspberry Pi Pico 2) + WIZnet W5500 Ethernet +
EBYTE E22-900M30S LoRa (SX1262) + NXP SE050E secure element**, running the
[microReticulum](https://github.com/attermann/microReticulum) network stack.

Status: **phase 0** — build probe. Nothing routes yet. See [docs/PLAN.md](docs/PLAN.md).

## What it is meant to become

- A LoRa ↔ TCP Reticulum transport node on Ethernet (`TCPClientInterface` /
  `TCPServerInterface` compatible with the reference implementation).
- Node identity (X25519 + Ed25519) **generated inside the SE050 and never exported**;
  ephemeral link keys and symmetric crypto stay in software on the MCU.
- Random numbers from the RP2350 TRNG, stirred with the SE050 TRNG.
- Firmware update and status/config over Ethernet only; USB is console and flashing.
- Remote management through Reticulum itself (microReticulum's remote management destination).

## Hardware

The carrier boards are the `pico2_w5500_e22` / `wiznet_5500_evb_pico2_e22p` designs (KiCad,
separate repository). Pin map in [include/board_pins.h](include/board_pins.h).

## Building

PlatformIO, same toolchain pin as the Meshtastic RP2350 builds:

```
pio run
pio run -t upload     # picotool, board in BOOTSEL
pio device monitor
```

## Licensing

Firmware: GPL-3.0-or-later (see LICENSE). It links microReticulum and microStore
(Apache-2.0), rweather/Crypto (MIT), arduino-pico (LGPL-2.1), and later RadioLib (MIT)
and the Arduino Ethernet library (LGPL-2.1). `src/PicoLittleFSFileSystem.h` is a modified
microStore adapter and keeps its Apache-2.0 header.
