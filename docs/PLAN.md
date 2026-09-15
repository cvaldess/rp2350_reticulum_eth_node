# Plan

Decided 2026-09-16. A new firmware, not a Meshtastic variant: the Meshtastic fork only
contributes code that is ours (SE050 driver, Ethernet OTA/HTTP port, board lessons).

## Architecture

```
App: transport node (main.cpp, cooperative loop, no RTOS)
  config on LittleFS · watchdog · serial log · Ethernet OTA · HTTP status/config API
microReticulum (Apache-2.0): Transport · Identity · Link · Resource · remote management
  crypto backend:  SE050 = identity keys (X25519 + Ed25519 in the vault) + TRNG
                   rweather/Crypto = ephemeral link keys, AES-CBC, HMAC, HKDF, SHA (CPU)
Interfaces:  TCPClient / TCPServer over W5500  ·  LoRa over RadioLib (E22)
Drivers:     SE050 (SCP03 over I2C, from the Meshtastic fork) · Ethernet · RadioLib
arduino-pico 5.4.4 + exceptions/RTTI · LittleFS · RP2350 TRNG
```

Design rules fixed from the start:

- **All protocols over Ethernet.** USB carries only the console and flashing.
- **Identity persistence is designed for handles, not bytes.** microReticulum's `Identity`
  keeps `_prv_bytes` in RAM and in the identity file; the vault mode replaces those with
  SE050 object IDs. The vault lands in phase 3, but nothing before it may assume that the
  private key is readable.
- **The RNG must be seeded from a hardware source before the first key exists**, and the
  firmware refuses to run otherwise (`RNG.available(32)` gate in `main.cpp`).
- Ephemeral keys stay in software: only long-lived identity operations go through the SE050
  (~64 ms per ECDH measured on the Meshtastic port; announces are minutes apart and links
  to a router are rare, so the chip is never on the forwarding path).
- E22 PA: requested dBm − 10 dB reaches the SX1262, capped at 22 dBm.

## Phases

| # | Deliverable | Proof |
|---|-------------|-------|
| 0 | PlatformIO skeleton, library builds with exceptions, TRNG seed, LittleFS adapter | build green; RAM/flash measured; transport identity hash identical across reboots |
| 1 | `TCPClientInterface` over W5500 to an `rnsd` on the LAN | this node's announce shows in `rnstatus` / `rnpath` of the host; first Reticulum MCU node on Ethernet |
| 2 | `LoRaInterface` on RadioLib with the E22 configuration | a second Reticulum LoRa node (RNode CE on a W5100S/Pico 2 board) sees the announce; node routes LoRa ↔ TCP |
| 3 | SE050 vault: Ed25519 sign + X25519 ECDH in-chip, identity as handles, ENA handling | flash dump contains no private key; announce signed by the chip verifies on `rnsd`; latencies measured |
| 4 | Ethernet OTA + HTTP status/config API | reflash and configure without touching the board |
| 5 | Hardening: TCP reconnect, watchdog, memory, 24×7 on the switch | one week unattended |

## Known unknowns

- `PIO_FRAMEWORK_ARDUINO_ENABLE_EXCEPTIONS` + microStore + MsgPack on arduino-pico: nobody
  has built this combination before.
- microReticulum's platform hooks (`Utilities/Memory.cpp`, `OS.h`) know ESP32 and nRF52
  only; the RP2350 falls into the generic branches. Heap reporting and watchdog reset need
  RP2 variants (`rp2040.getFreeHeap()`, `rp2040.wdt_reset()`).
- SE050 Ed25519: curve `TWISTED_ED25519`, algorithm `ED25519PURE_SHA_512` (0xA3) per NXP's
  plug-and-trust enums; must be exercised on the chip (FIPS mode off, AppletConfig 0x3F9F).

## References

- microReticulum `examples/lora_transport/src/main.cpp` — the template for `main.cpp`.
- Reticulum `RNS/Interfaces/TCPInterface.py` — HDLC framing: FLAG 0x7E, ESC 0x7D, mask 0x20.
- Meshtastic fork `src/security/SE050.cpp` — SCP03 channel, UserID session, X25519 keygen/ECDH.
- Meshtastic fork `variants/rp2350/diy/pico2_w5500_e22/variant.h` — pins and RF-switch lessons.
