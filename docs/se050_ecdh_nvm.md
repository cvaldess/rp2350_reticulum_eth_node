# Does the X25519 agreement wear the SE050's NVM?

Measured on bench 1 (SE050E2, applet 7.2.0, IoT applet `AppletConfig=0x3f9f`), 2026-09-17.
Short answer: **not measurably** with the byte-array form we use, so `SE050::x25519Ecdh`
stays on it. The transient-object form the spec recommends is implemented, verified and
kept as an option, and the measurement runs on demand from the console (`B`).

## The claim

AN12543 (SE05x APDU spec, rev 4.5) §4.10.3, on `ECDHGenerateSharedSecret`:

> ECDHGenerateSharedSecret commands with EC keys using curve ID_ECC_MONT_DH_25519 or
> ID_ECC_MONT_DH_448 cause NVM write operations for each call if the public key is passed
> as a byte array. This is not the case … when the external public key is passed via a
> transient Secure Object identifier.

NXP support (forum, 2026-09-17) confirmed it for applet 7.2.0 and said the `WriteECKey`
into a transient object goes to SRAM. The same spec, §4.7.1.1, warns the opposite:
*"writing transient ECKey Secure Objects causes NVM write accesses"*. The chip gives no way
to see its NVM, so the only thing left was to measure.

Why it would matter: `Identity::decrypt` does one agreement per single packet encrypted to
this node (links use ephemeral software keys; announces sign, they do not agree). On the
bench that is ~2 000 a day, nearly all of them the Pine64's probes.

## The two forms

- **Bytes** (`x25519EcdhBytes`): one APDU, `TAG_1` private key id + `TAG_2` peer key (32 B).
- **Object** (`x25519EcdhObject`): `WriteECKey` of the peer key into `PEER_KEY_OBJ`
  (`RNPK`, an `ECPublicKey` created once with `INS_TRANSIENT`, policy
  `ALLOW_KA|READ|WRITE|DELETE` bound to the UserID), then the agreement with `TAG_3` = that
  id. Two APDUs. The object's attributes live in NVM (one write, at creation); its value is
  in RAM and cleared on applet deselect, which is fine because it is rewritten before every
  agreement.

Both reproduce the software `Curve25519` secret byte for byte, every round.

## Why a plain "bytes vs object" timing cannot answer it

Every APDU is a UserID session nested in SCP03 (AES-CMAC + AES-CBC both ways) over I2C.
`TAG_2` carries the 32-byte key, `TAG_3` a 4-byte id; after the session wrapper and the
SCP03 padding that is **two AES blocks more on the wire** for the bytes form: ~3 ms at
100 kHz, the same order as an NVM write. And `xfer` polls the chip for its answer every
10 ms, which quantises every APDU to 10 ms. The first run showed exactly that: everything
landed on multiples of 10 ms and the "−10 ms" between a transient and a persistent write
was one poll interval, not the NVM.

So `benchEcdhNvm()`:

- polls every 0.25 ms and runs the bus at 400 kHz for its duration (the chip takes up to
  1 MHz with clock stretching, which the RP2350 does), both restored after;
- **prices the wire** with `EdDSASign` over 1 and 33 bytes: same computation (one
  SHA-512 block either way), exactly two AES blocks apart;
- **prices an NVM write** with the same `WriteECKey`, byte for byte, into a persistent
  control object (`RNPC`, created and deleted by the benchmark) next to the transient one;
- times the agreement against the persistent object too (same bytes as the transient one);
- rotates three peer keys so no write repeats the value an object already holds;
- reports min/avg/max over 12 rounds. Min is the statistic: the process is fixed-cost and
  the jitter is all above it.

## Results

Bench 1, 400 kHz, 0.25 ms polling, 12 rounds, two runs (boot with `-D SE050_BENCHMARK`,
then `B` on the production image). Milliseconds.

| APDU                                                | run 1 min / avg / max | run 2 min / avg / max |
| --------------------------------------------------- | --------------------- | --------------------- |
| ECDH, peer key as bytes (`TAG_2`)                   | 54.6 / 54.9 / 55.2    | 54.3 / 54.9 / 55.2    |
| ECDH, peer key by transient object (`TAG_3`)        | 53.9 / 54.1 / 55.9    | 53.4 / 54.2 / 55.9    |
| ECDH, peer key by persistent object (`TAG_3`)       | 52.8 / 53.4 / 55.1    | 52.6 / 53.2 / 55.1    |
| `WriteECKey` into the transient object              | 31.5 (11/12), 33.5 (1)| 31.6 (11/12), 33.8 (1)|
| `WriteECKey` into the persistent object (NVM)       | 33.2 / 33.7 / 33.8    | 33.5 / 33.8 / 33.8    |
| wire, two AES blocks (`EdDSASign` 33 B − 1 B)       | 1.3                   | 1.7                   |
| object form end to end (write + agree)              | 85.0 / 85.6 / 87.8    | 85.3 / 85.7 / 87.5    |
| software `Curve25519` on the RP2350                 | 25                    | 25                    |

At 100 kHz with the normal 10 ms polling (what the node runs): bytes 66 ms, object form
102 ms per agreement.

Reading:

1. **An NVM write is visible at this resolution: +1.6 to +2.3 ms.** The persistent write
   costs that much more than the transient one, 12 rounds out of 12, same bytes.
2. **The bytes agreement does not show one.** It costs 0.7-0.9 ms more than the object
   agreement, *less* than the 1.3-1.7 ms its two extra wire blocks cost on their own. An
   NVM write the size of the value write (+2 ms) is excluded; a single-page one (~1 ms)
   sits at about two sigma of the noise.
3. The transient write is not free of NVM either: one round in twelve costs exactly the
   persistent price (round 4, 4, 8 across runs), i.e. some periodic housekeeping in the
   applet. Still an order of magnitude less than "every call", if every call wrote.
4. The object form costs **+30-36 ms per decrypted packet** for nothing this chip lets us
   measure.

Scale, in case the spec were right after all: the SE050 datasheet gives the flash
**20 M cycles minimum, 100 M typical** per block. At 2 000 agreements a day on the same page
that is 27 years. It would start to matter in the Meshtastic port on a busy mesh (one
agreement per PKI packet), not here.

## Decision

`x25519Ecdh` = bytes. `-D SE050_ECDH_VIA_OBJECT` switches it to the object form, which
falls back to bytes for the run (with a `[WRN]`) if the chip refuses it while still
answering the byte-array form; `p` (re-probe) re-arms it.

## What this does not prove

- Nothing here sees the NVM. It is a timing proxy with a control; a write cheaper than
  ~1 ms would hide in the noise.
- One chip, one applet revision (7.2.0). A chip with another revision gets the same
  question asked again: `B` on the console, ~3 s, on any production image. It costs a
  handful of NVM writes (the control object) and creates `RNPK` on a chip that lacks it.
- Bench 2's applet revision was not checked in this pass.

## Reproducing

```
B            # on the USB console, after boot (probe() must have passed)
```

or build with `-D SE050_BENCHMARK` to run it at boot, right after the ECDH self-test. The
lines start with `SE050: bench`. The serial loggers hold the ports during a soak: stop the
one on the port, send `B`, restart it (see the bench notes).
