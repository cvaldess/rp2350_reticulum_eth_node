# Runtime settings over HTTP

Retune a node that lives in the switch without a rebuild and without USB. `include/node_config.h`
stays the source of the **defaults**; this only stores the **overrides**, in `/node_settings` on
LittleFS. A node with no settings file behaves exactly as it did before this existed.

Same port and same auth as the OTA (`docs/ota.md`): `GET /nonce`, then quote it with
`X-Auth-Nonce` and `X-Auth` = SHA-256(nonce ‖ PSK). **LAN only** — a pre-shared key is not
internet-facing auth.

```bash
python tools/node_config.py --host 192.168.1.191                        # show
python tools/node_config.py --host 192.168.1.191 --set announce_interval_s=600
python tools/node_config.py --host 192.168.1.191 --set lora_tx_power_dbm=0
python tools/node_config.py --host 192.168.1.191 --reset                # back to the build defaults
python tools/node_config.py --host 192.168.1.191 --reboot               # apply a boot-only change
```

The USB console prints the same thing with `c`.

## What is settable, and why these

| setting | range | takes effect | why it is here |
| --- | --- | --- | --- |
| `announce_interval_s` | 10..86400 | live | bench 2's ~9 % loss is its own announces colliding with the probe (half-duplex); this is the discriminator, and it used to need a reflash |
| `lora_tx_power_dbm` | -9..30, at the antenna | live | the other candidate for that loss, and a node two metres from its peer does not need 10 dBm |
| `ntp_interval_s` | 60..604800 | live | |
| `tcp_host` | dotted IPv4 | **reboot** | moving rnsd to another machine |
| `tcp_port` | 1..65535 | **reboot** | |

The **air parameters** (frequency, bandwidth, spreading factor, coding rate, preamble) are
deliberately **not** settable: every node of the mesh has to agree on them, so changing one node
over the air would only cut it off. They stay in `node_config.h`.

A `PUT` is validated in full before anything is stored, so a request with one bad field changes
nothing. The PA is the only setting that needs an action rather than a store: if the radio refuses
the new power, nothing is written, so the file can never disagree with the radio.

## Routes

- `GET /config` → effective values, which are `overridden`, the `defaults`, and `reboot_pending`.
- `PUT /config` (auth) — a JSON object with any subset of the settings. Returns what `changed`.
- `POST /config/reset` (auth) — drops every override.
- `POST /reboot` (auth) — the only way to apply a boot-only setting without USB.

## Bench verification (2026-09-16, bench 1)

- `announce_interval_s` and `lora_tx_power_dbm` set live over HTTP; the driver logged
  `tx power now 0 dBm at the antenna (SX1262 -9 dBm)` and **bench 2's received RSSI dropped from
  ~-10 dBm to -19 dBm** — the ~9 dB the 10→0 dBm change predicts. That is the real check: the
  setting moved the radiated power, not just a file. The link kept working (`rnprobe` 3/3).
- Rejected: a value out of range (422, `announce_interval_s must be 10..86400`) and an unknown key
  (422, `unknown setting 'potato'`); `GET /config` afterwards showed nothing had changed.
- Persistence: after `POST /reboot` the node came up `announce 600s, tx 0 dBm` and bench 2 still saw
  -20 dBm, so the stored power reaches the radio at boot, not only when it is set.
- Boot-only: `tcp_port=4243` + reboot → the node came up `rnsd 192.168.1.187:4243` and logged
  `connection to 192.168.1.187:4243 failed`, proving the new value was really used; `--reset` +
  `--reboot` put it back on 4242 and `rnprobe` answered 3/3.

**Not covered:** the settings file is plain text on LittleFS, so anyone who can read the flash can
read it — that is the same exposure as the OTA PSK and is the OTP task. There is no per-setting
audit trail, and no way yet to change the remote-management allow list or the PSK itself.
