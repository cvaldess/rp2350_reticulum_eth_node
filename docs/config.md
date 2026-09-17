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

The USB console prints the same thing with `c`. A node without Ethernet gets the same settings
over the radio: `docs/provisioning.md`.

## What is settable, and why these

| setting | range | takes effect | why it is here |
| --- | --- | --- | --- |
| `announce_interval_s` | 10..86400 | live | bench 2's ~9 % loss is its own announces colliding with the probe (half-duplex); this is the discriminator, and it used to need a reflash |
| `lora_tx_power_dbm` | -9..30, at the antenna | live | the other candidate for that loss, and a node two metres from its peer does not need 10 dBm |
| `ntp_interval_s` | 60..604800 | live | |
| `tcp_host` | dotted IPv4 | **reboot** | moving rnsd to another machine |
| `tcp_port` | 1..65535 | **reboot** | |
| `ip_mode` | `dhcp` / `static` | **reboot** | see *Addressing* below |
| `ip` | dotted IPv4, or `""` to clear | **reboot** | the static address, or the fallback in `dhcp` mode |
| `subnet` / `gateway` / `dns` | dotted IPv4, or `""` | **reboot** | optional: `/24`, the `.1` of that subnet, and the gateway when unset |

The **air parameters** (frequency, bandwidth, spreading factor, coding rate, preamble) are
deliberately **not** settable: every node of the mesh has to agree on them, so changing one node
over the air would only cut it off. They stay in `node_config.h`.

A `PUT` is validated in full before anything is stored, so a request with one bad field changes
nothing. The PA is the only setting that needs an action rather than a store: if the radio refuses
the new power, nothing is written, so the file can never disagree with the radio.

## Addressing: DHCP, DHCP with a fallback, or static

A node that lives alone in the switch loses its API (OTA + config), its TCP link to rnsd and its
clock together the moment DHCP stops answering — and the only way left in is LoRa. So:

| `ip_mode` | `ip` | at boot |
| --- | --- | --- |
| `dhcp` | unset | DHCP only, retried every 30 s while there is no lease (as before) |
| `dhcp` | set | DHCP; **no lease within 10 s ⇒ the node brings itself up on `ip`** and stays there until it reboots |
| `static` | set | `ip` only, DHCP is never asked. `static` without an `ip` is refused |

Once on the fallback the node does **not** keep trying DHCP: an address that flaps whenever the
server comes and goes would break the rnsd link and any API client for nothing. That is why the
fallback should be **the router's DHCP reservation for this MAC** (the MAC is derived from the
RP2350 unique id, so it is stable): a lease and the fallback are then the same address, and it
makes no difference which one won. `GET /config` reports `ip_source` (`dhcp`, `static`,
`static fallback`) so you can tell without USB.

**A static address boots on trial**, exactly like an OTA image (`docs/ota.md`): if no request
reaches the API at that address within `NODE_IP_TRIAL_TIMEOUT_S` (600 s), or
after `NODE_IP_TRIAL_BOOTS` (3) unconfirmed boots, the node sets `ip_mode=dhcp` (keeping `ip` as
the fallback), reboots, and `GET /config` shows `ip_trial: reverted`. Any well-formed request
confirms — if the API can be reached at all, so can whoever has to fix it — and
`node_config.py --host <new ip>` is the natural one. A typo in a static address would
otherwise cost a trip to the USB port. A `dhcp` configuration is never on trial: a wrong fallback
only matters while the DHCP server is down, and DHCP keeps the last word when it is up.

```bash
python tools/node_config.py --host 192.168.1.192 --set ip=192.168.1.192 --reboot    # dhcp + fallback = the reservation
python tools/node_config.py --host 192.168.1.192 --set ip_mode=static --reboot      # static only; then, within 10 min:
python tools/node_config.py --host 192.168.1.192                                    # ...this confirms it
```

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
