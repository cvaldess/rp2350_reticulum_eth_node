# Runtime settings over the radio

The settings of `docs/config.md`, for a node that has no Ethernet: the same values, the same
validation and the same file, reached through Reticulum instead of HTTP. This is
microReticulum's **Provisioning** subsystem, served on the node's remote management
destination (`rnstransport.remote.management` of its transport identity) at the request path
`/provision`, next to the `/status` and `/path` that `rnstatus -R` uses. Only identities in
`NODE_REMOTE_MANAGEMENT_ALLOWED` (`include/node_config.h`) get an answer.

```bash
# on a host with an RNS stack and a path to the node (the Pine64), with its own Python:
~/rns-venv/bin/python rnprovision.py 71805a3a5aadac924b76626ea4be1ff7            # show (bench 1)
~/rns-venv/bin/python rnprovision.py <hash> --set announce_interval_s=600
~/rns-venv/bin/python rnprovision.py <hash> --set tcp_host=192.168.1.50 --set tcp_port=4242 --reboot
~/rns-venv/bin/python rnprovision.py <hash> --reset       # POST /config/reset
~/rns-venv/bin/python rnprovision.py <hash> --schema      # every namespace the node exposes
```

`<hash>` is the **transport identity** hash (what `rnstatus -R` takes and what the console's
`i` prints as `transport identity`), not the node destination `rnprobe` uses. The identity that
signs the requests is `--identity`, default `~/mgmt_identity` (its hash is the one in the
allow-list).

## What the node exposes

Namespace **`Node`** (id 200), one field per setting of `docs/config.md`, with the same bounds
and the same live/reboot behaviour:

| field | type | applies | notes |
| --- | --- | --- | --- |
| `announce_interval_s` | int 10..86400 | live | |
| `lora_tx_power_dbm` | int -9..30 | live | refused if the radio will not take it |
| `ntp_interval_s` | int 60..604800 | live | |
| `tcp_host` | string | reboot | dotted IPv4 |
| `tcp_port` | int 1..65535 | reboot | |
| `ip_mode` | enum `dhcp` / `static` | reboot | |
| `ip`, `subnet`, `gateway`, `dns` | string | reboot | dotted IPv4 or `""` to clear; a static address boots on trial, as over HTTP |
| `reboot_pending`, `ip_trial`, `ip_source` | read-only | | what `GET /config` also reports |
| `last_error` | read-only | | why the last commit was refused, if it was |
| `reset_overrides` | command | | `POST /config/reset` |

A reboot is the protocol's own `REBOOT` op (`--reboot`), carried out the way `POST /reboot` is:
after the reply has gone out.

The library adds its own namespaces (`Reticulum General Config`, `Transport Config`, and the
read-only `Storage`, `Info`, `Memory`, `Allocator`); `--schema` lists them and
`--namespace <name>` addresses them. Two of the general ones deserve care: **Remote Management
Allowed** replaces the allow-list at the next boot (lock yourself out and the USB console is
the way back), and **Transport Identity** would replace, at the next boot, an identity that
on these nodes lives in the SE050 - leave it alone.

## One source of truth

`NodeSettings` keeps validating, applying and persisting (`/node_settings` on LittleFS), for
HTTP and radio alike. The namespace is a facade over it (`src/NodeProvisioning.cpp`):

- every field has a **getter** (reads go to `NodeSettings`) and **no setter**;
- a `COMMIT` fires the namespace's commit hook, which turns the pending drafts into the same
  JSON a `PUT /config` carries and hands it to `NodeSettings::applyJson`. All or nothing, like
  HTTP: one bad value and nothing changes, the drafts are dropped, the reply says `applied 0`
  and `last_error` says why;
- the Provisioner still mirrors committed values into its own file (`/config/ns200.msgpack`),
  because that is what the engine does. Nothing reads it back into effect (no setters), and
  `nodeProvisioningSync()` copies `NodeSettings` into the engine's working map after boot and
  after every change from any side, so the engine never believes a stale value - that matters
  for reboot-required fields, whose "is this a change?" check the engine makes against its
  working map rather than the live getter.

Order at boot: `nodeProvisioningRegister()` right before `reticulum.start()` (the engine loads
its files inside `start()`, and wants the namespaces first), then `nodeProvisioningSync()`.

## The client

`tools/rnprovision.py` is the radio counterpart of `tools/node_config.py`: a Link to the
management destination, `IDENTIFY`, then one `Request` per operation, each a MsgPack array
`[op, seq, payload]` as the library's `provisioning_client_guide.md` specifies. It fetches the
schema (several kB) once per node and caches it in `~/.rnprovision/<hash>.json`, keyed by the
schema hash the node reports in `GET_INFO`; every later call is `GET_INFO` + `GET_STATE` on
the one namespace, or `SET_STATE` + `COMMIT`. Over LoRa at 3.1 kbps and two hops, expect one
to two seconds per request and ten for a first-time schema fetch.

**Every write is verified.** After the commit the tool reads the namespace back and compares
each value with what was asked; `--reboot` waits for the node to answer again (30 s, then
a link every few seconds, up to four minutes) and checks the values and `reboot_pending`
there. The exit status is the verdict: **0** verified, **1** the node does not hold what was
asked (a refused commit shows the reason from `last_error`), **2** the tool could not tell
(no path, no link, no answer). `--no-verify` skips the read-back. This is what makes the
losses of a two-hop LoRa path harmless: a commit whose ack never came back is not a commit
that did not happen, nor the other way round, and the read-back settles it.

What the tool does about the losses themselves, all seen on the bench: a request without an
answer within `--timeout` is sent again and the answer to *either* copy is taken (after a
reboot the relay queues requests behind a burst of announces for ~20 s, so the first answer
arrives after the second request went out); a link request without an answer is retried
after asking for the path again (a link request can land while the node is sending its own
announce - half duplex - and the local stack then sits on a path rediscovery); and the exit
status goes through `RNS.exit()`, because with a Reticulum instance up a plain `sys.exit(n)`
comes out as 0.

## Verified (bench 1, 2026-09-17, one hop over TCP)

- `--schema`: 15 fields of `Node` plus the library's namespaces.
- `--set ntp_interval_s=3600`: `applied 1`, the node logs `[settings] changed: ntp_interval_s`
  and `[prov] commit applied by radio`, and `GET /config` over HTTP reports 3600, `set`.
- `--set ip=999.1.1.1`: `applied 0`, `last_error` = *ip must be a dotted IPv4 address, or ""
  to clear it*; nothing changed.
- `tcp_port=4243` over HTTP, then `--set tcp_port=4242` by radio: the radio saw 4243 (getter),
  and the set was accepted as a change (`applied 2, REBOOT REQUIRED`) - the working-map sync.
- `--reboot`: `[api] reboot requested over radio`, back in 40 s with the values persisted and
  `reboot_pending` clear.

## Verified (bench 2, 2026-09-17, LoRa only, two hops through bench 1)

- First-time `--schema`: link 1.4 s rtt, `GET_INFO` 2.4 s, `GET_SCHEMA` **9.6 s** (it comes
  back as a Resource), 16.5 s wall. With the cache, a `show` is 6.6 s wall (`GET_INFO` 2.0 s +
  `GET_STATE` 1.1 s).
- `--set ntp_interval_s=3600`: `applied 1`, `[prov] commit applied by radio`, `GET /config`
  over the node's own Ethernet shows 3600 `set`.
- `--set ip=999.1.1.1`: `applied 0`, `last_error` with NodeSettings' reason.
- `--reset`: `reset_overrides: done`, `[settings] overrides dropped`. Its first attempt did
  not run: a lost answer, then a link that did not come up within 30 s; the third try did.
  Two hops of LoRa lose packets, and the tool's one retry does not cover everything - read the
  node back before assuming.
- `--set ip=192.168.1.192 --reboot`: `applied 1, REBOOT REQUIRED`, the `REBOOT` ack in 0.9 s,
  `[api] reboot requested over radio`, back in ~40 s on `dhcp fallback 192.168.1.192`, with
  `ntp_interval_s` at its default (the reset held) and `reboot_pending` clear.
- `--namespace Metrics`: the library's read-only namespaces answer too.
- With the verification in place: `--set ntp_interval_s=3600` → `verified`, exit 0;
  `--set ip=999.1.1.1` → `MISMATCH ip is 192.168.1.192, wanted 999.1.1.1`, the reason, exit 1;
  `--reset` → the ten settable fields read back at their defaults, exit 0; `--set ip=… --set
  tcp_port=4243 --reboot` → verified before, then the reboot, then `back after 33 s` and both
  values plus `reboot_pending False` verified, exit 0. One session out of about fifteen needed
  the link retry.

Not verified: a commit of the built-in `Remote Management Allowed` or `Transport Identity`
(deliberately - see above), and behaviour under a lossier link than two hops at two metres.
