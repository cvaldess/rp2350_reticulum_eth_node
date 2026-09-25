// Phase-1 node configuration. Compile-time for now; phase 4 moves this to LittleFS + the HTTP API.
#pragma once

// rnsd with a TCPServerInterface on the LAN (the Pine64 "linbox" for phase 1; the PC firewall blocks inbound 4242).
#define RNS_TCP_TARGET_HOST "192.168.1.187"
#define RNS_TCP_TARGET_PORT 4242

// Clock. microReticulum keeps time as millis() plus a persisted offset, so without this the
// node lives in 1970 and every timestamp it reports (path expiry, announces) is nonsense.
// The name goes through the DHCP-supplied DNS; the fallback is time.cloudflare.com (anycast).
#define NODE_NTP_SERVER "pool.ntp.org"
#define NODE_NTP_FALLBACK_IP "162.159.200.1"
#define NODE_NTP_INTERVAL_S (6 * 3600)
#define NODE_NTP_RETRY_S 60

// Reticulum destination this node announces so the host can see it exists.
#define NODE_APP_NAME "rp2350node"
#define NODE_APP_ASPECT "status"
#define NODE_ANNOUNCE_INTERVAL_S 120
#define NODE_ANNOUNCE_RETRY_S 30 // spacing between attempts when one fails (identity could not sign)
#define NODE_ANNOUNCE_APP_DATA "rp2350_reticulum_eth_node"

// Where the application identity lives on LittleFS when there is no SE050 (with one, both
// identities are rebuilt from the chip's public keys and this file is not used).
#define NODE_IDENTITY_PATH "/node_identity"

// Identity hashes allowed to use remote management (`rnstatus -R <transport identity> -i <file>`,
// `rnpath -R ...`): status and path table over a Link, no USB needed. Empty list = nobody.
// Currently the management identity kept on the Pine64 in ~/mgmt_identity.
#define NODE_REMOTE_MANAGEMENT_ALLOWED {"3cf4282341f8fe4934f7b416b8287992"}

// LoRa air parameters — must match on every node of the mesh (both benches run this file).
// 869.525 MHz sits in the EU g3 sub-band (869.4–869.65, 10 % duty cycle). SF8/125 kHz/4:5 is the
// usual Reticulum "fast" profile. Power is at the antenna: the E22 PA gain is subtracted in code.
#define LORA_FREQUENCY_MHZ 869.525f
#define LORA_BANDWIDTH_KHZ 125.0f
#define LORA_SPREADING_FACTOR 8
#define LORA_CODING_RATE 5
#define LORA_PREAMBLE_SYMBOLS 8
#define LORA_TX_POWER_DBM 10 // bench: boards a metre apart; raise once they are further away

// The HTTP API on the LAN: OTA (docs/ota.md) and the runtime settings (docs/config.md) share
// one port and one auth. Wire taken from the Meshtastic fork's HTTP OTA: a nonce, a SHA-256 over
// nonce||PSK to prove the caller knows the key. LAN only: a pre-shared key is not internet-facing
// auth. The PSK (NODE_API_PSK_HEX) is not in the repo: tools/node_secrets.py writes it into
// node_secrets.h at build time from ~/.rp2350-keys/api_psk.hex, generating one if there is none.
#include "node_secrets.h"
#define NODE_API_PORT 4244
#define NODE_API_NONCE_TTL_S 30
#define NODE_API_AUTH_COOLDOWN_S 5
// Trial boot after an OTA: the new image has to prove itself (SE050 probe passed and the
// first announce went out signed) within this long, or it reboots; after this many unconfirmed
// boots the previous image is put back. Overridable from the build (PLATFORMIO_BUILD_FLAGS) so a
// bench image can exercise the rollback quickly; -D NODE_OTA_TEST_NO_CONFIRM makes it never confirm.
#ifndef NODE_OTA_TRIAL_TIMEOUT_S
#define NODE_OTA_TRIAL_TIMEOUT_S 600
#endif
#define NODE_OTA_TRIAL_BOOTS 3

// A static IP (ip_mode=static over PUT /config, docs/config.md) boots on trial like an OTA image:
// unless a request reaches the API at that address within the timeout, or
// after this many unconfirmed boots, the node goes back to DHCP and reboots. DHCP with a static
// fallback needs no trial: a wrong fallback only matters while the DHCP server is down.
#ifndef NODE_IP_TRIAL_TIMEOUT_S
#define NODE_IP_TRIAL_TIMEOUT_S 600
#endif
#define NODE_IP_TRIAL_BOOTS 3

// 24x7 hardening (Fase 5). The hardware watchdog reboots the node if loop() stops feeding it for
// this long (0 disables it). 8 s is the Meshtastic rp2xx0 value; the slowest single loop() pass
// here is an SE050 signature (~250 ms) or an OTA upload (fed from inside). The "reboots a healthy
// node after ~15 s" of 2026-09-17 was the feed compiled out of main.cpp (wrong #ifdef macro, see
// FEED_WDT in main.cpp), not the timer: the node lived 8 s past its last SE050 call.
// Console 'W' stalls loop() past the window on purpose to prove the trip; the boot banner says
// when a boot was a watchdog trip; the [loop] line reports the smallest window left at feed time.
#ifndef NODE_WATCHDOG_TIMEOUT_MS
#define NODE_WATCHDOG_TIMEOUT_MS 8000
#endif
// The node reboots when the free heap stays below this for NODE_LOW_HEAP_HOLD_MS. Free heap sits
// ~460 kB in normal operation; this is the "allocations are about to fail" floor, held long enough
// that a brief dip (e.g. during an OTA upload) does not trip it. 0 disables the check.
#ifndef NODE_LOW_HEAP_REBOOT_BYTES
#define NODE_LOW_HEAP_REBOOT_BYTES 20480
#endif
#define NODE_LOW_HEAP_HOLD_MS 5000
