// Phase-1 node configuration. Compile-time for now; phase 4 moves this to LittleFS + the HTTP API.
#pragma once

// rnsd with a TCPServerInterface on the LAN (the Pine64 "linbox" for phase 1; the PC firewall blocks inbound 4242).
#define RNS_TCP_TARGET_HOST "192.168.1.187"
#define RNS_TCP_TARGET_PORT 4242

// Reticulum destination this node announces so the host can see it exists.
#define NODE_APP_NAME "rp2350node"
#define NODE_APP_ASPECT "status"
#define NODE_ANNOUNCE_INTERVAL_S 120
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
