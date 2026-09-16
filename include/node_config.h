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

// Where the application identity lives on LittleFS (phase 3 replaces the bytes with SE050 handles).
#define NODE_IDENTITY_PATH "/node_identity"
