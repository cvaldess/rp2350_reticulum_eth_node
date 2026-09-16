// Runtime settings: the handful of values worth retuning on a node that lives in the switch,
// without a rebuild and without USB (docs/config.md).
//
// include/node_config.h stays the source of the defaults; this only holds the overrides, in
// /node_settings on LittleFS. A value that was never set reads as its compile-time default, so
// a node with no settings file behaves exactly as before this existed.
//
// Two of these exist because the bench needed them on 2026-09-16: announce_interval_s and
// lora_tx_power_dbm are the two discriminators for bench 2's ~9 % loss (half-duplex collisions
// with its own announces, or too much power at two metres), and retuning them meant a reflash.
#pragma once

#include <Arduino.h>

#include "node_config.h"

class NodeSettings
{
  public:
    // Called by a change that needs something done, not just read: currently the LoRa PA.
    using TxPowerApplier = bool (*)(int8_t dbm);

    void begin();
    void onTxPower(TxPowerApplier fn) { _applyTxPower = fn; }

    uint32_t announceIntervalS() const { return _announceIntervalS; }
    int8_t loraTxPowerDbm() const { return _loraTxPowerDbm; }
    uint32_t ntpIntervalS() const { return _ntpIntervalS; }
    const char *tcpHost() const { return _tcpHost; }
    uint16_t tcpPort() const { return _tcpPort; }
    // True once a setting that only takes effect at boot has been changed.
    bool rebootPending() const { return _rebootPending; }

    // Renders the effective settings, their defaults and which ones are overridden.
    void toJson(char *out, size_t cap) const;
    // Applies a JSON object holding any subset of the settings. On failure, nothing is changed
    // and err says why. changed/needsReboot report what it did.
    bool applyJson(const char *json, char *err, size_t errCap, char *changed, size_t changedCap);
    // Drops every override; the compile-time defaults apply again (reboot for the boot-only ones).
    bool reset();
    void status(Print &out) const;

  private:
    bool load();
    bool save();
    void setDefaults();

    uint32_t _announceIntervalS = NODE_ANNOUNCE_INTERVAL_S;
    int8_t _loraTxPowerDbm = LORA_TX_POWER_DBM;
    uint32_t _ntpIntervalS = NODE_NTP_INTERVAL_S;
    char _tcpHost[16] = RNS_TCP_TARGET_HOST;
    uint16_t _tcpPort = RNS_TCP_TARGET_PORT;
    // Which fields came from the file rather than from node_config.h.
    bool _overridden[5] = {false, false, false, false, false};
    bool _rebootPending = false;
    TxPowerApplier _applyTxPower = nullptr;
};

extern NodeSettings settings;

// Registers /config, /config/reset and /reboot on the shared HTTP API.
void nodeSettingsRegisterRoutes();
// Carries out a reboot asked for over HTTP, once the reply has gone out. Call from loop().
void nodeSettingsLoop();
