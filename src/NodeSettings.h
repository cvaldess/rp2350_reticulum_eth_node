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
//
// The address settings (2026-09-17) exist because a node that lives alone in the switch loses
// its API, its rnsd link and its clock together the moment DHCP stops answering: ip_mode=dhcp
// with an `ip` set falls back to that address when no lease comes; ip_mode=static never asks.
// A static address boots on trial (NODE_IP_TRIAL_*): a typo there would otherwise cost a USB trip.
#pragma once

#include <Arduino.h>
#include <IPAddress.h>

#include "node_config.h"

class NodeSettings
{
  public:
    // Called by a change that needs something done, not just read: currently the LoRa PA.
    using TxPowerApplier = bool (*)(int8_t dbm);

    // Asked when rendering /config: where the running address came from (EthernetLink).
    using IpSourceFn = const char *(*)();

    void begin();
    void onTxPower(TxPowerApplier fn) { _applyTxPower = fn; }
    void onIpSource(IpSourceFn fn) { _ipSource = fn; }

    uint32_t announceIntervalS() const { return _announceIntervalS; }
    int8_t loraTxPowerDbm() const { return _loraTxPowerDbm; }
    uint32_t ntpIntervalS() const { return _ntpIntervalS; }
    const char *tcpHost() const { return _tcpHost; }
    uint16_t tcpPort() const { return _tcpPort; }
    // True once a setting that only takes effect at boot has been changed.
    bool rebootPending() const { return _rebootPending; }

    // Address configuration for EthernetLink::begin(). staticOnly = ip_mode is static. hasStatic
    // = an `ip` is set; subnet/gateway/dns fall back to /24, the .1 of that subnet and the gateway.
    bool ipStaticOnly() const { return _ipStatic; }
    bool staticAddress(IPAddress &ip, IPAddress &subnet, IPAddress &gateway, IPAddress &dns) const;

    // The static-IP trial: pending while a static address has not yet been reached over the API.
    enum class IpTrial { None, Pending, Reverted };
    IpTrial ipTrial() const { return _ipTrial; }
    // A request reached the API at this address: the static configuration is proven.
    void confirmIp();
    // The trial ran out: back to DHCP (the address stays as the fallback) and reboot.
    void timeoutIpTrial();

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
    void revertIpToDhcp(const char *why);
    static const char *ipTrialName(IpTrial t);

    uint32_t _announceIntervalS = NODE_ANNOUNCE_INTERVAL_S;
    int8_t _loraTxPowerDbm = LORA_TX_POWER_DBM;
    uint32_t _ntpIntervalS = NODE_NTP_INTERVAL_S;
    char _tcpHost[16] = RNS_TCP_TARGET_HOST;
    uint16_t _tcpPort = RNS_TCP_TARGET_PORT;
    bool _ipStatic = false;   // ip_mode: false = dhcp (with _ip as the fallback when set)
    char _ip[16] = "";        // empty = not set
    char _subnet[16] = "";
    char _gateway[16] = "";
    char _dns[16] = "";
    // Which fields came from the file rather than from node_config.h.
    bool _overridden[10] = {false, false, false, false, false, false, false, false, false, false};
    bool _rebootPending = false;
    TxPowerApplier _applyTxPower = nullptr;
    IpSourceFn _ipSource = nullptr;

    IpTrial _ipTrial = IpTrial::None;
    uint32_t _ipTrialBoots = 0; // unconfirmed boots of the static address, this one included
    bool _ipTrialThisBoot = false;
};

extern NodeSettings settings;

// Registers /config, /config/reset and /reboot on the shared HTTP API.
void nodeSettingsRegisterRoutes();
// Carries out a reboot asked for over HTTP, once the reply has gone out, and times out the
// static-IP trial. Call from loop().
void nodeSettingsLoop();
