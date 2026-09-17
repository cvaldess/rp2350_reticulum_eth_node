// W5500 bring-up on SPI0, the sequence proven on this carrier by the Meshtastic port:
// hardware reset on GP20, ~50 ms for the PLL, SPI0 pins, DHCP with a bounded timeout
// (the library default blocks 60 s without a DHCP server, which used to stall the LoRa init).
//
// Addressing (docs/config.md): DHCP, DHCP with a static fallback, or static only. Once on the
// fallback the node stays there until it reboots — no address flapping if the server comes and
// goes — which is why the fallback should be the router's reservation for this MAC: then a lease
// and the fallback are the same address and nothing depends on which one won.
#pragma once

#include <Arduino.h>
#include <Ethernet.h>
#include <SPI.h>
#include <pico/unique_id.h>

#include "board_pins.h"

class EthernetLink
{
  public:
    // This blocking call is longer than the watchdog window (8 s, node_config.h): main.cpp feeds the
    // watchdog right before it, so a boot after a trip (the watchdog stays armed across the reset)
    // gets the whole window; ~6-7 s is a normal cold-boot lease on this network. If no lease comes
    // the static fallback (when set) takes over. The lease renewal in loop() reuses this timeout
    // inside Ethernet.maintain(): a DHCP server silent for > 8 s at renewal time trips the watchdog
    // and the node comes back on the fallback address. Known, accepted.
    static constexpr uint32_t DHCP_TIMEOUT_MS = 10000;
    static constexpr uint32_t DHCP_RETRY_TIMEOUT_MS = 4000;
    static constexpr uint32_t DHCP_RETRY_INTERVAL_MS = 30000;

    struct Address {
        bool staticOnly = false; // never ask DHCP
        bool hasStatic = false;  // ip/subnet/gateway/dns are usable (as the address, or as the fallback)
        IPAddress ip, subnet, gateway, dns;
    };
    // Where the address we are running with came from.
    enum class Source { None, Dhcp, Static, Fallback };

    bool begin(const Address &addr)
    {
        _addr = addr;
        pinMode(ETH_RESET, OUTPUT);
        digitalWrite(ETH_RESET, LOW);
        delay(100);
        digitalWrite(ETH_RESET, HIGH);
        delay(50);

        SPI.setRX(ETH_MISO);
        SPI.setSCK(ETH_SCK);
        SPI.setTX(ETH_MOSI);
        SPI.begin();
        Ethernet.init(ETH_CS);

        macFromBoardId(_mac);
        Serial.printf("[eth] mac %02x:%02x:%02x:%02x:%02x:%02x\n", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4],
                      _mac[5]);

        if (_addr.staticOnly && _addr.hasStatic) {
            Ethernet.begin(_mac, _addr.ip, _addr.dns, _addr.gateway, _addr.subnet);
            if (Ethernet.hardwareStatus() == EthernetNoHardware) {
                Serial.println("[eth] W5500 not found");
                return false;
            }
            _source = Source::Static;
            report();
            return true;
        }

        if (Ethernet.begin(_mac, DHCP_TIMEOUT_MS) == 0) {
            if (Ethernet.hardwareStatus() == EthernetNoHardware) {
                Serial.println("[eth] W5500 not found");
                return false;
            }
            _lastDhcpAttempt = millis();
            if (_addr.hasStatic) {
                Serial.printf("[eth] no DHCP lease in %lu s (link %s), falling back to the static address\n",
                              (unsigned long)(DHCP_TIMEOUT_MS / 1000), linkUp() ? "up" : "down");
                Ethernet.begin(_mac, _addr.ip, _addr.dns, _addr.gateway, _addr.subnet);
                _source = Source::Fallback;
                report();
                return true;
            }
            Serial.printf("[eth] no DHCP lease (link %s), will retry\n", linkUp() ? "up" : "down");
            return true;
        }
        _lastDhcpAttempt = millis();
        _source = Source::Dhcp;
        report();
        return true;
    }

    // On a lease: renews it, and re-runs DHCP every 30 s while there is no address but the link
    // is up. On a static address or the fallback there is nothing to maintain.
    void loop()
    {
        if (_source == Source::Static || _source == Source::Fallback)
            return;
        Ethernet.maintain();
        if (!hasIp() && linkUp() && millis() - _lastDhcpAttempt >= DHCP_RETRY_INTERVAL_MS) {
            _lastDhcpAttempt = millis();
            if (Ethernet.begin(_mac, DHCP_RETRY_TIMEOUT_MS) != 0) {
                _source = Source::Dhcp;
                report();
            }
        }
    }

    bool linkUp() const { return Ethernet.linkStatus() == LinkON; }
    bool hasIp() const { return Ethernet.localIP() != IPAddress(0, 0, 0, 0); }
    bool ready() const { return linkUp() && hasIp(); }
    Source source() const { return _source; }
    static const char *sourceName(Source s)
    {
        switch (s) {
        case Source::Dhcp:
            return "dhcp";
        case Source::Static:
            return "static";
        case Source::Fallback:
            return "static fallback";
        default:
            return "none";
        }
    }

    void report() const
    {
        IPAddress ip = Ethernet.localIP();
        IPAddress gw = Ethernet.gatewayIP();
        IPAddress dns = Ethernet.dnsServerIP();
        Serial.printf("[eth] ip %u.%u.%u.%u gw %u.%u.%u.%u dns %u.%u.%u.%u (%s) link %s\n", ip[0], ip[1], ip[2],
                      ip[3], gw[0], gw[1], gw[2], gw[3], dns[0], dns[1], dns[2], dns[3], sourceName(_source),
                      linkUp() ? "up" : "down");
    }

  private:
    // Locally administered unicast MAC derived from the RP2350 unique board id.
    static void macFromBoardId(uint8_t mac[6])
    {
        pico_unique_board_id_t id;
        pico_get_unique_board_id(&id);
        for (int i = 0; i < 6; i++)
            mac[i] = id.id[2 + i];
        mac[0] = (mac[0] & 0xfe) | 0x02;
    }

    uint8_t _mac[6] = {0};
    uint32_t _lastDhcpAttempt = 0;
    Address _addr;
    Source _source = Source::None;
};
