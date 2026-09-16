// W5500 bring-up on SPI0, the sequence proven on this carrier by the Meshtastic port:
// hardware reset on GP20, ~50 ms for the PLL, SPI0 pins, DHCP with a bounded timeout
// (the library default blocks 60 s without a DHCP server, which used to stall the LoRa init).
#pragma once

#include <Arduino.h>
#include <Ethernet.h>
#include <SPI.h>
#include <pico/unique_id.h>

#include "board_pins.h"

class EthernetLink
{
  public:
    static constexpr uint32_t DHCP_TIMEOUT_MS = 10000;
    static constexpr uint32_t DHCP_RETRY_TIMEOUT_MS = 4000;
    static constexpr uint32_t DHCP_RETRY_INTERVAL_MS = 30000;

    bool begin()
    {
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

        if (Ethernet.begin(_mac, DHCP_TIMEOUT_MS) == 0) {
            if (Ethernet.hardwareStatus() == EthernetNoHardware) {
                Serial.println("[eth] W5500 not found");
                return false;
            }
            Serial.printf("[eth] no DHCP lease (link %s), will retry\n", linkUp() ? "up" : "down");
            _lastDhcpAttempt = millis();
            return true;
        }
        _lastDhcpAttempt = millis();
        report();
        return true;
    }

    // Renews the lease; re-runs DHCP every 30 s while there is no address but the link is up.
    void loop()
    {
        Ethernet.maintain();
        if (!hasIp() && linkUp() && millis() - _lastDhcpAttempt >= DHCP_RETRY_INTERVAL_MS) {
            _lastDhcpAttempt = millis();
            if (Ethernet.begin(_mac, DHCP_RETRY_TIMEOUT_MS) != 0)
                report();
        }
    }

    bool linkUp() const { return Ethernet.linkStatus() == LinkON; }
    bool hasIp() const { return Ethernet.localIP() != IPAddress(0, 0, 0, 0); }
    bool ready() const { return linkUp() && hasIp(); }

    void report() const
    {
        IPAddress ip = Ethernet.localIP();
        IPAddress gw = Ethernet.gatewayIP();
        Serial.printf("[eth] ip %u.%u.%u.%u gw %u.%u.%u.%u link %s\n", ip[0], ip[1], ip[2], ip[3], gw[0], gw[1],
                      gw[2], gw[3], linkUp() ? "up" : "down");
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
};
