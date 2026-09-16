// SNTP over the W5500: one request, one reply, Unix time out. Non-blocking after the
// DNS lookup, so the periodic re-sync never stalls the Reticulum loop. No slewing and
// no filtering: Reticulum keeps time to the second and the clock only has to be
// right, not smooth.
#pragma once

#include <Arduino.h>
#include <Ethernet.h>
#include <EthernetUdp.h>

class Ntp
{
  public:
    // `server` is a host name resolved once (through the DHCP-supplied DNS) and cached;
    // `fallbackIp` is used when that lookup fails, so a broken DNS still gives us time.
    Ntp(const char *server, const char *fallbackIp) : server(server), fallbackIp(fallbackIp) {}

    // Sends one request. Returns false if nothing could be sent (no address, no socket).
    bool request();
    // True once the reply is in; unixMs is the server's transmit timestamp. A request
    // that gets no answer within REPLY_TIMEOUT_MS is dropped and pending() goes false.
    bool poll(uint64_t &unixMs);
    bool pending() const { return inflight; }

    // "YYYY-MM-DD HH:MM:SS UTC" for a Unix ms timestamp; out needs 24 bytes.
    static void format(uint64_t unixMs, char *out, size_t cap);

    static constexpr uint32_t REPLY_TIMEOUT_MS = 2000;

  private:
    bool resolve();

    const char *server;
    const char *fallbackIp;
    IPAddress ip;
    bool resolved = false;
    EthernetUDP udp;
    bool inflight = false;
    uint32_t sentAt = 0;
};
