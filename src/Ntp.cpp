#include "Ntp.h"

#include <Dns.h>
#include <string.h>
#include <time.h>

namespace
{
constexpr uint16_t NTP_PORT = 123;
constexpr uint16_t LOCAL_PORT = 8123;
constexpr size_t NTP_PACKET = 48;
// Seconds between the NTP era origin (1900-01-01) and the Unix epoch.
constexpr uint32_t NTP_TO_UNIX = 2208988800UL;
} // namespace

bool Ntp::resolve()
{
    if (resolved)
        return true;
    if (ip.fromString(server)) { // a dotted address needs no lookup
        resolved = true;
        return true;
    }
    DNSClient dns;
    dns.begin(Ethernet.dnsServerIP());
    if (dns.getHostByName(server, ip, 2000) == 1) {
        resolved = true;
        return true;
    }
    if (fallbackIp && ip.fromString(fallbackIp)) {
        Serial.printf("[clock] DNS lookup of %s failed, using %s\n", server, fallbackIp);
        resolved = true; // stick with it: a DNS that just failed is not worth asking every hour
        return true;
    }
    return false;
}

bool Ntp::request()
{
    if (inflight)
        return true;
    if (!resolve())
        return false;
    if (!udp.begin(LOCAL_PORT))
        return false;

    // LI 0, VN 4, Mode 3 (client); the rest can stay zero, the server fills in what
    // matters and we only read its transmit timestamp.
    uint8_t packet[NTP_PACKET] = {0};
    packet[0] = 0x23;
    if (!udp.beginPacket(ip, NTP_PORT) || udp.write(packet, sizeof(packet)) != sizeof(packet) || !udp.endPacket()) {
        udp.stop();
        return false;
    }
    sentAt = millis();
    inflight = true;
    return true;
}

bool Ntp::poll(uint64_t &unixMs)
{
    if (!inflight)
        return false;
    int size = udp.parsePacket();
    if (size <= 0) {
        if (millis() - sentAt > REPLY_TIMEOUT_MS) {
            udp.stop();
            inflight = false;
        }
        return false;
    }
    uint8_t packet[NTP_PACKET];
    int n = udp.read(packet, sizeof(packet));
    udp.stop();
    inflight = false;
    if (n < (int)NTP_PACKET)
        return false;
    // Kiss-o'-Death (stratum 0) means "go away"; a stratum 0 answer carries no time.
    if (packet[1] == 0)
        return false;

    // Transmit timestamp: seconds since 1900 at [40..43], fraction at [44..47].
    uint32_t secs = ((uint32_t)packet[40] << 24) | ((uint32_t)packet[41] << 16) | ((uint32_t)packet[42] << 8) | packet[43];
    uint32_t frac = ((uint32_t)packet[44] << 24) | ((uint32_t)packet[45] << 16) | ((uint32_t)packet[46] << 8) | packet[47];
    if (secs < NTP_TO_UNIX)
        return false;
    unixMs = (uint64_t)(secs - NTP_TO_UNIX) * 1000ULL + (((uint64_t)frac * 1000ULL) >> 32);
    return true;
}

void Ntp::format(uint64_t unixMs, char *out, size_t cap)
{
    time_t t = (time_t)(unixMs / 1000ULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%d %H:%M:%S UTC", &tm);
}
