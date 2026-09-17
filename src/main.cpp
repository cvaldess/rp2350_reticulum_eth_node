// rp2350_reticulum_eth_node — Reticulum transport node bridging LoRa and Ethernet.
//
// Phase 0 proved the stack lives on the RP2350 (identity persists, TRNG-seeded RNG).
// Phase 1 added the W5500 and a TCPClientInterface to an rnsd on the LAN.
// Phase 2 adds the E22 LoRa interface; a NODE_DISABLE_TCP build is the LoRa-only peer.
// Phase 3 moved both identities into the SE050 (src/se050, VaultKeys.h).
// Phase 4 adds the Ethernet OTA with a trial boot (Ota.h) and the runtime settings
// (NodeSettings.h) on a shared HTTP API (HttpApi.h): USB is for the console only.
// Each node announces an application destination so the hosts can see it exists.

#include <Arduino.h>
#include <microReticulum.h>
#include <microStore/FileSystem.h>

#include "EthernetLink.h"
#include "LoRaInterface.h"
#include "HttpApi.h"
#include "NodeSettings.h"
#include "Ntp.h"
#include "Ota.h"

// The RP2350 hardware watchdog. A trip survives the reset it causes and keeps counting through the
// next setup(), so each long blocking call in setup() is fed first (a no-op on a clean boot, the
// reboot-loop breaker after a trip); it is armed at the end of setup() and loop() feeds it. This is
// the Meshtastic rp2xx0 pattern (feed-before-blocking + arm + feed-in-loop).
//
// Guard on the macro the toolchain defines (ARDUINO_ARCH_RP2040, from the board's extra_flags), NOT
// on ARCH_RP2040: that one is defined by se050/se050_port.h, which is included further down, so an
// #ifdef ARCH_RP2040 here is false while the one that arms the watchdog at the end of setup() is
// true. That is exactly what shipped on 2026-09-17: armed, never fed from loop(), and the node
// rebooted 8 s after the last SE050 operation (the driver feeds inside its own calls), which read as
// a "~15 s trip with the loop running". main.cpp.o had no reference to watchdog_update at all.
#ifdef ARDUINO_ARCH_RP2040
#include <hardware/watchdog.h>
#define FEED_WDT() rp2040.wdt_reset()
#else
#define FEED_WDT() ((void)0)
#endif
#include "PicoLittleFSFileSystem.h"
#include "Rp2350Trng.h"
#include "TCPClientInterface.h"
#include "se050/SE050.h"
#include "se050/VaultKeys.h"
#include <Wire.h>
#include "board_pins.h"
#include "node_config.h"

#include <set>

static RNS::Reticulum reticulum({RNS::Type::NONE});
static RNS::Interface tcp_interface({RNS::Type::NONE});
static RNS::Interface lora_interface({RNS::Type::NONE});
static RNS::Identity node_identity({RNS::Type::NONE});
static RNS::Destination node_destination({RNS::Type::NONE});
static microStore::Adapters::PicoLittleFSFileSystem filesystem;
static Rp2350Trng trng;
static EthernetLink eth;
static TCPClientInterface *tcp = nullptr;
static LoRaInterface *lora = nullptr;

static uint32_t lastAnnounce = 0;
static bool announcePending = false;
static bool announcedOnce = false; // an announce left this node signed: half of the OTA trial's proof

static Ntp ntp(NODE_NTP_SERVER, NODE_NTP_FALLBACK_IP);
static uint32_t lastClockSync = 0; // millis() of the last request, answered or not
static bool clockValid = false;

// microReticulum's log sink writes through newlib's _write().
extern "C" int _write(int file, char *ptr, int len)
{
    (void)file;
    int wrote = Serial.write(ptr, len);
    Serial.flush();
    return wrote;
}

// Secure element bring-up: the Meshtastic port's four-layer probe (T=1oI2C reset + applet
// select, GetVersion/GetRandom, SCP03, on-chip X25519 identity + ECDH equivalence check).
// Phase 3 hangs the Reticulum identity off this; tonight it only has to say hello and stay up.
#ifdef SE050_ENA_PIN
// ENA pulse = the only power-on reset the SE050 gets after an MCU reset (see the
// Meshtastic port), and the driver's last resort when the chip stops answering.
// Only on carriers with the ENA hardware mod.
static void se050PowerCycle()
{
    pinMode(SE050_ENA_PIN, OUTPUT);
    digitalWrite(SE050_ENA_PIN, LOW);
    delay(5);
    digitalWrite(SE050_ENA_PIN, HIGH);
    delay(250);
}
#endif

static void se050Setup()
{
#ifdef SE050_ENA_PIN
    se050PowerCycle();
#endif
    Wire.setSDA(I2C_SDA);
    Wire.setSCL(I2C_SCL);
    Wire.begin();
    Wire.setClock(100000);
    se050 = new SE050(Wire, SE050_I2C_ADDR);
#ifdef SE050_ENA_PIN
    se050->onPowerCycle(se050PowerCycle);
#endif
    if (!se050->probe()) {
        Serial.println("[se050] not available on this board");
        delete se050;
        se050 = nullptr;
    }
}

// Puts Reticulum's clock on Unix time. OS::ltime() is millis() plus an offset that the
// library persists to flash every 10 minutes, so the offset becomes "Unix ms minus
// millis()". Applied after reticulum.start(), which loads its own offset first; from
// then on the persisted offset is already epoch-based and later boots start close.
static void clockApply(uint64_t unixMs, const char *why)
{
    int64_t delta = (int64_t)unixMs - (int64_t)RNS::Utilities::OS::ltime();
    if (delta > 1000 || delta < -1000)
        RNS::Utilities::OS::setTimeOffset(RNS::Utilities::OS::getTimeOffset() + delta);
    clockValid = true;
    char when[24];
    Ntp::format(unixMs, when, sizeof(when));
    Serial.printf("[clock] %s: %s (step %+lld ms)\n", why, when, (long long)delta);
}

// One request in flight at most; a reply is applied whenever it lands. Re-syncs every
// NODE_NTP_INTERVAL_S, or every NODE_NTP_RETRY_S while the clock has never been set.
static void clockLoop()
{
    uint64_t unixMs;
    if (ntp.poll(unixMs))
        clockApply(unixMs, "ntp");
    if (ntp.pending() || !eth.hasIp())
        return;
    uint32_t interval = (clockValid ? settings.ntpIntervalS() : NODE_NTP_RETRY_S) * 1000u;
    if (lastClockSync != 0 && millis() - lastClockSync < interval)
        return;
    lastClockSync = millis();
    if (!ntp.request())
        Serial.println("[clock] NTP request not sent (no DNS answer / no socket)");
}

static void printHeap(const char *tag)
{
    Serial.printf("[%s] heap total=%d free=%d\n", tag, rp2040.getTotalHeap(), rp2040.getFreeHeap());
}

// A last-resort reboot if the free heap stays below the floor for long enough. A hang is the
// watchdog's job; this is for the other 24x7 failure, a slow leak that would otherwise end in
// failed allocations and half-working state. The dip has to be sustained (NODE_LOW_HEAP_HOLD_MS)
// so a transient allocation (an OTA upload, a burst of packets) is not mistaken for a leak. The
// reboot goes through the normal path, so an OTA image that leaks fails its trial and rolls back.
static void checkLowHeap()
{
#if NODE_LOW_HEAP_REBOOT_BYTES > 0
    static uint32_t lowSince = 0;
    uint32_t freeHeap = rp2040.getFreeHeap();
    if (freeHeap >= NODE_LOW_HEAP_REBOOT_BYTES) {
        lowSince = 0;
        return;
    }
    uint32_t now = millis();
    if (lowSince == 0) {
        lowSince = now ? now : 1;
        Serial.printf("[mem] free heap %lu below %d, watching\n", (unsigned long)freeHeap,
                      NODE_LOW_HEAP_REBOOT_BYTES);
    } else if (now - lowSince >= NODE_LOW_HEAP_HOLD_MS) {
        Serial.printf("[mem] free heap %lu below %d for %d ms, rebooting\n", (unsigned long)freeHeap,
                      NODE_LOW_HEAP_REBOOT_BYTES, NODE_LOW_HEAP_HOLD_MS);
        Serial.flush();
        rp2040.reboot();
    }
#endif
}

static IPAddress parseIp(const char *s)
{
    IPAddress ip;
    ip.fromString(s);
    return ip;
}

static void announceNow(const char *why, bool force = false)
{
    if (!node_destination)
        return;
    // A failed attempt (the chip did not sign) waits NODE_ANNOUNCE_RETRY_S before the
    // next one, whatever asked for it: without this the "link up" retry fired once per
    // loop pass while the chip was off. The console skips the wait.
    if (!force && lastAnnounce != 0 && millis() - lastAnnounce < (uint32_t)NODE_ANNOUNCE_RETRY_S * 1000)
        return;
    lastAnnounce = millis();
    try {
        // Build first, send second. announce() with send=true swallows a signing failure
        // into its own log line and returns NONE in both cases; with send=false NONE means
        // exactly "no packet", which with the keys in the SE050 means the chip did not sign.
        RNS::Packet packet =
            node_destination.announce(RNS::bytesFromString(NODE_ANNOUNCE_APP_DATA), false, {RNS::Type::NONE}, {}, false);
        if (!packet) {
            Serial.printf("[node] announce NOT sent (%s): the identity could not sign\n", why);
            return;
        }
        packet.send();
        announcePending = false;
        announcedOnce = true;
        Serial.printf("[node] announced %s (%s)\n", node_destination.hash().toHex().c_str(), why);
    } catch (const std::exception &e) {
        Serial.printf("[node] announce failed: %s\n", e.what());
    }
}

static bool reticulumSetup()
{
    try {
        filesystem.init();
        RNS::Utilities::OS::register_filesystem(filesystem);

        // Reticulum() calls RNG.begin(), which resets the pool: seed *after* it and before start().
        reticulum = RNS::Reticulum();
        Rp2350Trng::seedOnce();
        RNG.addNoiseSource(trng);
        if (!RNG.available(32)) {
            Serial.println("FATAL: RNG has no entropy credit after TRNG seed, refusing to create keys");
            return false;
        }

#ifndef NODE_DISABLE_TCP
        tcp = new TCPClientInterface("TCPClientInterface", parseIp(settings.tcpHost()), settings.tcpPort());
        tcp_interface = tcp;
        tcp_interface.mode(RNS::Type::Interface::MODE_FULL);
        RNS::Transport::register_interface(tcp_interface);
        tcp_interface.start();
#endif

        // The air parameters are compile-time: every node of the mesh has to agree on them.
        // Only the power is a runtime setting, so a node in the switch can be turned down.
        LoRaInterface::Params lp = {LORA_FREQUENCY_MHZ,   LORA_BANDWIDTH_KHZ,    LORA_SPREADING_FACTOR,
                                    LORA_CODING_RATE,     LORA_PREAMBLE_SYMBOLS, settings.loraTxPowerDbm()};
        lora = new LoRaInterface("LoRaInterface", lp);
        lora_interface = lora;
        lora_interface.mode(RNS::Type::Interface::MODE_FULL);
        RNS::Transport::register_interface(lora_interface);
        if (!lora_interface.start()) {
            Serial.println("FATAL: LoRa radio did not initialise");
            return false;
        }

        // Transport identity. Transport::start() creates one on LittleFS unless it already
        // has one, so with an SE050 on the board it gets a pair of chip keys first (objIds
        // RNTX / RNTS). It signs the rnstransport.probe and remote-management proofs.
        if (se050) {
            RNS::Identity transport = se050Identity(*se050, VAULT_TRANSPORT_EXCHANGE_OBJ, VAULT_TRANSPORT_SIGNING_OBJ);
            if (transport) {
                RNS::Transport::identity(transport);
                Serial.println("[node] transport identity keys live in the SE050");
            } else {
                Serial.println("[node] SE050 present but transport keys are not usable, Transport falls back to LittleFS");
            }
        }

        // Who may talk to rnstransport.remote.management. Transport::start() copies the
        // list into the request handlers, so it has to be complete before start().
        {
            std::set<RNS::Bytes> allowed;
            for (const char *hex : NODE_REMOTE_MANAGEMENT_ALLOWED) {
                RNS::Bytes hash;
                hash.assignHex(hex);
                allowed.insert(hash);
            }
            RNS::Transport::remote_management_allowed(allowed);
            Serial.printf("[node] remote management allowed for %u identit%s\n", (unsigned)allowed.size(),
                          allowed.size() == 1 ? "y" : "ies");
        }

        reticulum.transport_enabled(true);
        reticulum.probe_destination_enabled(true);
        reticulum.remote_management_enabled(true);
        reticulum.start();

        // Clock, right after start() so no Transport state is timestamped in the old
        // timebase. Blocking here (at most REPLY_TIMEOUT_MS) is fine, the loop is not
        // running yet; afterwards clockLoop() keeps it in step without blocking.
        FEED_WDT(); // the NTP request blocks up to Ntp::REPLY_TIMEOUT_MS
        if (eth.hasIp() && ntp.request()) {
            lastClockSync = millis();
            uint64_t unixMs = 0;
            while (ntp.pending()) {
                if (ntp.poll(unixMs)) {
                    clockApply(unixMs, "boot");
                    break;
                }
                delay(5);
            }
            if (!clockValid)
                Serial.println("[clock] no NTP answer at boot, will keep trying");
        }

        // Application identity. With an SE050 on the board both private halves live in the
        // chip: X25519 (objId MTID) for decrypt, Ed25519 (objId RNSS) for announces, link
        // proofs and packet proofs. Nothing about it touches LittleFS - the identity is
        // rebuilt from the chip's public keys on every boot, and the hash is the same as
        // long as the chip is. Without a chip, the software identity on LittleFS as before.
        if (se050) {
            node_identity = se050Identity(*se050, SE050::IDENTITY_OBJ, SE050::SIGNING_OBJ);
            if (node_identity)
                Serial.println("[node] application identity keys live in the SE050");
            else
                Serial.println("[node] SE050 present but its keys are not usable, falling back to LittleFS");
        }
        if (!node_identity && RNS::Utilities::OS::file_exists(NODE_IDENTITY_PATH))
            node_identity = RNS::Identity::from_file(NODE_IDENTITY_PATH);
        if (!node_identity) {
            Serial.println("[node] creating application identity");
            node_identity = RNS::Identity();
            node_identity.to_file(NODE_IDENTITY_PATH);
        }
        node_destination = RNS::Destination(node_identity, RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE,
                                            NODE_APP_NAME, NODE_APP_ASPECT);
        // Prove every packet addressed to us so `rnprobe <destination>` from a host round-trips
        // through this node's signing key: the cheapest end-to-end check of the whole stack.
        node_destination.set_proof_strategy(RNS::Type::Destination::PROVE_ALL);
        Serial.printf("[node] identity %s destination %s\n", node_identity.hexhash().c_str(),
                      node_destination.hash().toHex().c_str());
        return true;
    } catch (const std::exception &e) {
        Serial.printf("FATAL: exception during Reticulum setup: %s\n", e.what());
        return false;
    }
}

// USB console: the only thing USB carries besides flashing.
static void handleConsole()
{
#ifdef SE050_ALLOW_ROTATION
    static uint32_t rotateArmed = 0; // millis() when 'R' armed the rotation; '!' confirms
#endif
    while (Serial.available()) {
        switch (Serial.read()) {
        case 'r':
            Serial.println("rebooting");
            Serial.flush();
            rp2040.reboot();
            break;
        case 't': {
            char when[24];
            Ntp::format(RNS::Utilities::OS::ltime(), when, sizeof(when));
            Serial.printf("[clock] now %s (%s), requesting a sync\n", when, clockValid ? "synced" : "never synced");
            lastClockSync = 0; // clockLoop() sends on its next pass
            break;
        }
        case 'i':
            Serial.printf("transport identity: %s\n", RNS::Transport::identity().hexhash().c_str());
            if (node_destination)
                Serial.printf("node destination:   %s\n", node_destination.hash().toHex().c_str());
            break;
        case 'h':
            printHeap("console");
            break;
        case 'o':
            ota.status(Serial);
            break;
        case 'c':
            settings.status(Serial);
            break;
        case 's':
            Serial.printf("[se050] %s\n", se050 ? "present, probe passed at boot" : "absent");
            break;
        case 'p':
            if (se050)
                Serial.printf("[se050] re-probe %s\n", se050->probe() ? "OK" : "FAILED");
            break;
        case 'k': // SCP03 crypto cross-check for tools/scp03_rotate.py (no chip writes)
            if (se050)
                se050->benchScp03Kat();
            break;
#ifdef SE050_ALLOW_ROTATION
        case 'D': // dry run: print the PUT KEY the rotation would send, without sending
            if (se050)
                se050->dryRunRotation();
            break;
        case 'R': // arm the (irreversible) Platform SCP03 rotation
            rotateArmed = millis();
            Serial.println("[se050] ROTATION ARMED (irreversible, spare SE050 only). Send '!' within 5 s.");
            break;
        case '!':
            if (se050 && rotateArmed != 0 && millis() - rotateArmed < 5000) {
                rotateArmed = 0;
                Serial.println("[se050] rotating Platform SCP03 keys...");
                Serial.printf("[se050] rotation %s\n", se050->rotatePlatformKeys() ? "OK" : "FAILED");
            } else {
                Serial.println("[se050] '!' ignored (not armed / timed out); send 'R' first");
            }
            break;
#endif
        // Fault injection for the vault's recovery path (bench only). Follow any of them
        // with `a`: the announce signs in the chip and has to come out signed anyway.
        case 'x': // the chip loses everything: SCP03 state, session, T=1 sequence
#ifdef SE050_ENA_PIN
            Serial.println("[se050] fault: power-cycling the chip via ENA");
            se050PowerCycle();
#else
            Serial.println("[se050] no ENA pin on this carrier, cannot power-cycle the chip");
#endif
            break;
        case 'y': // the chip goes away for good: ENA low and left there (I2C NACKs)
#ifdef SE050_ENA_PIN
            Serial.println("[se050] fault: chip powered off via ENA, left off");
            digitalWrite(SE050_ENA_PIN, LOW);
#else
            Serial.println("[se050] no ENA pin on this carrier");
#endif
            break;
        case 'Y': { // with or without the last resort, to see both behaviours
#ifdef SE050_ENA_PIN
            static bool lastResort = true;
            lastResort = !lastResort;
            if (se050)
                se050->onPowerCycle(lastResort ? se050PowerCycle : nullptr);
            Serial.printf("[se050] power-cycle last resort %s\n", lastResort ? "enabled" : "disabled");
#endif
            break;
        }
        case 'X': // host and chip disagree about the SCP03 counter
            if (se050)
                se050->faultInject('c');
            break;
        case 'Z': // host names a session the chip does not have
            if (se050)
                se050->faultInject('s');
            break;
        case 'e':
            eth.report();
            if (tcp)
                Serial.printf("[tcp] %s reconnects=%lu\n", tcp->connected() ? "connected" : "disconnected",
                              (unsigned long)tcp->reconnects());
            if (lora)
                Serial.printf("[lora] %s rx=%lu tx=%lu last rssi %.1f snr %.1f\n",
                              lora->online() ? "online" : "offline", (unsigned long)lora->rxFrames(),
                              (unsigned long)lora->txFrames(), lora->lastRssi(), lora->lastSnr());
            break;
        case 'a':
            announceNow("console", true);
            break;
#ifdef ARDUINO_ARCH_RP2040
        case 'W': { // the positive control: stall loop() past the window without feeding
            const uint32_t stallMs = NODE_WATCHDOG_TIMEOUT_MS > 0 ? NODE_WATCHDOG_TIMEOUT_MS + 4000 : 12000;
            Serial.printf("[wdt] stalling %lu ms without feeding: an armed watchdog reboots the node now\n",
                          (unsigned long)stallMs);
            Serial.flush();
            for (uint32_t t0 = millis(); millis() - t0 < stallMs;) {
            }
            Serial.println("[wdt] survived the stall: the watchdog is NOT armed");
            break;
        }
#endif
        case 'f': {
            fs::FSInfo info;
            if (LittleFS.info(info))
                Serial.printf("littlefs total=%llu used=%llu\n", info.totalBytes, info.usedBytes);
            break;
        }
        case 'l': {
            fs::Dir dir = LittleFS.openDir("/");
            while (dir.next())
                Serial.printf("  %s%s %u\n", dir.fileName().c_str(), dir.isDirectory() ? "/" : "", dir.fileSize());
            break;
        }
        default:
            break;
        }
    }
}

void setup()
{
    pinMode(LED_PIN, OUTPUT);
    Serial.begin(115200);
    // Headless node: wait a little for the USB console, then carry on regardless.
    for (uint32_t t0 = millis(); !Serial && millis() - t0 < 3000;)
        delay(50);

    Serial.println();
    Serial.println("rp2350_reticulum_eth_node phase 4 (Ethernet OTA + config API)");
    printHeap("boot");
#ifdef ARDUINO_ARCH_RP2040
    // The reason register survives the reset. A timer trip with the enable magic in scratch[4] is
    // the watchdog catching a stalled loop(); a trip without it is our own rp2040.reboot().
    if (watchdog_enable_caused_reboot())
        Serial.println("[wdt] REBOOTED BY THE WATCHDOG: the previous run stopped feeding it");
    else if (watchdog_caused_reboot())
        Serial.println("[boot] software reboot (rp2040.reboot: console, OTA, low heap)");
    else
        Serial.println("[boot] power-on or RUN-pin reset");
#endif
    FEED_WDT(); // a watchdog left armed by a previous trip is already ticking through this setup()

    // Before anything that could fail: this is where a trial boot is counted and, if it is
    // one too many, where the previous image is put back.
    ota.begin();
    // Before reticulumSetup(), which reads the rnsd address and the LoRa power from here.
    settings.begin();

    {
        EthernetLink::Address addr;
        addr.staticOnly = settings.ipStaticOnly();
        addr.hasStatic = settings.staticAddress(addr.ip, addr.subnet, addr.gateway, addr.dns);
        FEED_WDT(); // DHCP blocks in one call; start it with the whole window
        eth.begin(addr);
    }
    settings.onIpSource([]() { return EthernetLink::sourceName(eth.source()); });
    FEED_WDT();
    se050Setup();

    RNS::loglevel(RNS::LOG_DEBUG);

    FEED_WDT();
    if (!reticulumSetup()) {
        // Blink fast forever: something below Reticulum is broken.
        for (;;) {
            digitalWrite(LED_PIN, !digitalRead(LED_PIN));
            delay(100);
        }
    }

    // The radio exists now, so a power change over HTTP has somewhere to land.
    settings.onTxPower([](int8_t dbm) { return lora && lora->setTxPowerDbm(dbm); });
    otaRegisterRoutes();
    nodeSettingsRegisterRoutes();

    Serial.printf("transport identity: %s\n", RNS::Transport::identity().hexhash().c_str());
    printHeap("after start");

    // Bring-up is done: arm the watchdog. From here loop() has to feed it, so a hang below
    // Reticulum, a wedged SPI transaction or a stuck interface reboots the node instead of
    // leaving it dark in the switch. NODE_WATCHDOG_TIMEOUT_MS=0 disables it (bench).
#ifdef ARDUINO_ARCH_RP2040
    if (NODE_WATCHDOG_TIMEOUT_MS > 0) {
        rp2040.wdt_begin(NODE_WATCHDOG_TIMEOUT_MS);
        Serial.printf("[wdt] armed, %d ms (window now %lu ms)\n", NODE_WATCHDOG_TIMEOUT_MS,
                      (unsigned long)watchdog_get_time_remaining_ms());
    } else {
        Serial.println("[wdt] disabled (see node_config.h)");
    }
#endif
    announcePending = true;
}

#ifdef ARDUINO_ARCH_RP2040
// Smallest window left when loop() came round to feed, since the last [loop] line: the margin the
// slowest pass (an SE050 signature, a store compaction, an OTA upload) leaves before a trip.
static uint32_t wdtMinRemainingMs = UINT32_MAX;
#endif

void loop()
{
#ifdef ARDUINO_ARCH_RP2040
    if (NODE_WATCHDOG_TIMEOUT_MS > 0) {
        uint32_t remaining = watchdog_get_time_remaining_ms();
        if (remaining < wdtMinRemainingMs)
            wdtMinRemainingMs = remaining;
    }
#endif
    FEED_WDT();
    checkLowHeap();
    eth.loop();
    reticulum.loop();
    handleConsole();
    clockLoop();
    ota.loop();
    httpApi.loop();
    nodeSettingsLoop();

    // An OTA'd image has proved itself once the chip answered its probe and an announce went
    // out signed by it: the vault works and the node is reachable. Until then it is on trial.
#ifndef NODE_OTA_TEST_NO_CONFIRM // bench image that never confirms, to watch the rollback happen
    if (ota.pending() && se050 && announcedOnce)
        ota.confirm("SE050 probe passed and announce sent");
#endif

    // First announce a few seconds after the node is reachable (TCP link up, or LoRa alone on a
    // LoRa-only build), then every settings.announceIntervalS() (PUT /config retunes it live).
    static uint32_t onlineSince = 0;
    bool online = (tcp && tcp->connected()) || (!tcp && lora && lora->online());
    if (!online) {
        onlineSince = 0;
    } else if (onlineSince == 0) {
        onlineSince = millis();
        announcePending = true;
    } else if (announcePending && millis() - onlineSince >= 5000) {
        announceNow("link up");
    } else if (millis() - lastAnnounce >= settings.announceIntervalS() * 1000) {
        announceNow("periodic");
    }

    static uint32_t lastReport = 0;
    if (millis() - lastReport >= 10000) {
        lastReport = millis();
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
        printHeap("loop");
#ifdef ARDUINO_ARCH_RP2040
        if (NODE_WATCHDOG_TIMEOUT_MS > 0) {
            Serial.printf("[wdt] min window left at feed %lu ms of %d\n", (unsigned long)wdtMinRemainingMs,
                          NODE_WATCHDOG_TIMEOUT_MS);
            wdtMinRemainingMs = UINT32_MAX;
        }
#endif
    }
}
