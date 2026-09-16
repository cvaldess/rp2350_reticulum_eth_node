// rp2350_reticulum_eth_node — phase 2: Reticulum transport node bridging LoRa and Ethernet.
//
// Phase 0 proved the stack lives on the RP2350 (identity persists, TRNG-seeded RNG).
// Phase 1 added the W5500 and a TCPClientInterface to an rnsd on the LAN.
// Phase 2 adds the E22 LoRa interface; a NODE_DISABLE_TCP build is the LoRa-only peer.
// Each node announces an application destination so the hosts can see it exists.

#include <Arduino.h>
#include <microReticulum.h>
#include <microStore/FileSystem.h>

#include "EthernetLink.h"
#include "LoRaInterface.h"
#include "Ntp.h"
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
    uint32_t interval = (clockValid ? NODE_NTP_INTERVAL_S : NODE_NTP_RETRY_S) * 1000u;
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
        tcp = new TCPClientInterface("TCPClientInterface", parseIp(RNS_TCP_TARGET_HOST), RNS_TCP_TARGET_PORT);
        tcp_interface = tcp;
        tcp_interface.mode(RNS::Type::Interface::MODE_FULL);
        RNS::Transport::register_interface(tcp_interface);
        tcp_interface.start();
#endif

        LoRaInterface::Params lp = {LORA_FREQUENCY_MHZ,   LORA_BANDWIDTH_KHZ,    LORA_SPREADING_FACTOR,
                                    LORA_CODING_RATE,     LORA_PREAMBLE_SYMBOLS, LORA_TX_POWER_DBM};
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
    Serial.println("rp2350_reticulum_eth_node phase 2");
    printHeap("boot");

    eth.begin();
    se050Setup();

    RNS::loglevel(RNS::LOG_DEBUG);

    if (!reticulumSetup()) {
        // Blink fast forever: something below Reticulum is broken.
        for (;;) {
            digitalWrite(LED_PIN, !digitalRead(LED_PIN));
            delay(100);
        }
    }

    Serial.printf("transport identity: %s\n", RNS::Transport::identity().hexhash().c_str());
    printHeap("after start");
    announcePending = true;
}

void loop()
{
    eth.loop();
    reticulum.loop();
    handleConsole();
    clockLoop();

    // First announce a few seconds after the node is reachable (TCP link up, or LoRa alone on a
    // LoRa-only build), then every NODE_ANNOUNCE_INTERVAL_S.
    static uint32_t onlineSince = 0;
    bool online = (tcp && tcp->connected()) || (!tcp && lora && lora->online());
    if (!online) {
        onlineSince = 0;
    } else if (onlineSince == 0) {
        onlineSince = millis();
        announcePending = true;
    } else if (announcePending && millis() - onlineSince >= 5000) {
        announceNow("link up");
    } else if (millis() - lastAnnounce >= (uint32_t)NODE_ANNOUNCE_INTERVAL_S * 1000) {
        announceNow("periodic");
    }

    static uint32_t lastReport = 0;
    if (millis() - lastReport >= 10000) {
        lastReport = millis();
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
        printHeap("loop");
    }
}
