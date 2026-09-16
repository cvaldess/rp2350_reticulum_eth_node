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
static void se050Setup()
{
#ifdef SE050_ENA_PIN
    // ENA pulse = the only power-on reset the SE050 gets after an MCU reset (see the
    // Meshtastic port). Only on carriers with the ENA hardware mod.
    pinMode(SE050_ENA_PIN, OUTPUT);
    digitalWrite(SE050_ENA_PIN, LOW);
    delay(5);
    digitalWrite(SE050_ENA_PIN, HIGH);
    delay(250);
#endif
    Wire.setSDA(I2C_SDA);
    Wire.setSCL(I2C_SCL);
    Wire.begin();
    Wire.setClock(100000);
    se050 = new SE050(Wire, SE050_I2C_ADDR);
    if (!se050->probe()) {
        Serial.println("[se050] not available on this board");
        delete se050;
        se050 = nullptr;
    }
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

static void announceNow(const char *why)
{
    if (!node_destination)
        return;
    try {
        node_destination.announce(RNS::bytesFromString(NODE_ANNOUNCE_APP_DATA));
        lastAnnounce = millis();
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
    while (Serial.available()) {
        switch (Serial.read()) {
        case 'r':
            Serial.println("rebooting");
            Serial.flush();
            rp2040.reboot();
            break;
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
            announceNow("console");
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
