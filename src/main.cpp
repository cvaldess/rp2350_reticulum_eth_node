// rp2350_reticulum_eth_node — phase 0: does microReticulum live on the RP2350?
//
// No interfaces yet. This probe proves the parts every later phase depends on:
//   - the library builds and links on arduino-pico with exceptions enabled
//   - LittleFS works through the microStore adapter (src/PicoLittleFSFileSystem.h)
//   - the Crypto RNG is seeded from the RP2350 TRNG before any key is generated
//   - Transport creates a transport identity, persists it, and reloads it after a reboot
// Success criterion: the "transport identity" hash printed at boot is identical after a reset.

#include <Arduino.h>
#include <microReticulum.h>
#include <microStore/FileSystem.h>

#include "PicoLittleFSFileSystem.h"
#include "Rp2350Trng.h"
#include "board_pins.h"

static RNS::Reticulum reticulum({RNS::Type::NONE});
static microStore::Adapters::PicoLittleFSFileSystem filesystem;
static Rp2350Trng trng;

// microReticulum's log sink writes through newlib's _write().
extern "C" int _write(int file, char *ptr, int len)
{
    (void)file;
    int wrote = Serial.write(ptr, len);
    Serial.flush();
    return wrote;
}

static void printHeap(const char *tag)
{
    Serial.printf("[%s] heap total=%d free=%d\n", tag, rp2040.getTotalHeap(), rp2040.getFreeHeap());
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

        reticulum.transport_enabled(true);
        reticulum.probe_destination_enabled(true);
        reticulum.remote_management_enabled(true);
        reticulum.start();
        return true;
    } catch (const std::exception &e) {
        Serial.printf("FATAL: exception during Reticulum setup: %s\n", e.what());
        return false;
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
    Serial.println("rp2350_reticulum_eth_node phase 0 probe");
    printHeap("boot");

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
}

void loop()
{
    reticulum.loop();

    static uint32_t lastReport = 0;
    if (millis() - lastReport >= 10000) {
        lastReport = millis();
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
        printHeap("loop");
    }
}
