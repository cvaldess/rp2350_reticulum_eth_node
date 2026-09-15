// RP2350 hardware TRNG as an entropy source for the rweather/Crypto RNG used by microReticulum.
//
// Crypto's RNG.cpp only knows the SAM3X, nRF52, ESP8266 and ESP32 TRNGs; on any other MCU it
// compiles with "#warning no hardware random number source" and, without a seed in EEPROM,
// starts from the begin() tag alone. Every identity and ephemeral link key would then be
// derived from a predictable state. This source is registered with RNG.addNoiseSource() so
// RNG.loop() keeps stirring fresh TRNG words, and seedOnce() stirs a full 256-bit block
// before anything cryptographic runs.
//
// rp2040.hwrand32() wraps the SDK's get_rand_32(): on the RP2350 that is the hardware TRNG
// (on the RP2040 it is a ROSC-based approximation; this project only targets the RP2350).
#pragma once

#include <Arduino.h>
#include <NoiseSource.h>
#include <RNG.h>

class Rp2350Trng : public NoiseSource
{
  public:
    // Credit is in bits of entropy per byte delivered; the TRNG output is full-entropy.
    static constexpr unsigned CREDIT_PER_BYTE = 8;

    bool calibrating() const override { return false; }

    // Called from RNG.loop(): feed a few fresh words each pass.
    void stir() override
    {
        uint32_t words[4];
        for (auto &w : words)
            w = rp2040.hwrand32();
        output(reinterpret_cast<const uint8_t *>(words), sizeof(words), sizeof(words) * CREDIT_PER_BYTE);
    }

    // Stir 32 bytes with full credit so RNG.available(32) is true before the first key is made.
    static void seedOnce()
    {
        uint32_t words[8];
        for (auto &w : words)
            w = rp2040.hwrand32();
        RNG.stir(reinterpret_cast<const uint8_t *>(words), sizeof(words), sizeof(words) * CREDIT_PER_BYTE);
    }
};
