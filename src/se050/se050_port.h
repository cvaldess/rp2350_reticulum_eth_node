// Glue that lets the SE050 driver from the Meshtastic fork compile unchanged here.
//
// The driver expects Meshtastic's configuration.h (HAS_SE050, ARCH_RP2040), its LOG_* macros
// and HardwareRNG::fill() for the SCP03 host challenge. This header supplies equivalents:
// logging goes to the USB console with an [SE050] prefix, and the challenge comes from the
// RP2350 TRNG.
#pragma once

#include <Arduino.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifndef HAS_SE050
#define HAS_SE050 1
#endif
#define ARCH_RP2040 1

inline void se050Log(const char *level, const char *fmt, ...)
{
    char line[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    Serial.printf("[%s] %s\n", level, line);
}

#define LOG_DEBUG(...) se050Log("DBG", __VA_ARGS__)
#define LOG_INFO(...) se050Log("INF", __VA_ARGS__)
#define LOG_WARN(...) se050Log("WRN", __VA_ARGS__)
#define LOG_ERROR(...) se050Log("ERR", __VA_ARGS__)

// Host challenge for SCP03 INITIALIZE UPDATE: 8 bytes from the hardware TRNG.
inline bool se050PortRandom(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = rp2040.hwrand32();
        for (size_t k = 0; k < 4 && i + k < len; k++)
            out[i + k] = (uint8_t)(w >> (8 * k));
    }
    return true;
}
