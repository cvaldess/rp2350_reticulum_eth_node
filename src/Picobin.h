// The RP2350 bootrom's image metadata (datasheet 5.9): the block loop at the start of the flash
// image, and whether the IMAGE_DEF it boots is the signed one tools/seal.py appends. Read-only;
// the bootrom is what enforces the signature once secure boot is on, this just reports it.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace Picobin {

struct Signed {
    uint32_t blockAddr = 0;  // flash address of the signed IMAGE_DEF, 0 if the image is unsigned
    uint16_t major = 0, minor = 0;
    uint8_t pubkey[64] = {0};
    int keyIndex = -1;  // index into NODE_BOOT_PUBKEYS, -1 if the key is not ours
};

// Walks the running image's block loop (image = XIP_BASE, len = sketch area). False if there is
// no closed loop; sig.blockAddr stays 0 when the last IMAGE_DEF carries no SIGNATURE item.
bool inspect(const uint8_t *image, size_t len, Signed &sig);

} // namespace Picobin
