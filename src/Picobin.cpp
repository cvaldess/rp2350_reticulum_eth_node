#include "Picobin.h"

#include "boot_pubkeys.h"
#include <string.h>

// boot/picobin.h is not on arduino-pico's sketch include path; these are the spec constants
// (RP2350 datasheet 5.9, pico-sdk boot_picobin_headers).
#define PICOBIN_BLOCK_MARKER_START 0xffffded3u
#define PICOBIN_BLOCK_MARKER_END 0xab123579u
#define PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE 0x42u
#define PICOBIN_BLOCK_ITEM_1BS_VERSION 0x48u
#define PICOBIN_BLOCK_ITEM_SIGNATURE 0x09u
#define PICOBIN_BLOCK_ITEM_2BS_LAST (0x80u | 0x7fu)

namespace Picobin {

static constexpr size_t FIRST_BLOCK_SEARCH = 4096; // where the bootrom looks for the first header
static constexpr size_t MAX_BLOCK_BYTES = 384;     // larger IMAGE_DEFs are ignored by the bootrom
static constexpr int MAX_BLOCKS = 16;

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

struct Block {
    size_t off = 0;    // header offset within the image
    int32_t link = 0;  // relative offset of the next header
    size_t imageType = 0, version = 0, signature = 0; // item offsets, 0 if absent
    bool imageDef = false;
};

// Parses the block at image[off]; false if it is not well formed.
static bool parse(const uint8_t *image, size_t len, size_t off, Block &b)
{
    if (off + 4 > len || rd32(image + off) != PICOBIN_BLOCK_MARKER_START)
        return false;
    b = Block();
    b.off = off;
    size_t p = off + 4;
    bool first = true;
    while (true) {
        if (p + 4 > len || p - off > MAX_BLOCK_BYTES)
            return false;
        uint8_t b0 = image[p];
        uint8_t type = b0 & 0x7f;
        size_t size = (b0 & 0x80) ? (image[p + 1] | ((size_t)image[p + 2] << 8)) : image[p + 1];
        if (first) {
            b.imageDef = (type == PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE);
            first = false;
        }
        if (type == PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE)
            b.imageType = p;
        else if (type == PICOBIN_BLOCK_ITEM_1BS_VERSION)
            b.version = p;
        else if (type == PICOBIN_BLOCK_ITEM_SIGNATURE && size == 33)
            b.signature = p;
        if (type == (PICOBIN_BLOCK_ITEM_2BS_LAST & 0x7f)) {
            p += 4;
            break;
        }
        if (size == 0)
            return false;
        p += 4 * size;
    }
    if (p + 8 > len)
        return false;
    b.link = (int32_t)rd32(image + p);
    return rd32(image + p + 4) == PICOBIN_BLOCK_MARKER_END;
}

bool inspect(const uint8_t *image, size_t len, Signed &sig)
{
    sig = Signed();
    size_t first = SIZE_MAX;
    Block b;
    for (size_t off = 0; off + 4 <= len && off < FIRST_BLOCK_SEARCH; off += 4) {
        if (rd32(image + off) == PICOBIN_BLOCK_MARKER_START && parse(image, len, off, b)) {
            first = off;
            break;
        }
    }
    if (first == SIZE_MAX)
        return false;
    // The loop must close on the first block; the bootrom boots the last IMAGE_DEF in it.
    Block last;
    bool haveDef = false;
    size_t off = first;
    for (int i = 0; i < MAX_BLOCKS; i++) {
        if (!parse(image, len, off, b))
            return false;
        if (b.imageDef) {
            last = b;
            haveDef = true;
        }
        int64_t next = (int64_t)off + b.link;
        if (next == (int64_t)first)
            break;
        if (next < 0 || next >= (int64_t)len || i == MAX_BLOCKS - 1)
            return false;
        off = (size_t)next;
    }
    if (!haveDef || !last.signature)
        return true;
    sig.blockAddr = (uint32_t)(uintptr_t)(image + last.off);
    if (last.version) {
        sig.minor = image[last.version + 4] | (image[last.version + 5] << 8);
        sig.major = image[last.version + 6] | (image[last.version + 7] << 8);
    }
    memcpy(sig.pubkey, image + last.signature + 4, sizeof(sig.pubkey));
    for (int k = 0; k < NODE_BOOT_PUBKEY_COUNT; k++)
        if (memcmp(sig.pubkey, NODE_BOOT_PUBKEYS[k], 64) == 0)
            sig.keyIndex = k;
    return true;
}

} // namespace Picobin
