// The RP2350's OTP as the node's vault (docs/secure_boot.md).
//
// One page (64 rows x 16 bits) holds a per-device 32-byte seed the SCP03 keys derive from:
// the seed in rows 0..15 with ECC, its bitwise complement (raw 24-bit, ECC bits included) in
// rows 32..47. Rows i and 32+i share OTP bit cells, so a stored value and its complement make
// every cell pair {0,1}/{1,0} and an FIB/PVC image of the array cannot tell them apart
// (datasheet 13.8, "chaff"). The page is hard-locked Secure read-only, Non-secure and PicoBoot
// inaccessible (picotool cannot read it), and the firmware soft-locks it for everyone after
// deriving the keys, until the next reset.
//
// Reads and writes go through the bootrom's otp_access API (datasheet 5.4.8.21): it applies
// the page permissions, computes ECC on writes and corrects on reads.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace OtpVault {

constexpr uint16_t SEED_PAGE = 32;
constexpr uint16_t SEED_ROW = SEED_PAGE * 64; // 0x800
constexpr uint16_t SEED_ROWS = 16;            // 32 bytes, 16 bits per row
constexpr uint16_t CHAFF_ROW = SEED_ROW + 32; // 0x820: complement of rows 0x800..0x80f

enum class SeedState { Blank, Present, Corrupt, Unreadable };

// Reads the seed. Present = both halves check out; Blank = the page was never written;
// Corrupt = the complement rows disagree; Unreadable = the bootrom refused (locked).
SeedState readSeed(uint8_t seed[32]);
const char *seedStateName(SeedState s);

// Secure and Non-secure inaccessible until the next reset. Call once the keys are derived.
void softLockSeedPage();
bool seedPageSoftLocked();
// PAGE32_LOCK1 in OTP already advances the Secure lock (lockSeedPage() was run). A lock word
// is only writable while its page's Secure lock is still read-write, so this must come before
// any soft lock on a board that is still being provisioned.
bool seedPageHardLocked();

// What the hardware decoded from the critical rows at boot (OTP CRITICAL register).
struct Status {
    bool secureBoot, debugDisabled, secureDebugDisabled, riscvDisabled, glitchDetector;
    uint8_t keyValid, keyInvalid; // BOOT_FLAGS1 (3-way vote)
    uint32_t bootFlags0;          // BOOT_FLAGS0 (3-way vote)
    uint32_t page1Lock1, page2Lock1, seedPageLock1; // raw lock rows (24 bits, 3 copies of a byte)
    uint8_t chipRevision;         // SYSINFO CHIP_ID.REVISION (A2 = 2)
    uint8_t bootromVersion;       // byte at ROM 0x13 (A4 reports a newer bootrom than A3)
    bool bootkey0, bootkey1;      // any row of the fingerprint non-zero
};
void status(Status &s);

// Raw access for the provisioning console (NODE_OTP_PROVISION). ECC rows: 16-bit values; raw
// rows: 24-bit values. Return a bootrom error code (0 = BOOTROM_OK).
int readEcc(uint16_t row, uint16_t *out, unsigned n);
int readRaw(uint16_t row, uint32_t *out, unsigned n);
int writeEcc(uint16_t row, const uint16_t *in, unsigned n);
int writeRaw(uint16_t row, const uint32_t *in, unsigned n);
const char *errorName(int rc);

#ifdef NODE_OTP_PROVISION
// Writes seed + complement into a blank page and reads both back. why explains a refusal.
bool writeSeed(const uint8_t seed[32], const char **why);
// PAGE32_LOCK1 := Secure read-only, Non-secure inaccessible, PicoBoot inaccessible.
bool lockSeedPage(const char **why);
#endif

} // namespace OtpVault
