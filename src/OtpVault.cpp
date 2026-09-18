#include "OtpVault.h"

#include <Arduino.h>
#include <boot/bootrom_constants.h>
#include <hardware/regs/addressmap.h>
#include <hardware/regs/otp.h>
#include <hardware/regs/otp_data.h>
#include <hardware/regs/sysinfo.h>
#include <hardware/structs/otp.h>
#include <hardware/structs/sysinfo.h>
#include <pico/bootrom.h>
#include <string.h>

namespace OtpVault {

static constexpr uint32_t RAW_MASK = 0x00ffffff;

static int access(uint16_t row, void *buf, uint32_t len, bool write, bool ecc)
{
    otp_cmd_t cmd;
    cmd.flags = (uint32_t)row | (write ? OTP_CMD_WRITE_BITS : 0) | (ecc ? OTP_CMD_ECC_BITS : 0);
    return rom_func_otp_access((uint8_t *)buf, len, cmd);
}

int readEcc(uint16_t row, uint16_t *out, unsigned n)
{
    return access(row, out, 2 * n, false, true);
}

int readRaw(uint16_t row, uint32_t *out, unsigned n)
{
    return access(row, out, 4 * n, false, false);
}

int writeEcc(uint16_t row, const uint16_t *in, unsigned n)
{
    return access(row, (void *)in, 2 * n, true, true);
}

int writeRaw(uint16_t row, const uint32_t *in, unsigned n)
{
    return access(row, (void *)in, 4 * n, true, false);
}

const char *errorName(int rc)
{
    switch (rc) {
    case BOOTROM_OK:
        return "ok";
    case BOOTROM_ERROR_NOT_PERMITTED:
        return "not permitted (page lock)";
    case BOOTROM_ERROR_INVALID_ARG:
        return "invalid argument";
    case BOOTROM_ERROR_INVALID_ADDRESS:
        return "invalid address";
    case BOOTROM_ERROR_UNSUPPORTED_MODIFICATION:
        return "unsupported modification (would clear a bit)";
    case BOOTROM_ERROR_PRECONDITION_NOT_MET:
        return "precondition not met";
    case BOOTROM_ERROR_INVALID_STATE:
        return "invalid state";
    default:
        return "bootrom error";
    }
}

const char *seedStateName(SeedState s)
{
    switch (s) {
    case SeedState::Blank:
        return "blank";
    case SeedState::Present:
        return "present";
    case SeedState::Corrupt:
        return "CORRUPT";
    default:
        return "unreadable";
    }
}

SeedState readSeed(uint8_t seed[32])
{
    uint32_t raw[SEED_ROWS], chaff[SEED_ROWS];
    if (readRaw(SEED_ROW, raw, SEED_ROWS) != BOOTROM_OK || readRaw(CHAFF_ROW, chaff, SEED_ROWS) != BOOTROM_OK)
        return SeedState::Unreadable;
    bool blank = true;
    for (unsigned i = 0; i < SEED_ROWS; i++)
        if ((raw[i] & RAW_MASK) || (chaff[i] & RAW_MASK))
            blank = false;
    if (blank)
        return SeedState::Blank;
    for (unsigned i = 0; i < SEED_ROWS; i++)
        if (((raw[i] ^ chaff[i]) & RAW_MASK) != RAW_MASK)
            return SeedState::Corrupt;
    uint16_t rows[SEED_ROWS];
    if (readEcc(SEED_ROW, rows, SEED_ROWS) != BOOTROM_OK)
        return SeedState::Unreadable;
    memcpy(seed, rows, 32);
    memset(rows, 0, sizeof(rows));
    return SeedState::Present;
}

void softLockSeedPage()
{
    otp_hw->sw_lock[SEED_PAGE] = (OTP_SW_LOCK0_SEC_VALUE_INACCESSIBLE << OTP_SW_LOCK0_SEC_LSB) |
                                 (OTP_SW_LOCK0_NSEC_VALUE_INACCESSIBLE << OTP_SW_LOCK0_NSEC_LSB);
}

bool seedPageSoftLocked()
{
    return ((otp_hw->sw_lock[SEED_PAGE] & OTP_SW_LOCK0_SEC_BITS) >> OTP_SW_LOCK0_SEC_LSB) ==
           OTP_SW_LOCK0_SEC_VALUE_INACCESSIBLE;
}

// Lock words are world-readable in hardware, but the bootrom API refuses them once their own
// page is soft-locked; the memory-mapped raw alias answers regardless.
static uint32_t rawRowAlias(uint16_t row)
{
    return *(volatile uint32_t *)(OTP_DATA_RAW_BASE + 4u * row) & RAW_MASK;
}

static uint8_t voteByte(uint32_t raw)
{
    uint8_t b0 = raw & 0xff, b1 = (raw >> 8) & 0xff, b2 = (raw >> 16) & 0xff;
    return (b0 & b1) | (b0 & b2) | (b1 & b2);
}

bool seedPageHardLocked()
{
    return (voteByte(rawRowAlias(OTP_DATA_PAGE32_LOCK1_ROW)) & OTP_DATA_PAGE32_LOCK1_LOCK_S_BITS) != 0;
}

// Bitwise majority of three redundant raw rows (BOOT_FLAGS0/1 are "RBIT-3").
static uint32_t vote3(uint16_t row)
{
    uint32_t r[3] = {0, 0, 0};
    readRaw(row, r, 3);
    return ((r[0] & r[1]) | (r[0] & r[2]) | (r[1] & r[2])) & RAW_MASK;
}

static bool anyNonZeroEcc(uint16_t row, unsigned n)
{
    uint16_t v[16] = {0};
    if (n > 16 || readEcc(row, v, n) != BOOTROM_OK)
        return false;
    for (unsigned i = 0; i < n; i++)
        if (v[i])
            return true;
    return false;
}

void status(Status &s)
{
    uint32_t crit = otp_hw->critical;
    s.secureBoot = crit & OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS;
    s.debugDisabled = crit & OTP_CRITICAL_DEBUG_DISABLE_BITS;
    s.secureDebugDisabled = crit & OTP_CRITICAL_SECURE_DEBUG_DISABLE_BITS;
    s.riscvDisabled = crit & OTP_CRITICAL_RISCV_DISABLE_BITS;
    s.glitchDetector = crit & OTP_CRITICAL_GLITCH_DETECTOR_ENABLE_BITS;
    s.bootFlags0 = vote3(OTP_DATA_BOOT_FLAGS0_ROW);
    uint32_t bf1 = vote3(OTP_DATA_BOOT_FLAGS1_ROW);
    s.keyValid = bf1 & OTP_DATA_BOOT_FLAGS1_KEY_VALID_BITS;
    s.keyInvalid = (bf1 & OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS) >> 8;
    s.page1Lock1 = rawRowAlias(OTP_DATA_PAGE1_LOCK1_ROW);
    s.page2Lock1 = rawRowAlias(OTP_DATA_PAGE2_LOCK1_ROW);
    s.seedPageLock1 = rawRowAlias(OTP_DATA_PAGE32_LOCK1_ROW);
    s.chipRevision = (sysinfo_hw->chip_id & SYSINFO_CHIP_ID_REVISION_BITS) >> SYSINFO_CHIP_ID_REVISION_LSB;
    s.bootromVersion = *(const volatile uint8_t *)0x13;
    s.bootkey0 = anyNonZeroEcc(OTP_DATA_BOOTKEY0_0_ROW, 16);
    s.bootkey1 = anyNonZeroEcc(OTP_DATA_BOOTKEY1_0_ROW, 16);
}

#ifdef NODE_OTP_PROVISION
bool writeSeed(const uint8_t seed[32], const char **why)
{
    uint8_t have[32];
    SeedState st = readSeed(have);
    if (st != SeedState::Blank) {
        *why = st == SeedState::Present ? "seed page already written" : seedStateName(st);
        return false;
    }
    uint16_t rows[SEED_ROWS];
    memcpy(rows, seed, 32);
    int rc = writeEcc(SEED_ROW, rows, SEED_ROWS);
    memset(rows, 0, sizeof(rows));
    if (rc != BOOTROM_OK) {
        *why = errorName(rc);
        return false;
    }
    // The complement is of the whole 24-bit row as programmed (data + ECC + BRP), so read
    // what the bootrom actually wrote rather than encoding it again here.
    uint32_t raw[SEED_ROWS], chaff[SEED_ROWS];
    if ((rc = readRaw(SEED_ROW, raw, SEED_ROWS)) != BOOTROM_OK) {
        *why = errorName(rc);
        return false;
    }
    for (unsigned i = 0; i < SEED_ROWS; i++)
        chaff[i] = (~raw[i]) & RAW_MASK;
    if ((rc = writeRaw(CHAFF_ROW, chaff, SEED_ROWS)) != BOOTROM_OK) {
        *why = errorName(rc);
        return false;
    }
    st = readSeed(have);
    bool same = st == SeedState::Present && memcmp(have, seed, 32) == 0;
    memset(have, 0, sizeof(have));
    if (!same) {
        *why = st == SeedState::Present ? "read-back differs from what was written" : seedStateName(st);
        return false;
    }
    return true;
}

bool lockSeedPage(const char **why)
{
    // Once the keys were derived this boot the page is soft-locked and unreadable; that is
    // the provisioned state too. Only a page that reads blank or corrupt is refused.
    uint8_t seed[32];
    SeedState st = readSeed(seed);
    memset(seed, 0, sizeof(seed));
    bool provisioned = st == SeedState::Present || (st == SeedState::Unreadable && seedPageSoftLocked());
    if (!provisioned) {
        *why = "seed page is not provisioned";
        return false;
    }
    // One byte, three copies: S read-only (1), NS inaccessible (3), PicoBoot inaccessible (3).
    const uint8_t lockByte = (OTP_DATA_PAGE32_LOCK1_LOCK_S_VALUE_READ_ONLY << OTP_DATA_PAGE32_LOCK1_LOCK_S_LSB) |
                             (OTP_DATA_PAGE32_LOCK1_LOCK_NS_VALUE_INACCESSIBLE << OTP_DATA_PAGE32_LOCK1_LOCK_NS_LSB) |
                             (OTP_DATA_PAGE32_LOCK1_LOCK_BL_VALUE_INACCESSIBLE << OTP_DATA_PAGE32_LOCK1_LOCK_BL_LSB);
    uint32_t want = (uint32_t)lockByte | ((uint32_t)lockByte << 8) | ((uint32_t)lockByte << 16);
    uint32_t have = 0;
    readRaw(OTP_DATA_PAGE32_LOCK1_ROW, &have, 1);
    if ((have & RAW_MASK) == want) {
        *why = "already locked";
        return false;
    }
    int rc = writeRaw(OTP_DATA_PAGE32_LOCK1_ROW, &want, 1);
    if (rc != BOOTROM_OK) {
        *why = errorName(rc);
        return false;
    }
    have = 0;
    readRaw(OTP_DATA_PAGE32_LOCK1_ROW, &have, 1);
    if ((have & RAW_MASK) != want) {
        *why = "lock row read-back differs";
        return false;
    }
    return true;
}
#endif

} // namespace OtpVault
