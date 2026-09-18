#include "OtpProvision.h"

#ifdef NODE_OTP_PROVISION

#include "OtpVault.h"
#include "Picobin.h"
#include "boot_pubkeys.h"
#include "se050/SE050.h"
#include <SHA256.h>
#include <boot/bootrom_constants.h>
#include <hardware/regs/addressmap.h>
#include <hardware/regs/otp_data.h>
#include <hardware/watchdog.h>
#include <string.h>

extern uint8_t _FS_start;

static constexpr uint32_t RAW_MASK = 0x00ffffff;

static bool readLine(Stream &io, char *buf, size_t cap, uint32_t timeoutMs)
{
    size_t n = 0;
    uint32_t last = millis();
    while (millis() - last < timeoutMs) {
        watchdog_update();
        if (!io.available()) {
            delay(1);
            continue;
        }
        char c = io.read();
        last = millis();
        if (c == '\r')
            continue;
        if (c == '\n')
            break;
        if (n + 1 < cap)
            buf[n++] = c;
    }
    buf[n] = 0;
    return n > 0;
}

static bool confirmed(const char *line)
{
    size_t n = strlen(line);
    return n > 0 && line[n - 1] == '!';
}

static void hexRows16(Stream &io, const char *label, uint16_t row, unsigned n)
{
    uint16_t v[16] = {0};
    int rc = OtpVault::readEcc(row, v, n);
    io.printf("  %-10s rows 0x%03x..0x%03x: ", label, row, row + n - 1);
    if (rc != BOOTROM_OK) {
        io.printf("%s\n", OtpVault::errorName(rc));
        return;
    }
    for (unsigned i = 0; i < n; i++)
        io.printf("%02x%02x", v[i] & 0xff, v[i] >> 8); // as the bootrom's byte buffer sees them
    io.println();
}

// The 32-byte fingerprint in BOOTKEYn as the bootrom reads it: 16 ECC rows into a byte buffer.
static bool readBootkey(int n, uint8_t out[32])
{
    uint16_t v[16];
    if (OtpVault::readEcc(OTP_DATA_BOOTKEY0_0_ROW + 16 * n, v, 16) != BOOTROM_OK)
        return false;
    memcpy(out, v, 32);
    return true;
}

static void fingerprint(int keyIndex, uint8_t out[32])
{
    SHA256 h;
    h.reset();
    h.update(NODE_BOOT_PUBKEYS[keyIndex], 64);
    h.finalize(out, 32);
}

// Which burned BOOTKEY slot (0/1) holds the fingerprint of our key keyIndex, -1 if none.
static int burnedSlotFor(int keyIndex)
{
    uint8_t want[32], have[32];
    fingerprint(keyIndex, want);
    for (int slot = 0; slot < 2; slot++)
        if (readBootkey(slot, have) && memcmp(have, want, 32) == 0)
            return slot;
    return -1;
}

static void info(Stream &io)
{
    OtpVault::Status s;
    OtpVault::status(s);
    io.printf("[otp] chip revision A%u, bootrom version byte 0x%02x (A2=E16/E20/E24 open; A4 fixes them)\n",
              s.chipRevision, s.bootromVersion);
    io.printf("[otp] CRITICAL: secure_boot=%d debug_disable=%d secure_debug_disable=%d riscv_disable=%d glitch=%d\n",
              s.secureBoot, s.debugDisabled, s.secureDebugDisabled, s.riscvDisabled, s.glitchDetector);
    io.printf("[otp] BOOT_FLAGS0=0x%06lx (uart_boot_off=%d wdt_scratch_off=%d usb_msd_off=%d picoboot_off=%d)\n",
              (unsigned long)s.bootFlags0, !!(s.bootFlags0 & OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_UART_BOOT_BITS),
              !!(s.bootFlags0 & OTP_DATA_BOOT_FLAGS0_DISABLE_WATCHDOG_SCRATCH_BITS),
              !!(s.bootFlags0 & OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_USB_MSD_IFC_BITS),
              !!(s.bootFlags0 & OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_USB_PICOBOOT_IFC_BITS));
    io.printf("[otp] BOOT_FLAGS1: key_valid=0x%x key_invalid=0x%x; BOOTKEY0 %s, BOOTKEY1 %s\n", s.keyValid, s.keyInvalid,
              s.bootkey0 ? "written" : "blank", s.bootkey1 ? "written" : "blank");
    hexRows16(io, "BOOTKEY0", OTP_DATA_BOOTKEY0_0_ROW, 16);
    hexRows16(io, "BOOTKEY1", OTP_DATA_BOOTKEY1_0_ROW, 16);
    for (int k = 0; k < NODE_BOOT_PUBKEY_COUNT; k++) {
        uint8_t fp[32];
        fingerprint(k, fp);
        io.printf("  our key %d fingerprint: ", k);
        for (int i = 0; i < 32; i++)
            io.printf("%02x", fp[i]);
        io.printf(" -> burned in slot %d\n", burnedSlotFor(k));
    }
    io.printf("[otp] locks (LOCK1 raw, byte x3: S=bits1:0 NS=3:2 BL=5:4): page1=0x%06lx page2=0x%06lx seed page %u=0x%06lx\n",
              (unsigned long)s.page1Lock1, (unsigned long)s.page2Lock1, OtpVault::SEED_PAGE,
              (unsigned long)s.seedPageLock1);
    uint8_t seed[32];
    OtpVault::SeedState st = OtpVault::readSeed(seed);
    memset(seed, 0, sizeof(seed));
    bool soft = OtpVault::seedPageSoftLocked();
    io.printf("[otp] seed page: %s%s\n",
              (st == OtpVault::SeedState::Unreadable && soft) ? "present (keys derived this boot)" : OtpVault::seedStateName(st),
              soft ? ", soft-locked until reset" : ", not soft-locked");
    Picobin::Signed img;
    Picobin::inspect((const uint8_t *)XIP_BASE, (uint32_t)&_FS_start - XIP_BASE, img);
    if (img.blockAddr)
        io.printf("[otp] running image: signed, version %u.%u, key %d (%s)\n", img.major, img.minor, img.keyIndex,
                  img.keyIndex >= 0 ? "ours" : "NOT ours");
    else
        io.println("[otp] running image: NOT signed");
    io.printf("[otp] SE050 keys in use: %s\n", se050 ? SE050::keySourceName(se050->keys()) : "(no SE050)");
}

static void writeSeed(Stream &io)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; i += 4) {
        uint32_t w = rp2040.hwrand32();
        memcpy(seed + i, &w, 4);
    }
    const char *why = "";
    bool ok = OtpVault::writeSeed(seed, &why);
    if (ok) {
        SHA256 h;
        uint8_t fp[32];
        h.reset();
        h.update(seed, 32);
        h.finalize(fp, 32);
        io.print("[otp] seed written and read back OK; SHA-256 of the seed (not the seed): ");
        for (int i = 0; i < 32; i++)
            io.printf("%02x", fp[i]);
        io.println();
        SE050::forgetOtpKeys();
    } else {
        io.printf("[otp] seed NOT written: %s\n", why);
    }
    memset(seed, 0, sizeof(seed));
}

// Sets bits in n consecutive raw rows (critical flags: 8 copies; boot flags: 3 copies).
static bool orRaw(Stream &io, const char *what, uint16_t row, unsigned n, uint32_t bits)
{
    uint32_t cur[8] = {0};
    if (n > 8)
        return false;
    int rc = OtpVault::readRaw(row, cur, n);
    if (rc != BOOTROM_OK) {
        io.printf("[otp] %s: read failed: %s\n", what, OtpVault::errorName(rc));
        return false;
    }
    uint32_t want[8];
    bool change = false;
    for (unsigned i = 0; i < n; i++) {
        want[i] = (cur[i] | bits) & RAW_MASK;
        if (want[i] != (cur[i] & RAW_MASK))
            change = true;
    }
    if (!change) {
        io.printf("[otp] %s: already set\n", what);
        return true;
    }
    rc = OtpVault::writeRaw(row, want, n);
    if (rc != BOOTROM_OK) {
        io.printf("[otp] %s: write failed: %s\n", what, OtpVault::errorName(rc));
        return false;
    }
    uint32_t back[8] = {0};
    OtpVault::readRaw(row, back, n);
    for (unsigned i = 0; i < n; i++)
        if ((back[i] & RAW_MASK) != want[i]) {
            io.printf("[otp] %s: row 0x%03x reads 0x%06lx, wanted 0x%06lx\n", what, row + i, (unsigned long)back[i],
                      (unsigned long)want[i]);
            return false;
        }
    io.printf("[otp] %s: written, %u rows read back OK\n", what, n);
    return true;
}

static bool parseHex32(const char *s, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return false;
        out[i] = v;
    }
    return true;
}

static void writeBootkey(Stream &io, int slot, const char *hex)
{
    uint8_t fp[32];
    if (strlen(hex) < 64 || !parseHex32(hex, fp)) {
        io.println("[otp] usage: Ok<0|1> <64 hex chars of the fingerprint>!");
        return;
    }
    // Only a fingerprint of one of OUR public keys goes into a slot: a typo here is a brick.
    int ours = -1;
    for (int k = 0; k < NODE_BOOT_PUBKEY_COUNT; k++) {
        uint8_t mine[32];
        fingerprint(k, mine);
        if (memcmp(mine, fp, 32) == 0)
            ours = k;
    }
    if (ours < 0) {
        io.println("[otp] refused: that fingerprint is not one of include/boot_pubkeys.h");
        return;
    }
    uint8_t have[32];
    if (readBootkey(slot, have)) {
        bool blank = true;
        for (int i = 0; i < 32; i++)
            if (have[i])
                blank = false;
        if (!blank) {
            io.printf("[otp] refused: BOOTKEY%d is not blank\n", slot);
            return;
        }
    }
    uint16_t rows[16];
    memcpy(rows, fp, 32);
    int rc = OtpVault::writeEcc(OTP_DATA_BOOTKEY0_0_ROW + 16 * slot, rows, 16);
    if (rc != BOOTROM_OK) {
        io.printf("[otp] BOOTKEY%d write failed: %s\n", slot, OtpVault::errorName(rc));
        return;
    }
    io.printf("[otp] BOOTKEY%d written with our key %d, read back: %s\n", slot, ours,
              burnedSlotFor(ours) == slot ? "MATCHES" : "DIFFERS (!)");
}

static void keyValid(Stream &io)
{
    OtpVault::Status s;
    OtpVault::status(s);
    if (!s.bootkey0 || !s.bootkey1) {
        io.println("[otp] refused: burn BOOTKEY0 and BOOTKEY1 first (Ok0/Ok1)");
        return;
    }
    if (burnedSlotFor(0) != 0 || burnedSlotFor(1) != 1) {
        io.println("[otp] refused: the burned fingerprints do not match our keys 0 and 1");
        return;
    }
    // Slots 2 and 3 stay open until the signed image has booted under secure boot (Ox): a
    // wrongly encoded fingerprint could still be fixed from BOOTSEL through a spare slot.
    orRaw(io, "BOOT_FLAGS1 KEY_VALID=0011", OTP_DATA_BOOT_FLAGS1_ROW, 3, 0x3u);
}

static void keyInvalid(Stream &io)
{
    OtpVault::Status s;
    OtpVault::status(s);
    if (!s.secureBoot) {
        io.println("[otp] refused: enable secure boot first (OS) and prove the signed image boots");
        return;
    }
    orRaw(io, "BOOT_FLAGS1 KEY_INVALID=1100 (slots 2-3 closed for good)", OTP_DATA_BOOT_FLAGS1_ROW, 3, 0xcu << 8);
}

static void secureBoot(Stream &io)
{
    OtpVault::Status s;
    OtpVault::status(s);
    if (s.secureBoot) {
        io.println("[otp] secure boot is already enabled");
        return;
    }
    if (!(s.keyValid & 0x1)) {
        io.println("[otp] refused: KEY_VALID does not cover slot 0 (Ov first)");
        return;
    }
    Picobin::Signed img;
    Picobin::inspect((const uint8_t *)XIP_BASE, (uint32_t)&_FS_start - XIP_BASE, img);
    if (!img.blockAddr || img.keyIndex < 0) {
        io.println("[otp] refused: the running image is not signed with one of our keys; it would not boot again");
        return;
    }
    int slot = burnedSlotFor(img.keyIndex);
    if (slot < 0 || !((s.keyValid >> slot) & 1)) {
        io.printf("[otp] refused: the running image's key %d is not burned+valid in a BOOTKEY slot\n", img.keyIndex);
        return;
    }
    io.printf("[otp] running image signed with key %d = BOOTKEY%d (valid); enabling secure boot\n", img.keyIndex, slot);
    orRaw(io, "CRIT1 SECURE_BOOT_ENABLE (8 rows)", OTP_DATA_CRIT1_ROW, 8, OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS);
    io.println("[otp] reboot now ('r'): the bootrom must accept the signed image before anything else is burned");
}

static void lockdown(Stream &io)
{
    OtpVault::Status s;
    OtpVault::status(s);
    if (!s.secureBoot) {
        io.println("[otp] refused: enable secure boot first (OS) and prove the signed image boots");
        return;
    }
    // CRIT0 (RISCV_DISABLE) lives in page 0, factory read-only: not ours to set. Secure boot
    // already forces the Arm cores (datasheet 13.4), and BOOTSEL then lists ARM only.
    bool ok = orRaw(io, "CRIT1 DEBUG_DISABLE+SECURE_DEBUG_DISABLE (8 rows)", OTP_DATA_CRIT1_ROW, 8,
                    OTP_DATA_CRIT1_DEBUG_DISABLE_BITS | OTP_DATA_CRIT1_SECURE_DEBUG_DISABLE_BITS);
    // UART boot and OTP boot are unused boot paths; the watchdog-scratch reboot is E20's lever.
    ok = orRaw(io, "BOOT_FLAGS0 DISABLE_BOOTSEL_UART_BOOT+DISABLE_OTP_BOOT+DISABLE_WATCHDOG_SCRATCH (3 rows)",
               OTP_DATA_BOOT_FLAGS0_ROW, 3,
               OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_UART_BOOT_BITS | OTP_DATA_BOOT_FLAGS0_DISABLE_OTP_BOOT_BITS |
                   OTP_DATA_BOOT_FLAGS0_DISABLE_WATCHDOG_SCRATCH_BITS) &&
         ok;
    io.printf("[otp] lockdown %s; takes effect at the next reset\n", ok ? "written" : "INCOMPLETE");
}

static void lockBootPages(Stream &io)
{
    OtpVault::Status s;
    OtpVault::status(s);
    if (!s.secureBoot || !s.debugDisabled || !(s.keyInvalid & 0xc)) {
        io.println("[otp] refused: this is the last step, after OS, Ox and Od");
        return;
    }
    // Pages 1 (boot flags, critical rows) and 2 (boot keys): read-only for PicoBoot, so nobody
    // with a USB cable can add, revoke or invalidate anything from BOOTSEL. Secure stays
    // read-write on purpose: only our signed firmware runs as Secure, and it keeps the ability
    // to revoke a key or set a flag later. Non-secure is already read-only from the factory.
    const uint8_t b = (OTP_DATA_PAGE1_LOCK1_LOCK_NS_VALUE_READ_ONLY << OTP_DATA_PAGE1_LOCK1_LOCK_NS_LSB) |
                      (OTP_DATA_PAGE1_LOCK1_LOCK_BL_VALUE_READ_ONLY << OTP_DATA_PAGE1_LOCK1_LOCK_BL_LSB);
    uint32_t bits = (uint32_t)b | ((uint32_t)b << 8) | ((uint32_t)b << 16);
    orRaw(io, "PAGE1_LOCK1 NS/BL read-only", OTP_DATA_PAGE1_LOCK1_ROW, 1, bits);
    orRaw(io, "PAGE2_LOCK1 NS/BL read-only", OTP_DATA_PAGE2_LOCK1_ROW, 1, bits);
}

void otpProvisionConsole(Stream &io)
{
    char line[96];
    if (!readLine(io, line, sizeof(line), 3000)) {
        io.println("[otp] O<cmd>[args][!]: i info | b bootsel | s! seed | l! lock seed page | w soft-lock now | "
                   "k0/k1 <fp>! bootkey | v! keys valid | S! secure boot | x! slots 2-3 invalid | d! lockdown | "
                   "p! lock pages 1-2");
        return;
    }
    char cmd = line[0];
    const char *arg = line + 1;
    while (*arg == ' ')
        arg++;
    bool bang = confirmed(line);
    switch (cmd) {
    case 'i':
        info(io);
        break;
    case 'w':
        OtpVault::softLockSeedPage();
        io.printf("[otp] seed page soft-locked: %s\n", OtpVault::seedPageSoftLocked() ? "yes" : "no");
        break;
    case 's':
        if (!bang) {
            io.println("[otp] Os! writes a random seed into the blank seed page (irreversible)");
            break;
        }
        writeSeed(io);
        break;
    case 'l': {
        if (!bang) {
            io.println("[otp] Ol! hard-locks the seed page: S read-only, NS + PicoBoot inaccessible (irreversible)");
            break;
        }
        const char *why = "";
        io.printf("[otp] seed page lock: %s%s\n", OtpVault::lockSeedPage(&why) ? "written and read back OK" : "NOT written: ",
                  why);
        break;
    }
    case 'k': {
        int slot = (arg[0] == '0') ? 0 : (arg[0] == '1') ? 1 : -1;
        if (slot < 0 || !bang) {
            io.println("[otp] Ok<0|1> <fingerprint hex64>! burns a boot key fingerprint (irreversible)");
            break;
        }
        char hex[80];
        strncpy(hex, arg + 1, sizeof(hex) - 1);
        hex[sizeof(hex) - 1] = 0;
        char *p = hex;
        while (*p == ' ')
            p++;
        char *e = strchr(p, '!');
        if (e)
            *e = 0;
        writeBootkey(io, slot, p);
        break;
    }
    case 'v':
        if (!bang) {
            io.println("[otp] Ov! marks BOOTKEY0+1 valid (irreversible)");
            break;
        }
        keyValid(io);
        break;
    case 'x':
        if (!bang) {
            io.println("[otp] Ox! marks slots 2+3 invalid, so no key can ever be added (irreversible)");
            break;
        }
        keyInvalid(io);
        break;
    case 'b':
        io.println("[otp] rebooting into BOOTSEL for picotool; `picotool reboot` comes back");
        io.flush();
        delay(100);
        rp2040.rebootToBootloader();
        break;
    case 'S':
        if (!bang) {
            io.println("[otp] OS! enables secure boot (irreversible: only images signed with a burned key boot)");
            break;
        }
        secureBoot(io);
        break;
    case 'd':
        if (!bang) {
            io.println("[otp] Od! disables debug (SWD), UART boot, OTP boot and the watchdog-scratch reboot");
            break;
        }
        lockdown(io);
        break;
    case 'p':
        if (!bang) {
            io.println("[otp] Op! makes OTP pages 1-2 read-only for everyone (no more keys or flags, ever)");
            break;
        }
        lockBootPages(io);
        break;
    default:
        io.printf("[otp] unknown sub-command '%c'\n", cmd);
    }
}

#endif // NODE_OTP_PROVISION
