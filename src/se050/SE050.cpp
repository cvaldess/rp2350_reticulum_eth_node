// Ported from the Meshtastic fork of this hardware (src/security/SE050.{h,cpp}), where it was
// brought up and measured on the SE050E2 of this carrier. Only the glue changed: logging, the
// RNG for the host challenge and the build flags live in se050_port.h.
#include "SE050.h"

#if defined(HAS_SE050)

#include "se050_port.h"
#include <AES.h>
#include <Arduino.h>
#include <Curve25519.h>
#include <Ed25519.h>
#include <SHA256.h>
#include <string.h>
#include "../OtpVault.h"

SE050 *se050 = nullptr;

#ifdef ARCH_RP2040
#include <hardware/watchdog.h>
#include <pico/time.h>
#define SE050_FEED_WATCHDOG() watchdog_update()
// A hardware busy-wait, not delay(). delay() runs the framework's yield hook,
// which hands control to whatever else is pending - in the middle of a
// transaction, that is exactly what must not happen. The wait is short and the
// watchdog is fed explicitly around it.
#define SE050_WAIT_MS(ms) busy_wait_us_32((ms)*1000u)
#define SE050_WAIT_US(us) busy_wait_us_32(us)
#else
#define SE050_FEED_WATCHDOG() ((void)0)
#define SE050_WAIT_MS(ms) delay(ms)
#define SE050_WAIT_US(us) delayMicroseconds(us)
#endif

namespace
{
constexpr uint8_t NAD_HOST_TO_SE = 0x5A;
constexpr uint8_t NAD_SE_TO_HOST = 0xA5; // also the SOF we resynchronise on
constexpr uint8_t PCB_S_REQ = 0xC0;
constexpr uint8_t PCB_S_RSP = 0xE0;
constexpr uint8_t S_INTF_RESET = 0x0F;
constexpr uint8_t S_WTX = 0x03; // wait-time extension request/response

// The answer to a fresh key generation can take seconds (compute plus an NVM
// write), so the poll window has to be generous. Not-ready simply NACKs, which
// returns immediately, so a normal answer still exits after a couple of passes.
constexpr int POLL_ATTEMPTS = 400;
constexpr uint32_t POLL_INTERVAL_MS = 10;

// How many wait-time extensions to grant before declaring the chip stuck.
constexpr int MAX_WTX_GRANTS = 20;
} // namespace

// CRC-16 as T1oI2C uses it: reflected polynomial 0x8408, init and xorout 0xFFFF,
// and the result byte-swapped (UM11225), appended big-endian.
uint16_t SE050::crc(const uint8_t *data, size_t len)
{
    uint16_t cal = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        cal ^= data[i];
        for (int bit = 0; bit < 8; bit++)
            cal = (cal & 1) ? ((cal >> 1) ^ 0x8408) : (cal >> 1);
    }
    cal ^= 0xFFFF;
    return (uint16_t)(((cal & 0xFF) << 8) | ((cal >> 8) & 0xFF));
}

// Whether a call arrived while a transaction is parked mid-flight. Refusing is
// the only safe answer: the caller would share buffers and an SCP03 counter with
// work that has not finished, and the chip would see two interleaved commands on
// one channel.
bool SE050::reentered(const char *what)
{
    if (!waiting)
        return false;
    LOG_ERROR("SE050: %s re-entered while a transaction is in flight, refusing", what);
    return true;
}

size_t SE050::xfer(const uint8_t *tx, size_t txLen, uint8_t *rx, size_t rxCap)
{
    if (rxCap < 3)
        return 0;

    bus.beginTransmission(address);
    bus.write(tx, txLen);
    if (bus.endTransmission() != 0) {
        LOG_DEBUG("SE050: write of %u bytes was not acked", (unsigned)txLen);
        return 0;
    }

    // Read in two phases, the way NXP's own PAL does it: poll for the 3-byte
    // header until the start-of-frame shows up, then read exactly the body the
    // header announced. A single large fixed read does not survive a slow answer.
    uint8_t header[3];
    bool haveHeader = false;
    waiting = true;
    const int attempts = POLL_ATTEMPTS * (int)(POLL_INTERVAL_MS * 1000) / (int)pollIntervalUs; // same 4 s ceiling whatever the interval
    for (int attempt = 0; attempt < attempts && !haveHeader; attempt++) {
        SE050_WAIT_US(pollIntervalUs);
        SE050_FEED_WATCHDOG(); // this loop can run for seconds
        if (bus.requestFrom(address, sizeof(header)) == sizeof(header)) {
            for (size_t i = 0; i < sizeof(header); i++)
                header[i] = bus.read();
            haveHeader = (header[0] == NAD_SE_TO_HOST);
        }
    }
    waiting = false;
    if (!haveHeader)
        return 0;

    rx[0] = header[0];
    rx[1] = header[1];
    rx[2] = header[2];

    size_t body = (size_t)header[2] + 2; // INF plus the two CRC bytes
    if (3 + body > rxCap) {
        LOG_WARN("SE050: response of %u bytes does not fit in %u", (unsigned)(3 + body), (unsigned)rxCap);
        return 0;
    }
    if (body > 0) {
        if (bus.requestFrom(address, body) != body) {
            LOG_DEBUG("SE050: body read failed (LEN=%u)", (unsigned)header[2]);
            return 0;
        }
        for (size_t i = 0; i < body; i++)
            rx[3 + i] = bus.read();
    }

    // Validate the CRC so a desynchronised read is discarded rather than parsed.
    // Retransmitting resynchronises the SE050, so the caller can simply retry.
    size_t total = 3 + body;
    if (total >= 5) {
        uint16_t want = crc(rx, total - 2);
        if (rx[total - 2] != ((want >> 8) & 0xFF) || rx[total - 1] != (want & 0xFF)) {
            LOG_DEBUG("SE050: response CRC mismatch, discarding frame");
            return 0;
        }
    }
    return total;
}

bool SE050::reset(uint8_t *atrOut, size_t atrCap, size_t *atrLen)
{
    uint8_t frame[5] = {NAD_HOST_TO_SE, (uint8_t)(PCB_S_REQ | S_INTF_RESET), 0x00, 0, 0};
    uint16_t c = crc(frame, 3);
    frame[3] = (c >> 8) & 0xFF;
    frame[4] = c & 0xFF;

    const uint8_t expected = (uint8_t)(PCB_S_RSP | S_INTF_RESET); // 0xEF

    // Retransmitting the interface reset is also how a stream that went out of
    // step is recovered, so a failed attempt is worth repeating.
    for (int attempt = 0; attempt < 4; attempt++) {
        uint8_t rx[128];
        size_t n = xfer(frame, sizeof(frame), rx, sizeof(rx));
        if (n >= 3 && rx[1] == expected) {
            size_t len = rx[2];
            if (3 + len > n)
                len = n - 3;
            if (atrOut && atrLen) {
                size_t copy = len < atrCap ? len : atrCap;
                memcpy(atrOut, &rx[3], copy);
                *atrLen = copy;
            }
            seq = 0;
            return true;
        }
        LOG_DEBUG("SE050: interface reset attempt %d gave %s", attempt + 1, n == 0 ? "no valid frame" : "an unexpected PCB");
    }
    return false;
}

uint16_t SE050::statusWord(const uint8_t *resp, int len)
{
    return len >= 2 ? (uint16_t)((resp[len - 2] << 8) | resp[len - 1]) : 0xFFFF;
}

int SE050::transceive(const uint8_t *apdu, size_t apduLen, uint8_t *resp, size_t respCap)
{
    if (reentered("transceive"))
        return -1;

    uint8_t *const frame = txFrame;
    // LEN (below) is a single byte (UM11225), tighter than the txFrame capacity check alone -
    // without this, 256-283 bytes would pass the capacity check and then silently wrap into a
    // wrong LEN.
    if (apduLen > 255 || 5 + apduLen > sizeof(txFrame))
        return -1;

    frame[0] = NAD_HOST_TO_SE;
    frame[1] = (uint8_t)((seq & 1) << 6); // I-block: bit7=0, N(S) in bit6
    frame[2] = (uint8_t)apduLen;          // LEN, single byte (UM11225)
    memcpy(&frame[3], apdu, apduLen);
    uint16_t c = crc(frame, 3 + apduLen);
    frame[3 + apduLen] = (c >> 8) & 0xFF;
    frame[4 + apduLen] = c & 0xFF;

    uint8_t *const rx = rxFrame;
    size_t n = xfer(frame, 5 + apduLen, rx, sizeof(rxFrame));
    seq ^= 1;
    if (n == 0)
        return -1;

    // WTX: the SE050 asks for more time (S-block request). Grant it and re-read.
    //
    // Bounded, because a chip that keeps asking would otherwise spin here forever,
    // and xfer feeds the watchdog on every pass - so the board would hang silently
    // rather than reset. Each grant already allows a full poll window, so twenty of
    // them is far more patience than any real operation needs.
    for (int grants = 0; n >= 2 && rx[1] == (uint8_t)(PCB_S_REQ | S_WTX); grants++) {
        if (grants >= MAX_WTX_GRANTS) {
            LOG_ERROR("SE050: chip kept asking for more time, giving up");
            return -1;
        }
        uint8_t wtx = rx[2] >= 1 ? rx[3] : 1;
        uint8_t w[6] = {NAD_HOST_TO_SE, (uint8_t)(PCB_S_RSP | S_WTX), 0x01, wtx, 0, 0};
        uint16_t wc = crc(w, 4);
        w[4] = (wc >> 8) & 0xFF;
        w[5] = wc & 0xFF;
        n = xfer(w, sizeof(w), rx, sizeof(rxFrame));
        if (n == 0)
            return -1;
    }

    size_t len = rx[2];
    if (3 + len > n)
        len = n > 3 ? n - 3 : 0;
    if (len > respCap)
        len = respCap;
    memcpy(resp, &rx[3], len);
    return (int)len;
}

bool SE050::selectApplet()
{
    // SELECT (by name) the SE05x IoT applet - AID A0000003965453000000010300000000.
    static const uint8_t SEL[] = {0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x03, 0x96, 0x54,
                                  0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00};
    uint8_t r[64];
    int n = transceive(SEL, sizeof(SEL), r, sizeof(r));
    uint16_t sw = statusWord(r, n);
    if (sw != 0x9000) {
        LOG_ERROR("SE050: applet SELECT returned SW=%04x", sw);
        return false;
    }
    if (n >= 3)
        LOG_INFO("SE050: IoT applet selected, version %d.%d.%d", r[0], r[1], r[2]);
    return true;
}

bool SE050::open()
{
    if (!reset())
        return false;
    return selectApplet();
}

// --- PlatformSCP03 -------------------------------------------------------
//
// Factory keys for OEF 0x0001A921 (SE050E). These are the default keys NXP ships
// in its middleware, so they are public and confer no secrecy - they only open
// the transport channel the SE050 requires before it will do key agreement.
static const uint8_t SCP_KEY_ENC[16] = {0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7,
                                        0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64};
static const uint8_t SCP_KEY_MAC[16] = {0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0,
                                        0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B};
// Factory DEK for the same OEF (AN12436). The running channel never needed it - only ENC/MAC
// derive the session keys - but PUT KEY encrypts the new key components under the current DEK.
static const uint8_t SCP_KEY_DEK[16] = {0x67, 0x02, 0xDA, 0xC3, 0x09, 0x42, 0xB2, 0xC8,
                                        0x5E, 0x7F, 0x47, 0xB4, 0x2C, 0xED, 0x4E, 0x7F};
static constexpr uint8_t SCP03_KEYVER = 0x0B;

// AES-CMAC (RFC 4493). The bundled Crypto library only exposes OMAC in its EAX
// form, which prepends a tag block, so the plain construction is done here.
void SE050::cmac(const uint8_t key[16], const uint8_t *data, size_t len, uint8_t out[16])
{
    AES128 aes;
    aes.setKey(key, 16);

    // Subkeys: L = E(K, 0), K1 = dbl(L), K2 = dbl(K1); dbl left-shifts and, on
    // carry out of the top bit, folds in the 0x87 field polynomial.
    uint8_t k1[16] = {0}, k2[16] = {0};
    aes.encryptBlock(k1, k1);
    for (int round = 0; round < 2; round++) {
        uint8_t *k = round == 0 ? k1 : k2;
        if (round == 1)
            memcpy(k2, k1, 16);
        uint8_t carry = k[0] & 0x80;
        for (int i = 0; i < 15; i++)
            k[i] = (uint8_t)((k[i] << 1) | (k[i + 1] >> 7));
        k[15] = (uint8_t)(k[15] << 1);
        if (carry)
            k[15] ^= 0x87;
    }

    uint8_t state[16] = {0};
    size_t full = len ? (len - 1) / 16 : 0; // blocks processed before the last one
    for (size_t b = 0; b < full; b++) {
        for (int i = 0; i < 16; i++)
            state[i] ^= data[b * 16 + i];
        aes.encryptBlock(state, state);
    }

    // Last block: XOR K1 if it is exactly full, otherwise pad with 0x80 00.. and
    // XOR K2 instead.
    uint8_t last[16] = {0};
    size_t rem = len - full * 16;
    if (len > 0 && rem == 16) {
        memcpy(last, &data[full * 16], 16);
        for (int i = 0; i < 16; i++)
            last[i] ^= k1[i];
    } else {
        memcpy(last, &data[full * 16], rem);
        last[rem] = 0x80;
        for (int i = 0; i < 16; i++)
            last[i] ^= k2[i];
    }
    for (int i = 0; i < 16; i++)
        state[i] ^= last[i];
    aes.encryptBlock(out, state);
}

// SCP03 key derivation (SP800-108 in counter mode, CMAC as the PRF).
void SE050::kdf(const uint8_t key[16], uint8_t constant, uint16_t bits, const uint8_t context[16], uint8_t out[16])
{
    uint8_t dd[32];
    memset(dd, 0, 11);
    dd[11] = constant;
    dd[12] = 0x00;
    dd[13] = (uint8_t)(bits >> 8);
    dd[14] = (uint8_t)(bits & 0xFF);
    dd[15] = 0x01;
    memcpy(&dd[16], context, 16);
    cmac(key, dd, sizeof(dd), out);
}

void SE050::sessionKeys(const uint8_t context[16])
{
    // Factory keys until a rotation switched the chip (and this driver) to per-device keys.
    const uint8_t *enc = usingRotatedKeys ? curEnc : SCP_KEY_ENC;
    const uint8_t *mac = usingRotatedKeys ? curMac : SCP_KEY_MAC;
    kdf(enc, 0x04, 128, context, scp.senc);
    kdf(mac, 0x06, 128, context, scp.smac);
    kdf(mac, 0x07, 128, context, scp.srmac);
}

// Cryptograms are the first 8 bytes of a 64-bit derivation off S-MAC.
void SE050::cryptogram(uint8_t constant, const uint8_t context[16], uint8_t out[8])
{
    uint8_t full[16];
    kdf(scp.smac, constant, 64, context, full);
    memcpy(out, full, 8);
}

// C-MAC over MCV || command, updating the MCV to the full CMAC so successive
// commands chain.
void SE050::chainedCmac(const uint8_t *cmd, size_t len, uint8_t mac[8])
{
    uint8_t buf[16 + 288];
    if (16 + len > sizeof(buf))
        return;
    memcpy(buf, scp.mcv, 16);
    memcpy(&buf[16], cmd, len);
    uint8_t full[16];
    cmac(scp.smac, buf, 16 + len, full);
    memcpy(scp.mcv, full, 16);
    memcpy(mac, full, 8);
}

bool SE050::initializeUpdate(const uint8_t hostChallenge[8], uint8_t cardChallenge[8], uint8_t cardCryptogram[8])
{
    uint8_t iu[] = {0x80,
                    0x50,
                    SCP03_KEYVER,
                    0x00,
                    0x08,
                    hostChallenge[0],
                    hostChallenge[1],
                    hostChallenge[2],
                    hostChallenge[3],
                    hostChallenge[4],
                    hostChallenge[5],
                    hostChallenge[6],
                    hostChallenge[7],
                    0x00};
    uint8_t r[64];
    int n = transceive(iu, sizeof(iu), r, sizeof(r));
    if (statusWord(r, n) != 0x9000 || n < 31) {
        LOG_ERROR("SE050: INITIALIZE UPDATE (keyver=%02x) SW=%04x n=%d", SCP03_KEYVER, statusWord(r, n), n);
        return false;
    }
    // keyDivData(10) || keyInfo(3) || cardChallenge(8) || cardCryptogram(8)
    memcpy(cardChallenge, &r[13], 8);
    memcpy(cardCryptogram, &r[21], 8);
    return true;
}

const char *SE050::keySourceName(KeySource s)
{
    switch (s) {
    case KeySource::Otp:
        return "OTP-derived";
    case KeySource::Bench:
        return "bench-master";
    default:
        return "factory";
    }
}

bool SE050::openSecureChannel()
{
    // The chip only answers to one static key set and there is no persisted flag saying
    // which: try them most-likely first. A provisioned board runs the OTP-derived keys; a
    // bench build may still carry the compile-time master (SE050_ROTATED); a virgin chip
    // holds NXP's factory keys. A miss costs one INITIALIZE UPDATE.
    static const KeySource order[] = {KeySource::Otp, KeySource::Bench, KeySource::Factory};
    for (KeySource src : order) {
        if (src == KeySource::Factory) {
            usingRotatedKeys = false;
        } else {
            if (!deriveKeys(src, curEnc, curMac, curDek))
                continue;
            usingRotatedKeys = true;
        }
        keySource = src;
        if (tryOpenChannel()) {
            if (src != KeySource::Factory)
                LOG_INFO("SE050: channel open with the %s keys", keySourceName(src));
            return true;
        }
    }
    keySource = KeySource::Factory;
    usingRotatedKeys = false;
    return false;
}

bool SE050::tryOpenChannel()
{
    memset(&scp, 0, sizeof(scp));
    // A new channel means the UserID session nested in the old one is gone too;
    // the chip was reset to get here. Leaving the flag set made a re-probe try
    // ReadObject inside a dead session, fail, and then "generate" over an
    // identity that already exists (WriteECKey 6985).
    sessionActive = false;
    identityReady = signingReady = false;

    uint8_t hostChallenge[8];
    if (!se050PortRandom(hostChallenge, sizeof(hostChallenge))) {
        LOG_ERROR("SE050: no entropy source available for the SCP03 host challenge");
        return false;
    }

    uint8_t cardChallenge[8], cardCryptogram[8];
    if (!initializeUpdate(hostChallenge, cardChallenge, cardCryptogram))
        return false;

    memcpy(lastHostChallenge, hostChallenge, 8);
    memcpy(lastCardChallenge, cardChallenge, 8);
    memcpy(lastCardCryptogram, cardCryptogram, 8);

    uint8_t context[16];
    memcpy(context, hostChallenge, 8);
    memcpy(&context[8], cardChallenge, 8);
    sessionKeys(context);

    // If this does not match, the static keys or the KDF are wrong - there is no
    // point continuing, and it is also how the chip authenticates itself to us.
    uint8_t expected[8];
    cryptogram(0x00, context, expected);
    if (memcmp(expected, cardCryptogram, 8) != 0) {
        // Wrong key set for this chip (the usual reason a rotated chip rejects the factory
        // keys), or a broken KDF. openSecureChannel() may retry with the other key set.
        LOG_INFO("SE050: card cryptogram mismatch with the %s keys", keySourceName(keySource));
        return false;
    }

    uint8_t hostCryptogram[8];
    cryptogram(0x01, context, hostCryptogram);

    // EXTERNAL AUTHENTICATE. CLA 0x84 carries the security bit; P1 0x33 asks for
    // C-DEC | C-MAC | R-MAC | R-ENC. Lc covers the cryptogram plus its C-MAC, and
    // the C-MAC chains from the still-zero MCV.
    uint8_t cmd[13];
    cmd[0] = 0x84;
    cmd[1] = 0x82;
    cmd[2] = 0x33;
    cmd[3] = 0x00;
    cmd[4] = 0x10;
    memcpy(&cmd[5], hostCryptogram, 8);

    uint8_t mac[8];
    chainedCmac(cmd, sizeof(cmd), mac);

    uint8_t apdu[sizeof(cmd) + 8];
    memcpy(apdu, cmd, sizeof(cmd));
    memcpy(&apdu[sizeof(cmd)], mac, 8);

    uint8_t r[32];
    int n = transceive(apdu, sizeof(apdu), r, sizeof(r));
    uint16_t sw = statusWord(r, n);
    if (sw != 0x9000) {
        LOG_ERROR("SE050: EXTERNAL AUTHENTICATE SW=%04x - channel not open", sw);
        return false;
    }

    scp.open = true;
    scp.counter = 0; // the first wrapped command increments this to 1
    return true;
}

// --- Secure channel wrapping ---------------------------------------------

void SE050::cbc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out, bool encrypt)
{
    AES128 aes;
    aes.setKey(key, 16);
    uint8_t chain[16];
    memcpy(chain, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        if (encrypt) {
            uint8_t block[16];
            for (int i = 0; i < 16; i++)
                block[i] = in[off + i] ^ chain[i];
            aes.encryptBlock(&out[off], block);
            memcpy(chain, &out[off], 16);
        } else {
            uint8_t cipher[16];
            memcpy(cipher, &in[off], 16);
            aes.decryptBlock(&out[off], cipher);
            for (int i = 0; i < 16; i++)
                out[off + i] ^= chain[i];
            memcpy(chain, cipher, 16);
        }
    }
}

// The encryption IV is AES-ECB(S-ENC, counter block). The counter goes in the low
// bytes big-endian; for a response the top byte of the block is 0x80.
void SE050::encryptionIcv(bool response, uint8_t icv[16])
{
    uint8_t blk[16] = {0};
    blk[12] = (uint8_t)(scp.counter >> 24);
    blk[13] = (uint8_t)(scp.counter >> 16);
    blk[14] = (uint8_t)(scp.counter >> 8);
    blk[15] = (uint8_t)(scp.counter);
    if (response)
        blk[0] = 0x80;
    AES128 aes;
    aes.setKey(scp.senc, 16);
    aes.encryptBlock(icv, blk);
}

int SE050::secureApdu(const uint8_t header[4], const uint8_t *data, int dataLen, bool expectResponse, uint8_t *resp, int respCap,
                      uint16_t *sw)
{
    if (!scp.open || reentered("secureApdu")) {
        *sw = 0xFFFF;
        return -1;
    }

    scp.counter++;

    uint8_t *const enc = encBuf;
    int encLen = 0;
    if (dataLen > 0) {
        uint8_t *const padded = padBuf;
        if ((size_t)dataLen + 16 > sizeof(padBuf)) {
            // scp.counter already advanced for a command that never reached the card, so the
            // host and card ICVs/MCVs can no longer agree - closing the channel here (and at
            // every other exit below that can't confirm the card is still in step) forces the
            // next call to reopen instead of building C-MACs the card will reject forever.
            scp.open = sessionActive = false;
            *sw = 0xFFFF;
            return -1;
        }
        memcpy(padded, data, dataLen);
        padded[dataLen] = 0x80; // SCP03 pads with 80 00 .. to the block size
        encLen = ((dataLen + 1 + 15) / 16) * 16;
        if (encLen + 8 > 255) {
            // Lc (below) is a single ISO7816 short-form byte, tighter than what padBuf alone
            // allows - without this, a payload in the ~240-283 byte range would silently wrap
            // Lc instead of getting rejected here.
            scp.open = sessionActive = false;
            *sw = 0xFFFF;
            return -1;
        }
        memset(&padded[dataLen + 1], 0, encLen - (dataLen + 1));
        uint8_t icv[16];
        encryptionIcv(false, icv);
        cbc(scp.senc, icv, padded, encLen, enc, true);
    }

    uint8_t *const out = apduOut;
    int p = 0;
    out[p++] = (uint8_t)(header[0] | 0x04); // CLA carries the security bit
    out[p++] = header[1];
    out[p++] = header[2];
    out[p++] = header[3];
    out[p++] = (uint8_t)(encLen + 8); // Lc counts the C-MAC too
    memcpy(&out[p], enc, encLen);
    p += encLen;

    uint8_t mac[8];
    chainedCmac(out, p, mac);
    memcpy(&out[p], mac, 8);
    p += 8;
    if (expectResponse)
        out[p++] = 0x00;

    uint8_t *const r = apduIn;
    int n = transceive(out, p, r, sizeof(apduIn));
    if (n < 0) {
        scp.open = sessionActive = false;
        *sw = 0xFFFF;
        return -1;
    }

    // Response is [encrypted data][R-MAC 8][SW 2]. A short frame is the card answering with a
    // bare status word and no R-MAC, which is what it does for an ordinary application error:
    // the 6985 from the idempotent setup steps in identitySession() is one, and so is the failed
    // ReadObject that tells identityEnsure() there is no identity on the chip yet. Both of those
    // commands did travel the secure channel - the card accepted the C-MAC and advanced its
    // counter in step with ours - so the channel is still good and the caller only needs the SW.
    // Closing here regardless made every idempotent step poison the session it was preparing.
    //
    // Only a response with no status word at all, or one saying the secure messaging itself was
    // refused, can leave the two sides disagreeing about the counter.
    if (n < 10) {
        *sw = statusWord(r, n);
        if (n < 2 || *sw == 0x6982 || *sw == 0x6987 || *sw == 0x6988) {
            LOG_WARN("SE050: secure channel closed after a %04x response, it will be reopened", *sw);
            scp.open = sessionActive = false;
        }
        return n >= 2 ? 0 : -1;
    }
    *sw = (uint16_t)((r[n - 2] << 8) | r[n - 1]);

    int encRespLen = n - 10;
    uint8_t *const buf = macBuf;
    if ((size_t)(16 + encRespLen + 2) > sizeof(macBuf)) {
        LOG_ERROR("SE050: response of %d bytes is too long to verify", encRespLen);
        scp.open = sessionActive = false;
        return -1;
    }
    memcpy(buf, scp.mcv, 16); // R-MAC reads the MCV but must not advance it
    memcpy(&buf[16], r, encRespLen);
    buf[16 + encRespLen] = r[n - 2];
    buf[16 + encRespLen + 1] = r[n - 1];
    uint8_t full[16];
    cmac(scp.srmac, buf, 16 + encRespLen + 2, full);
    if (memcmp(full, &r[n - 10], 8) != 0) {
        LOG_ERROR("SE050: R-MAC verification failed");
        scp.open = sessionActive = false;
        return -1;
    }
    if (encRespLen == 0)
        return 0;

    uint8_t icv[16];
    encryptionIcv(true, icv);
    uint8_t *const plain = plainBuf;
    if ((size_t)encRespLen > sizeof(plainBuf))
        return -1;
    cbc(scp.senc, icv, r, encRespLen, plain, false);

    int len = encRespLen; // strip the 80 00 .. padding
    while (len > 0 && plain[len - 1] == 0x00)
        len--;
    if (len > 0 && plain[len - 1] == 0x80)
        len--;
    if (len > respCap)
        len = respCap;
    memcpy(resp, plain, len);
    return len;
}

int SE050::sessionApdu(const uint8_t header[4], const uint8_t *data, int dataLen, bool expectResponse, uint8_t *resp, int respCap,
                       uint16_t *sw)
{
    if (reentered("sessionApdu")) {
        *sw = 0xFFFF;
        return -1;
    }

    uint8_t *const od = sessionBuf;
    int j = 0;
    int innerLc = (dataLen == 0) ? 0 : ((dataLen < 0xFF && !expectResponse) ? 1 : 3);
    int tagLen = 4 + innerLc + dataLen;
    if ((size_t)(14 + tagLen) > sizeof(sessionBuf)) { // session id TLV, TAG_1 header, inner command
        *sw = 0xFFFF;
        return -1;
    }

    od[j++] = 0x10; // TAG_SESSION_ID
    od[j++] = 0x08;
    memcpy(&od[j], sessionId, 8);
    j += 8;
    od[j++] = 0x41; // TAG_1 wraps the inner command
    if (tagLen <= 0x7F) {
        od[j++] = (uint8_t)tagLen;
    } else if (tagLen <= 0xFF) {
        od[j++] = 0x81;
        od[j++] = (uint8_t)tagLen;
    } else {
        od[j++] = 0x82;
        od[j++] = (uint8_t)(tagLen >> 8);
        od[j++] = (uint8_t)tagLen;
    }
    memcpy(&od[j], header, 4);
    j += 4;
    if (dataLen > 0) {
        if (dataLen < 0xFF && !expectResponse) {
            od[j++] = (uint8_t)dataLen;
        } else {
            od[j++] = 0x00;
            od[j++] = (uint8_t)(dataLen >> 8);
            od[j++] = (uint8_t)dataLen;
        }
        memcpy(&od[j], data, dataLen);
        j += dataLen;
    }

    static const uint8_t PROCESS_SESSION_CMD[4] = {0x80, 0x05, 0x00, 0x00};
    return secureApdu(PROCESS_SESSION_CMD, od, j, expectResponse, resp, respCap, sw);
}

// First TLV with tag 0x41, handling BER short and long form lengths.
const uint8_t *SE050::tlv1(const uint8_t *resp, int len, int *valueLen)
{
    *valueLen = 0;
    if (len < 2 || resp[0] != 0x41)
        return nullptr;
    int off, l;
    if (resp[1] == 0x82) {
        l = (resp[2] << 8) | resp[3];
        off = 4;
    } else if (resp[1] == 0x81) {
        l = resp[2];
        off = 3;
    } else {
        l = resp[1];
        off = 2;
    }
    if (off + l > len)
        l = len - off;
    *valueLen = l;
    return &resp[off];
}

void SE050::reverse(const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = in[len - 1 - i];
}

// --- Identity ------------------------------------------------------------

namespace
{
// "MTKY", the mirrored copy of the key Meshtastic already holds in its config.
// Deliberately a different object from MTID so the chip-generated identity, and
// the self-test that leans on it, stay intact.
constexpr uint32_t NODE_KEY_OBJ = 0x4D544B59u;
constexpr uint32_t AUTH_OBJ = 0x20000AAAu; // UserID authenticator the key is bound to
const uint8_t AUTH_PIN[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

void be32(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}
} // namespace

// Curve, authenticator and UserID session: everything an identity object needs
// before it can be created, read or used. Every step is idempotent, so both the
// generate and the import path open with this.
bool SE050::identitySession()
{
    if (!scp.open) {
        LOG_ERROR("SE050: identity needs an open secure channel");
        return false;
    }
    // A session opened earlier is still good: nothing closes it, and asking the
    // chip for a second one while the first is live is not a request it expects.
    if (sessionActive)
        return true;

    uint8_t authId[4];
    be32(AUTH_OBJ, authId);

    uint8_t r[192];
    uint16_t sw = 0;
    int rl, vl;
    const uint8_t *v;

    // Applet 7.x does not ship the Montgomery or the Edwards curve pre-created; the
    // X25519 identity needs the first, the Ed25519 signing key the second. Neither
    // takes curve parameters (AN12413 4.8.2). Idempotent: 6985 just means it exists.
    static const uint8_t CURVES[] = {0x41, 0x40}; // ID_ECC_MONT_DH_25519, ID_ECC_ED_25519
    for (uint8_t curve : CURVES) {
        const uint8_t h[4] = {0x80, 0x01, 0x0B, 0x04};
        uint8_t d[] = {0x41, 0x01, curve};
        secureApdu(h, d, sizeof(d), false, r, sizeof(r), &sw);
        if (sw != 0x9000 && sw != 0x6985)
            LOG_WARN("SE050: CreateECCurve %02x SW=%04x", curve, sw);
    }

    // UserID authenticator. INS carries the AUTH_OBJECT bit (0x40). Also idempotent.
    {
        const uint8_t h[4] = {0x80, 0x41, 0x07, 0x00};
        uint8_t d[] = {0x41,        0x04,        authId[0],   authId[1],   authId[2],   authId[3],   0x42,        0x08,
                       AUTH_PIN[0], AUTH_PIN[1], AUTH_PIN[2], AUTH_PIN[3], AUTH_PIN[4], AUTH_PIN[5], AUTH_PIN[6], AUTH_PIN[7]};
        secureApdu(h, d, sizeof(d), false, r, sizeof(r), &sw);
        if (sw != 0x9000 && sw != 0x6985)
            LOG_WARN("SE050: WriteUserID SW=%04x", sw);
    }

    // Open and authenticate a UserID session nested inside the secure channel.
    {
        const uint8_t h[4] = {0x80, 0x04, 0x00, 0x1B};
        uint8_t d[] = {0x41, 0x04, authId[0], authId[1], authId[2], authId[3]};
        rl = secureApdu(h, d, sizeof(d), true, r, sizeof(r), &sw);
        if (sw != 0x9000) {
            LOG_ERROR("SE050: CreateSession SW=%04x", sw);
            return false;
        }
        v = tlv1(r, rl, &vl);
        if (!v || vl != 8) {
            LOG_ERROR("SE050: unexpected session id");
            return false;
        }
        memcpy(sessionId, v, 8);
    }
    {
        const uint8_t h[4] = {0x80, 0x04, 0x00, 0x2C};
        uint8_t d[] = {0x41,        0x08,        AUTH_PIN[0], AUTH_PIN[1], AUTH_PIN[2],
                       AUTH_PIN[3], AUTH_PIN[4], AUTH_PIN[5], AUTH_PIN[6], AUTH_PIN[7]};
        sessionApdu(h, d, sizeof(d), false, r, sizeof(r), &sw);
        if (sw != 0x9000) {
            LOG_ERROR("SE050: VerifySessionUserID SW=%04x", sw);
            return false;
        }
    }
    sessionActive = true;
    return true;
}

// --- Recovery ------------------------------------------------------------
//
// Three things can leave the host and the chip disagreeing: the chip resets behind
// our back (brown-out, ENA toggled) and forgets the SCP03 state and the session; the
// channel gets closed by secureApdu() on an error it recognises; the counter drifts.
// Every operation below funnels through ensureSession() and, if the chip still does
// not answer 9000 with a live session, rebuilds everything once and retries once.
// The rest of the node sees a slower call, not a dead vault until the next reboot.

bool SE050::recover(const char *what)
{
    uint32_t t0 = millis();
    LOG_WARN("SE050: %s found the channel down, rebuilding applet select, SCP03 and the session", what);
    scp.open = sessionActive = false;
    bool up = open();
    if (!up && powerCycle) {
        // No answer to the interface reset: wedged or unpowered. An unpowered chip
        // NACKs the I2C write and fails in milliseconds; a wedged one that ACKs and
        // stays silent costs the full poll window per attempt first. ENA low/high is
        // the only power-on reset the chip can get from here.
        LOG_WARN("SE050: no answer to the interface reset after %u ms, power-cycling the chip", (unsigned)(millis() - t0));
        powerCycle();
        up = open();
    }
    if (!up) {
        LOG_ERROR("SE050: chip does not answer the interface reset, gave up after %u ms", (unsigned)(millis() - t0));
        return false;
    }
    if (!openSecureChannel()) {
        LOG_ERROR("SE050: secure channel could not be reopened");
        return false;
    }
    if (!identitySession())
        return false;
    LOG_INFO("SE050: channel rebuilt in %u ms", (unsigned)(millis() - t0));
    return true;
}

bool SE050::ensureSession(const char *what)
{
    if (sessionActive)
        return true;
    if (scp.open)
        return identitySession(); // fresh channel, first session: the ordinary path
    return recover(what);
}

int SE050::objectExists(uint32_t objId)
{
    uint8_t keyId[4];
    be32(objId, keyId);
    const uint8_t h[4] = {0x80, 0x04, 0x00, 0x27}; // INS_MGMT, P1_DEFAULT, P2_EXIST
    uint8_t d[] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3]};
    uint8_t r[32];
    uint16_t sw = 0;
    int rl = sessionApdu(h, d, sizeof(d), true, r, sizeof(r), &sw);
    if (sw != 0x9000) {
        LOG_WARN("SE050: CheckObjectExists SW=%04x", sw);
        return -1;
    }
    int vl;
    const uint8_t *v = tlv1(r, rl, &vl);
    if (!v || vl != 1)
        return -1;
    return v[0] == 0x01 ? 1 : 0; // RESULT_SUCCESS / RESULT_FAILURE
}

// --- Keys by object id ---------------------------------------------------

bool SE050::keyEnsure(const char *what, uint32_t objId, uint8_t curve, const uint8_t policy[4], uint8_t publicKey[32])
{
    if (reentered("keyEnsure"))
        return false;

    uint8_t authId[4], keyId[4];
    be32(AUTH_OBJ, authId);
    be32(objId, keyId);

    uint8_t r[192];
    uint16_t sw = 0;
    int rl, vl;
    const uint8_t *v;

    for (int attempt = 0; attempt < 2; attempt++) {
        if (!ensureSession(what))
            return false;

        // Ask before reading: a failed ReadObject cannot tell a missing object from a
        // dead session, and generating over an existing key is the one thing not to do.
        int exists = objectExists(objId);
        if (exists < 0) {
            scp.open = sessionActive = false; // rebuild on the next lap
            continue;
        }
        if (exists == 0) {
            LOG_INFO("SE050: no %s key at 0x%08x yet, generating it in-chip", what, (unsigned)objId);
            const uint8_t hGen[4] = {0x80, 0x01, 0x61, 0x00}; // P1_KEY_PAIR | P1_EC, no TAG_3/4: the chip generates
            // Policy: bound to the UserID authenticator, access rules per curve (see callers).
            uint8_t dGen[] = {0x11,      0x09,      0x08,      authId[0], authId[1], authId[2], authId[3],
                              policy[0], policy[1], policy[2], policy[3], 0x41,      0x04,      keyId[0],
                              keyId[1],  keyId[2],  keyId[3],  0x42,      0x01,      curve};
            sessionApdu(hGen, dGen, sizeof(dGen), false, r, sizeof(r), &sw);
            if (sw != 0x9000) {
                LOG_ERROR("SE050: WriteECKey (%s 0x%08x) SW=%04x", what, (unsigned)objId, sw);
                return false;
            }
        } else {
            LOG_INFO("SE050: reusing %s key at 0x%08x", what, (unsigned)objId);
        }

        const uint8_t hRead[4] = {0x80, 0x02, 0x00, 0x00};
        uint8_t dRead[] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3]};
        rl = sessionApdu(hRead, dRead, sizeof(dRead), true, r, sizeof(r), &sw);
        if (sw != 0x9000) {
            LOG_ERROR("SE050: ReadObject (%s 0x%08x) SW=%04x", what, (unsigned)objId, sw);
            return false;
        }
        v = tlv1(r, rl, &vl);
        if (!v || vl < 32) {
            LOG_ERROR("SE050: unexpected %s public key length %d", what, vl);
            return false;
        }
        reverse(v, publicKey, 32); // the SE050 reports big-endian (AN12413 section 7)
        return true;
    }
    return false;
}

bool SE050::x25519Ensure(uint32_t objId, uint8_t publicKey[32])
{
    // AR header 0x043C0000: ALLOW_KA | READ | WRITE | GEN | DELETE.
    static const uint8_t POLICY[4] = {0x04, 0x3C, 0x00, 0x00};
    return keyEnsure("X25519", objId, 0x41, POLICY, publicKey); // ID_ECC_MONT_DH_25519
}

bool SE050::ed25519Ensure(uint32_t objId, uint8_t publicKey[32])
{
    // AR header 0x183C0000: ALLOW_SIGN | ALLOW_VERIFY | READ | WRITE | GEN | DELETE.
    static const uint8_t POLICY[4] = {0x18, 0x3C, 0x00, 0x00};
    return keyEnsure("Ed25519", objId, 0x40, POLICY, publicKey); // ID_ECC_ED_25519
}

bool SE050::x25519EcdhBytes(uint32_t objId, const uint8_t peerPublic[32], uint8_t shared[32])
{
    if (reentered("x25519EcdhBytes"))
        return false;

    uint8_t keyId[4];
    be32(objId, keyId);
    uint8_t peerBe[32];
    reverse(peerPublic, peerBe, 32);

    const uint8_t h[4] = {0x80, 0x03, 0x01, 0x0F}; // INS_CRYPTO, P1_EC, P2_DH
    uint8_t d[40];
    int j = 0;
    d[j++] = 0x41; // TAG_1: the on-chip private key
    d[j++] = 0x04;
    memcpy(&d[j], keyId, 4);
    j += 4;
    d[j++] = 0x42; // TAG_2: peer public key, big-endian
    d[j++] = 0x20;
    memcpy(&d[j], peerBe, 32);
    j += 32;

    uint8_t r[128];
    uint16_t sw = 0;
    uint32_t t0 = millis();
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!ensureSession("x25519EcdhBytes"))
            return false;
        int rl = sessionApdu(h, d, j, true, r, sizeof(r), &sw);
        if (sw == 0x9000) {
            int vl;
            const uint8_t *v = tlv1(r, rl, &vl);
            if (!v || vl != 32)
                return false;
            reverse(v, shared, 32);
            if (attempt > 0)
                LOG_INFO("SE050: ECDH completed on the retry, %u ms end to end", (unsigned)(millis() - t0));
            return true;
        }
        // A live session with an existing key and this policy cannot refuse a key
        // agreement, so whatever came back means the chip and the host no longer
        // share a session or a channel: rebuild once and retry once.
        LOG_WARN("SE050: ECDH (0x%08x) SW=%04x%s", (unsigned)objId, sw, attempt == 0 ? ", rebuilding and retrying" : "");
        scp.open = sessionActive = false;
    }
    return false;
}

bool SE050::peerKeyWrite(uint32_t objId, const uint8_t valueBe[32], bool create, bool transient, uint16_t *sw)
{
    uint8_t authId[4], keyId[4];
    be32(AUTH_OBJ, authId);
    be32(objId, keyId);

    // INS_WRITE, plus INS_TRANSIENT (0x80) for a new transient object. The chip ignores
    // that bit on an existing object, but the create/update split is real: policy and
    // curve are refused once the id is in use. P1 = P1_PUBLIC | P1_EC, read on creation.
    const uint8_t hdr[4] = {0x80, (uint8_t)((create && transient) ? 0x81 : 0x01), 0x21, 0x00};
    uint8_t d[64];
    int j = 0;
    if (create) {
        // AR header 0x04340000: ALLOW_KA | READ | WRITE | DELETE, bound to the UserID
        // authenticator like every other object here. WRITE is the one that matters:
        // it is what lets the value be replaced before every agreement.
        static const uint8_t POLICY[4] = {0x04, 0x34, 0x00, 0x00};
        d[j++] = 0x11; // TAG_POLICY
        d[j++] = 0x09;
        d[j++] = 0x08;
        memcpy(&d[j], authId, 4);
        j += 4;
        memcpy(&d[j], POLICY, 4);
        j += 4;
    }
    d[j++] = 0x41; // TAG_1: object id
    d[j++] = 0x04;
    memcpy(&d[j], keyId, 4);
    j += 4;
    if (create) {
        d[j++] = 0x42; // TAG_2: curve, ID_ECC_MONT_DH_25519
        d[j++] = 0x01;
        d[j++] = 0x41;
    }
    d[j++] = 0x44; // TAG_4: public key value, big-endian (AN12413 section 7)
    d[j++] = 0x20;
    memcpy(&d[j], valueBe, 32);
    j += 32;

    uint8_t r[32];
    *sw = 0;
    sessionApdu(hdr, d, j, false, r, sizeof(r), sw);
    return *sw == 0x9000;
}

bool SE050::deleteObject(uint32_t objId, uint16_t *sw)
{
    uint8_t keyId[4];
    be32(objId, keyId);
    const uint8_t h[4] = {0x80, 0x04, 0x00, 0x28}; // INS_MGMT, P1_DEFAULT, P2_DELETE_OBJECT
    uint8_t d[] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3]};
    uint8_t r[32];
    *sw = 0;
    sessionApdu(h, d, sizeof(d), false, r, sizeof(r), sw);
    return *sw == 0x9000;
}

bool SE050::x25519EcdhObject(uint32_t objId, const uint8_t peerPublic[32], uint8_t shared[32])
{
    if (reentered("x25519EcdhObject"))
        return false;

    uint8_t keyId[4], peerId[4];
    be32(objId, keyId);
    be32(PEER_KEY_OBJ, peerId);
    uint8_t peerBe[32];
    reverse(peerPublic, peerBe, 32);

    const uint8_t h[4] = {0x80, 0x03, 0x01, 0x0F}; // INS_CRYPTO, P1_EC, P2_DH
    uint8_t d[12];
    int j = 0;
    d[j++] = 0x41; // TAG_1: the on-chip private key
    d[j++] = 0x04;
    memcpy(&d[j], keyId, 4);
    j += 4;
    d[j++] = 0x43; // TAG_3: the peer public key, by object id
    d[j++] = 0x04;
    memcpy(&d[j], peerId, 4);
    j += 4;

    uint8_t r[128];
    uint16_t sw = 0;
    uint32_t t0 = millis();
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!ensureSession("x25519EcdhObject"))
            return false;

        // The object outlives sessions, channels and resets (its attributes are in NVM),
        // so this is one CheckObjectExists per run, not per agreement. Creating it is the
        // one NVM write of the whole scheme.
        bool written = false;
        if (!peerObjReady) {
            int exists = objectExists(PEER_KEY_OBJ);
            if (exists < 0) {
                scp.open = sessionActive = false; // rebuild on the next lap
                continue;
            }
            if (exists == 0) {
                LOG_INFO("SE050: no peer key object at 0x%08x yet, creating it (transient)", (unsigned)PEER_KEY_OBJ);
                if (!peerKeyWrite(PEER_KEY_OBJ, peerBe, true, true, &sw)) {
                    // A refusal to create (6A84 no transient memory, 6A80 bad TLV...) is not
                    // a session problem: nothing to rebuild, the caller falls back.
                    LOG_WARN("SE050: WriteECKey (create peer object 0x%08x) SW=%04x", (unsigned)PEER_KEY_OBJ, sw);
                    return false;
                }
                written = true;
            }
            peerObjReady = true;
        }
        if (!written && !peerKeyWrite(PEER_KEY_OBJ, peerBe, false, true, &sw)) {
            // Either the session is gone, or the object is there but not as expected (a
            // persistent one under the same id, another policy): the retry answers both,
            // because it asks the chip about the object again.
            LOG_WARN("SE050: WriteECKey (peer object 0x%08x) SW=%04x%s", (unsigned)PEER_KEY_OBJ, sw,
                     attempt == 0 ? ", rebuilding and retrying" : "");
            peerObjReady = false;
            scp.open = sessionActive = false;
            continue;
        }

        int rl = sessionApdu(h, d, j, true, r, sizeof(r), &sw);
        if (sw == 0x9000) {
            int vl;
            const uint8_t *v = tlv1(r, rl, &vl);
            if (!v || vl != 32)
                return false;
            reverse(v, shared, 32);
            if (attempt > 0)
                LOG_INFO("SE050: ECDH via object completed on the retry, %u ms end to end", (unsigned)(millis() - t0));
            return true;
        }
        LOG_WARN("SE050: ECDH via object (0x%08x) SW=%04x%s", (unsigned)objId, sw, attempt == 0 ? ", rebuilding and retrying" : "");
        peerObjReady = false;
        scp.open = sessionActive = false;
    }
    return false;
}

bool SE050::x25519Ecdh(uint32_t objId, const uint8_t peerPublic[32], uint8_t shared[32])
{
    if (ecdhViaObject && x25519EcdhObject(objId, peerPublic, shared))
        return true;
    bool ok = x25519EcdhBytes(objId, peerPublic, shared);
    // The object path rebuilt and retried on its own before giving up, so if the chip
    // answers the byte-array form right after, it is that path it refuses, not the
    // session: stop asking. A chip that is simply gone fails both and keeps the setting.
    if (ok && ecdhViaObject) {
        ecdhViaObject = false;
        LOG_WARN("SE050: key agreement via the peer object refused, byte-array form (an NVM write per call) for the rest of the run");
    }
    return ok;
}

bool SE050::ed25519Sign(uint32_t objId, const uint8_t *message, size_t len, uint8_t signature[64])
{
    if (reentered("ed25519Sign"))
        return false;
    if (len > SIGN_MAX_MESSAGE) {
        LOG_ERROR("SE050: message of %u bytes exceeds the %u-byte signing limit", (unsigned)len, (unsigned)SIGN_MAX_MESSAGE);
        return false;
    }

    uint8_t keyId[4];
    be32(objId, keyId);

    const uint8_t h[4] = {0x80, 0x03, 0x0C, 0x09}; // INS_CRYPTO, P1_SIGNATURE, P2_SIGN
    uint8_t d[12 + SIGN_MAX_MESSAGE];
    int j = 0;
    d[j++] = 0x41; // TAG_1: the on-chip signing key
    d[j++] = 0x04;
    memcpy(&d[j], keyId, 4);
    j += 4;
    d[j++] = 0x42; // TAG_2: EDSignatureAlgo
    d[j++] = 0x01;
    d[j++] = 0xA3; // SIG_ED25519PURE, the chip runs SHA-512 over the plain message
    d[j++] = 0x43; // TAG_3: the message, BER length
    if (len > 0x7F)
        d[j++] = 0x81;
    d[j++] = (uint8_t)len;
    memcpy(&d[j], message, len);
    j += len;

    uint8_t r[96];
    uint16_t sw = 0;
    uint32_t t0 = millis();
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!ensureSession("ed25519Sign"))
            return false;
        int rl = sessionApdu(h, d, j, true, r, sizeof(r), &sw);
        if (sw == 0x9000) {
            int vl;
            const uint8_t *v = tlv1(r, rl, &vl);
            if (!v || vl != 64) {
                LOG_ERROR("SE050: unexpected signature length %d", vl);
                return false;
            }
            // r and s come back reversed, each on its own (AN12413 7.1, figure 19).
            reverse(v, signature, 32);
            reverse(v + 32, signature + 32, 32);
            if (attempt > 0)
                LOG_INFO("SE050: signature completed on the retry, %u ms end to end", (unsigned)(millis() - t0));
            return true;
        }
        // Same reasoning as x25519Ecdh: this cannot be a policy refusal.
        LOG_WARN("SE050: EdDSASign (0x%08x) SW=%04x%s", (unsigned)objId, sw, attempt == 0 ? ", rebuilding and retrying" : "");
        scp.open = sessionActive = false;
    }
    return false;
}

static void benchHex(const char *label, const uint8_t *b, size_t n)
{
    char hex[2 * 80 + 1]; // the PUT KEY data field is 70 bytes
    size_t cap = n < 80 ? n : 80;
    for (size_t i = 0; i < cap; i++)
        snprintf(&hex[i * 2], 3, "%02x", b[i]);
    Serial.printf("  %s = %s\n", label, hex);
}

void SE050::benchScp03Kat()
{
    // The fixed KAT vector from tools/scp03_rotate.py selftest. If these three lines match
    // the tool's, SE050::cmac() and SE050::kdf() are byte-identical to the reference, which
    // is what the whole PUT KEY assembly leans on.
    static const uint8_t katKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t katCtx[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                       0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    Serial.println("[se050] SCP03 KAT (compare with tools/scp03_rotate.py selftest):");
    uint8_t out[16];
    cmac(katKey, katCtx, sizeof(katCtx), out);
    benchHex("cmac(kat_key, kat_ctx)          ", out, 16);
    kdf(katKey, 0x04, 128, katCtx, out);
    benchHex("kdf(kat_key, 0x04, 128, kat_ctx)", out, 16);
    kdf(katKey, 0x06, 128, katCtx, out);
    benchHex("kdf(kat_key, 0x06, 128, kat_ctx)", out, 16);

    // The last session's public challenges + the cryptogram the chip sent, for `verify`.
    Serial.println("[se050] last SCP03 session (for scp03_rotate.py verify):");
    benchHex("hostChallenge ", lastHostChallenge, 8);
    benchHex("cardChallenge ", lastCardChallenge, 8);
    benchHex("cardCryptogram", lastCardCryptogram, 8);
}

// --- Per-device Platform SCP03 keys ----------------------------------------------
//
// key_i = SHA256(master || label)[:16], labels SCP03-ENC/MAC/DEK. The master is the 32-byte
// seed in this board's OTP (OtpVault, docs/secure_boot.md); a bench build may also carry the
// compile-time placeholder (SE050_ROTATED, se050_port.h). The one-way send that puts the keys
// in the chip is separate, under SE050_ALLOW_ROTATION. The framing matches NXP's own demo byte
// for byte (se05x_RotatePlatformSCP03Keys/se05x_TP_PlatformSCP03keys.c, createKeyData),
// cross-checked against tools/scp03_rotate.py.

static void deriveOne(const uint8_t *master, size_t mlen, const char *label, uint8_t out[16])
{
    SHA256 h;
    h.reset();
    h.update(master, mlen);
    h.update(label, strlen(label));
    uint8_t full[32];
    h.finalize(full, sizeof(full));
    memcpy(out, full, 16);
}

static void deriveThree(const uint8_t *master, size_t mlen, uint8_t enc[16], uint8_t mac[16], uint8_t dek[16])
{
    deriveOne(master, mlen, "SCP03-ENC", enc);
    deriveOne(master, mlen, "SCP03-MAC", mac);
    deriveOne(master, mlen, "SCP03-DEK", dek);
}

// The OTP-derived keys, read once per boot: the seed is derived from and wiped, and its page
// soft-locked for everyone until the next reset. A blank page is left alone (not locked) so a
// provisioning build can still write it.
static uint8_t otpEnc[16], otpMac[16], otpDek[16];
static enum { OTP_UNTRIED, OTP_PRESENT, OTP_ABSENT } otpKeys = OTP_UNTRIED;

void SE050::forgetOtpKeys()
{
    otpKeys = OTP_UNTRIED;
}

bool SE050::deriveKeys(KeySource src, uint8_t enc[16], uint8_t mac[16], uint8_t dek[16])
{
    switch (src) {
    case KeySource::Otp: {
        if (otpKeys == OTP_UNTRIED) {
            uint8_t seed[32];
            OtpVault::SeedState st = OtpVault::readSeed(seed);
            if (st == OtpVault::SeedState::Present) {
                deriveThree(seed, sizeof(seed), otpEnc, otpMac, otpDek);
                otpKeys = OTP_PRESENT;
#ifdef NODE_OTP_PROVISION
                // The lock word can only be written while the page is still Secure read-write:
                // a provisioning build leaves the soft lock to Ow until Ol! has been run.
                if (OtpVault::seedPageHardLocked()) {
                    OtpVault::softLockSeedPage();
                    LOG_INFO("SE050: per-device keys derived from the OTP seed, seed page soft-locked");
                } else {
                    LOG_WARN("SE050: keys derived from the OTP seed; page NOT soft-locked (hard-lock it: Ol!, then Ow)");
                }
#else
                OtpVault::softLockSeedPage();
                LOG_INFO("SE050: per-device keys derived from the OTP seed, seed page soft-locked");
#endif
            } else {
                otpKeys = OTP_ABSENT;
                LOG_INFO("SE050: OTP seed %s, no OTP-derived keys", OtpVault::seedStateName(st));
            }
            memset(seed, 0, sizeof(seed));
        }
        if (otpKeys != OTP_PRESENT)
            return false;
        memcpy(enc, otpEnc, 16);
        memcpy(mac, otpMac, 16);
        memcpy(dek, otpDek, 16);
        return true;
    }
    case KeySource::Bench: {
#ifdef SE050_ROTATED
        static const uint8_t master[] = SE050_ROTATION_MASTER;
        deriveThree(master, sizeof(master), enc, mac, dek);
        return true;
#else
        return false;
#endif
    }
    default:
        return false;
    }
}

#ifdef SE050_ALLOW_ROTATION
// --- The one-way send (PUT KEY). Bench only, -D SE050_ALLOW_ROTATION. -------------

int SE050::buildPutKeyData(uint8_t *data, uint8_t *expected)
{
    // Encrypt each new component under the CURRENT DEK (factory on a virgin chip).
    const uint8_t *dekNow = usingRotatedKeys ? curDek : SCP_KEY_DEK;

    uint8_t nEnc[16], nMac[16], nDek[16];
    if (!deriveKeys(KeySource::Otp, nEnc, nMac, nDek))
        return 0;
    const uint8_t *newKeys[3] = {nEnc, nMac, nDek};

    uint8_t zero[16] = {};
    uint8_t ones[16];
    memset(ones, 0x01, sizeof(ones));

    int p = 0, e = 0;
    data[p++] = SCP03_KEYVER; // KVN to replace
    expected[e++] = SCP03_KEYVER;
    for (int k = 0; k < 3; k++) {
        uint8_t encComp[16], kcvFull[16];
        cbc(dekNow, zero, newKeys[k], 16, encComp, true); // AES-CBC, IV 0, one block = ECB
        cbc(newKeys[k], zero, ones, 16, kcvFull, true);   // KCV = AES-ECB(newKey, 01..)[:3]
        data[p++] = 0x88;                                  // GPCS_KEY_TYPE_AES
        data[p++] = 16 + 1;                                // length of AES key data
        data[p++] = 16;                                    // length of AES key
        memcpy(&data[p], encComp, 16);
        p += 16;
        data[p++] = 3; // CRYPTO_KEY_CHECK_LEN
        memcpy(&data[p], kcvFull, 3);
        p += 3;
        memcpy(&expected[e], kcvFull, 3);
        e += 3;
    }
    return p;
}

void SE050::dryRunRotation()
{
    uint8_t nEnc[16], nMac[16], nDek[16];
    if (!deriveKeys(KeySource::Otp, nEnc, nMac, nDek)) {
        Serial.println("[se050] rotation DRY RUN: no OTP seed on this board, nothing to derive (console O s)");
        return;
    }
    // The new keys derive from the OTP seed and never leave the board: only the framing and
    // the KCVs (3 bytes per key, what the chip echoes) are printed, not the keys or the PUT
    // KEY data (which is the keys under the current DEK, and a bench DEK is known to the PC).
    memset(nEnc, 0, 16);
    memset(nMac, 0, 16);
    memset(nDek, 0, 16);
    Serial.printf("[se050] rotation DRY RUN (nothing is sent), current keys: %s -> new keys: OTP-derived\n",
                  keySourceName(keySource));
    uint8_t data[128], expected[16];
    int len = buildPutKeyData(data, expected);
    memset(data, 0, sizeof(data));
    const uint8_t hdr[4] = {0x80, 0xD8, SCP03_KEYVER, 0x81};
    benchHex("APDU header (->0x84 wrapped)", hdr, 4);
    Serial.printf("  Lc = %d (3 AES-128 components, NXP createKeyData layout)\n", len);
    benchHex("expected response (KVN+3 KCV)", expected, 10);
}

bool SE050::rotatePlatformKeys()
{
    if (keySource == KeySource::Otp) {
        LOG_WARN("SE050: this chip already runs the OTP-derived keys, nothing to do");
        return true;
    }
    uint8_t nEnc[16], nMac[16], nDek[16];
    if (!deriveKeys(KeySource::Otp, nEnc, nMac, nDek)) {
        LOG_ERROR("SE050: no OTP seed on this board (console O s first), not rotating");
        return false;
    }

    // PUT KEY targets the security domain that owns the Platform SCP keys, not the IoT applet
    // (with the applet selected it returned 6a80; with nothing selected INITIALIZE UPDATE
    // returned 6a88). NXP's middleware selects the SSD for rotation (sm_const.h SSD_NAME =
    // D276000085304A434F9003, "Rotate keys ... Select SSD" in sm_connect.c). So: interface
    // reset, SELECT that SSD, then open Platform SCP there (with whichever current keys the
    // chip answers to: factory or the bench master) and send PUT KEY.
    scp.open = sessionActive = false;
    usingRotatedKeys = false;
    if (!reset()) {
        LOG_ERROR("SE050: interface reset failed, not rotating");
        return false;
    }
    {
        static const uint8_t SEL_SSD[] = {0x00, 0xA4, 0x04, 0x00, 0x0B, 0xD2, 0x76, 0x00,
                                          0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03};
        uint8_t r[64];
        int n = transceive(SEL_SSD, sizeof(SEL_SSD), r, sizeof(r));
        uint16_t sw = statusWord(r, n);
        if (sw != 0x9000) {
            LOG_ERROR("SE050: SELECT SSD returned SW=%04x, not rotating", sw);
            return false;
        }
        LOG_INFO("SE050: SSD selected for rotation");
    }
    if (!openSecureChannel()) {
        LOG_ERROR("SE050: cannot open a Platform SCP channel on the SSD, not rotating");
        return false;
    }
    if (keySource == KeySource::Otp) {
        LOG_WARN("SE050: the SSD already opens with the OTP-derived keys, nothing to do");
        return true;
    }
    LOG_INFO("SE050: SSD channel open with the %s keys", keySourceName(keySource));

    uint8_t data[128], expected[16];
    int len = buildPutKeyData(data, expected); // derives the same OTP keys as nEnc/nMac/nDek

    LOG_WARN("SE050: sending PUT KEY - this is irreversible");
    const uint8_t hdr[4] = {0x80, 0xD8, SCP03_KEYVER, 0x81};
    uint8_t resp[32];
    uint16_t sw = 0;
    int rl = secureApdu(hdr, data, len, true, resp, sizeof(resp), &sw);
    if (sw != 0x9000) {
        LOG_ERROR("SE050: PUT KEY SW=%04x - the chip rejected it, keys NOT changed", sw);
        return false;
    }
    if (rl != 10 || memcmp(resp, expected, 10) != 0) {
        LOG_ERROR("SE050: PUT KEY echoed unexpected KCVs (rl=%d) - stored keys may be wrong", rl);
        // do not adopt; the channel is still on the old keys, so the chip is still usable
        return false;
    }
    LOG_INFO("SE050: PUT KEY accepted, chip echoed the expected KVN+KCVs");

    // Adopt the new keys and reopen the channel to prove they actually work end to end.
    memcpy(curEnc, nEnc, 16);
    memcpy(curMac, nMac, 16);
    memcpy(curDek, nDek, 16);
    usingRotatedKeys = true;
    keySource = KeySource::Otp;
    scp.open = sessionActive = false;
    if (!open() || !tryOpenChannel()) {
        LOG_ERROR("SE050: CANNOT reopen with the new keys - rotation is bad, chip may be lost");
        return false;
    }
    uint8_t pub[32];
    if (!identityEnsure(pub))
        LOG_WARN("SE050: channel reopened but the identity is not reachable - check the chip");

    Serial.println("[se050] rotation CONFIRMED - channel reopens with the OTP-derived keys");
    Serial.println("  (the chip now answers only to keys derived from this board's OTP seed)");
    memset(nEnc, 0, 16);
    memset(nMac, 0, 16);
    memset(nDek, 0, 16);
    return true;
}
#endif // SE050_ALLOW_ROTATION

void SE050::faultInject(char what)
{
    switch (what) {
    case 'c':
        scp.counter += 3;
        LOG_WARN("SE050: fault injected, host SCP03 counter advanced by 3");
        break;
    case 's':
        sessionId[0] ^= 0xFF;
        LOG_WARN("SE050: fault injected, session id corrupted");
        break;
    default:
        break;
    }
}

// --- The node identity: wrappers the self-test and the Meshtastic port use ----

bool SE050::identityEnsure(uint8_t publicKey[32])
{
    identityReady = false;
    if (!x25519Ensure(IDENTITY_OBJ, publicKey))
        return false;
    activeKeyObj = IDENTITY_OBJ;
    identityReady = true;
    return true;
}

bool SE050::identityImport(const uint8_t privateKey[32], uint8_t publicKeyOut[32], bool replaceStale)
{
    identityReady = false;
    if (!identitySession())
        return false;

    uint8_t authId[4], keyId[4];
    be32(AUTH_OBJ, authId);
    be32(NODE_KEY_OBJ, keyId);

    // WriteECKey wants both halves of a key pair or neither, and Meshtastic only
    // keeps the private one, so derive the public half here.
    uint8_t privLe[32], pubLe[32];
    memcpy(privLe, privateKey, 32);
    Curve25519::eval(pubLe, privLe, 0);
    memcpy(publicKeyOut, pubLe, 32);

    uint8_t r[192];
    uint16_t sw = 0;
    int rl, vl;
    const uint8_t *v;

    // Already there? Compare before writing. This is what keeps the NVM write to
    // once per node instead of once per boot.
    const uint8_t hRead[4] = {0x80, 0x02, 0x00, 0x00};
    uint8_t dRead[] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3]};
    rl = sessionApdu(hRead, dRead, sizeof(dRead), true, r, sizeof(r), &sw);
    if (sw == 0x9000) {
        v = tlv1(r, rl, &vl);
        uint8_t onChip[32];
        if (v && vl >= 32) {
            reverse(v, onChip, 32); // the SE050 reports big-endian
            if (memcmp(onChip, pubLe, 32) == 0) {
                LOG_INFO("SE050: node key already mirrored (objId 0x%08x)", (unsigned)NODE_KEY_OBJ);
                activeKeyObj = NODE_KEY_OBJ;
                identityReady = true;
                return true;
            }
        }
        if (!replaceStale) {
            LOG_WARN("SE050: objId 0x%08x holds a different key - refusing to overwrite an identity", (unsigned)NODE_KEY_OBJ);
            LOG_WARN("SE050: build with -D SE050_REPLACE_MIRROR once to discard it and mirror the current node key");
            return false;
        }

        // Asked for explicitly, and only then. The stale object is a mirror of a
        // node key that no longer exists, so nothing is lost with it - but that
        // is a judgement about this object in this stage of the port, not one
        // the driver gets to make on its own for any key it finds in the way.
        LOG_WARN("SE050: objId 0x%08x holds a different key - replacing it as asked", (unsigned)NODE_KEY_OBJ);
        const uint8_t hDelete[4] = {0x80, 0x04, 0x00, 0x28};
        uint8_t dDelete[] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3]};
        sessionApdu(hDelete, dDelete, sizeof(dDelete), false, r, sizeof(r), &sw);
        if (sw != 0x9000) {
            // 6985 here means the object's own policy does not carry ALLOW_DELETE,
            // in which case it cannot be removed through this session at all.
            LOG_ERROR("SE050: DeleteSecureObject SW=%04x, the stale mirror stays", sw);
            return false;
        }
    }

    // Montgomery keys go in big-endian, private half included (AN12413 section 7.2).
    uint8_t privBe[32], pubBe[32];
    reverse(privLe, privBe, 32);
    reverse(pubLe, pubBe, 32);

    LOG_INFO("SE050: mirroring node key into the chip (objId 0x%08x)", (unsigned)NODE_KEY_OBJ);
    uint8_t d[128];
    int j = 0;
    // Policy: bound to the UserID authenticator, allowing key agreement.
    d[j++] = 0x11;
    d[j++] = 0x09;
    d[j++] = 0x08;
    memcpy(&d[j], authId, 4);
    j += 4;
    d[j++] = 0x04;
    d[j++] = 0x3C;
    d[j++] = 0x00;
    d[j++] = 0x00;
    d[j++] = 0x41; // TAG_1: object id
    d[j++] = 0x04;
    memcpy(&d[j], keyId, 4);
    j += 4;
    d[j++] = 0x42; // TAG_2: curve
    d[j++] = 0x01;
    d[j++] = 0x41;
    d[j++] = 0x43; // TAG_3: private half
    d[j++] = 0x20;
    memcpy(&d[j], privBe, 32);
    j += 32;
    d[j++] = 0x44; // TAG_4: public half
    d[j++] = 0x20;
    memcpy(&d[j], pubBe, 32);
    j += 32;

    const uint8_t hWrite[4] = {0x80, 0x01, 0x61, 0x00}; // P1_EC | P1_KEY_PAIR
    sessionApdu(hWrite, d, j, false, r, sizeof(r), &sw);
    if (sw != 0x9000) {
        LOG_ERROR("SE050: WriteECKey (import) SW=%04x", sw);
        return false;
    }

    // Read it back: proves the byte order was right rather than assuming it.
    rl = sessionApdu(hRead, dRead, sizeof(dRead), true, r, sizeof(r), &sw);
    if (sw != 0x9000) {
        LOG_ERROR("SE050: ReadObject after import SW=%04x", sw);
        return false;
    }
    v = tlv1(r, rl, &vl);
    uint8_t readBack[32];
    if (!v || vl < 32) {
        LOG_ERROR("SE050: unexpected public key length %d after import", vl);
        return false;
    }
    reverse(v, readBack, 32);
    if (memcmp(readBack, pubLe, 32) != 0) {
        LOG_ERROR("SE050: imported key does not read back - byte order is wrong");
        return false;
    }

    activeKeyObj = NODE_KEY_OBJ;
    identityReady = true;
    return true;
}

bool SE050::identityEcdh(const uint8_t peerPublic[32], uint8_t shared[32])
{
    if (!identityReady)
        return false;
    return x25519Ecdh(activeKeyObj, peerPublic, shared);
}

bool SE050::signingEnsure(uint8_t publicKey[32])
{
    signingReady = ed25519Ensure(SIGNING_OBJ, publicKey);
    return signingReady;
}

bool SE050::sign(const uint8_t *message, size_t len, uint8_t signature[64])
{
    if (!signingReady)
        return false;
    return ed25519Sign(SIGNING_OBJ, message, len, signature);
}

bool SE050::probe()
{
    ecdhViaObject = ECDH_VIA_OBJECT_DEFAULT; // a re-probe gives the peer-object path another chance
    peerObjReady = false;
    if (!open()) {
        LOG_ERROR("SE050: bring-up failed at 0x%x", address);
        return false;
    }

    // GetVersion: CLA=80 INS_MGMT=04 P1=00 P2_VERSION=20, Le=00. The 7-byte
    // VersionInfo comes back in a BER-TLV (tag 0x41): applet version, then the
    // 2-byte AppletConfig and 2-byte SecureBox. Long-form length is possible.
    static const uint8_t GV[] = {0x80, 0x04, 0x00, 0x20, 0x00};
    uint8_t r[32];
    int n = transceive(GV, sizeof(GV), r, sizeof(r));
    if (statusWord(r, n) == 0x9000) {
        const uint8_t *vi = r;
        int off = 0;
        if (n >= 2 && r[0] == 0x41) {
            if (r[1] == 0x82)
                off = 4;
            else if (r[1] == 0x81)
                off = 3;
            else
                off = 2;
        }
        vi = &r[off];
        if (n - off >= 7) {
            uint16_t cfg = (uint16_t)((vi[3] << 8) | vi[4]);
            LOG_INFO("SE050: applet %d.%d.%d AppletConfig=0x%04x (EDDSA %s, DH_MONT %s, FIPS %s)", vi[0], vi[1], vi[2],
                     cfg, (cfg & 0x0004) ? "on" : "off", (cfg & 0x0008) ? "on" : "off", (cfg & 0x1000) ? "off" : "on");
        }
    } else {
        LOG_WARN("SE050: GetVersion returned SW=%04x", statusWord(r, n));
    }

    // GetRandom (16 bytes): CLA=80 INS_MGMT=04 P1=00 P2_RANDOM=49, TLV 41 02 <size>, Le=00.
    // Proves the on-chip TRNG is live - the bytes must differ every boot.
    static const uint8_t GR[] = {0x80, 0x04, 0x00, 0x49, 0x04, 0x41, 0x02, 0x00, 0x10, 0x00};
    n = transceive(GR, sizeof(GR), r, sizeof(r));
    if (statusWord(r, n) == 0x9000 && n >= 2 && r[0] == 0x41) {
        int off = (r[1] == 0x82) ? 4 : (r[1] == 0x81) ? 3 : 2;
        int rl = (r[1] == 0x82) ? ((r[2] << 8) | r[3]) : (r[1] == 0x81) ? r[2] : r[1];
        char hex[2 * 16 + 1];
        int shown = 0;
        for (int i = 0; i < rl && off + i < n - 2 && shown < 16; i++, shown++)
            snprintf(&hex[shown * 2], 3, "%02X", r[off + i]);
        hex[shown * 2] = '\0';
        LOG_INFO("SE050: GetRandom OK, TRNG live: %s", hex);
    } else {
        LOG_WARN("SE050: GetRandom returned SW=%04x", statusWord(r, n));
    }

    if (!openSecureChannel()) {
        LOG_WARN("SE050: SCP03 secure channel not established");
        return true;
    }
    // "Open", not "authenticated": the keys are NXP's public factory defaults (see
    // SCP_KEY_ENC/MAC above), so this confirms a chip that speaks PlatformSCP03
    // correctly, not one we trust more than an attacker with physical I2C access
    // could. Rotating to per-device keys is a prerequisite for that claim, not done here.
    LOG_INFO("SE050: SCP03 secure channel open");

    uint8_t ourPublic[32];
    if (!identityEnsure(ourPublic)) {
        LOG_WARN("SE050: identity not available");
        return true;
    }
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(&hex[i * 2], 3, "%02X", ourPublic[i]);
    LOG_INFO("SE050: identity public key %s", hex);

    // Equivalence check: generate a throwaway keypair in software, do the exchange
    // both ways, and compare. If the SE050 agrees with Curve25519 byte for byte,
    // the whole chain - byte order, curve, policy, session - is correct, and the
    // chip can stand in for the software implementation.
    uint8_t testPrivate[32], testPublic[32];
    Curve25519::dh1(testPublic, testPrivate);

    uint8_t sharedChip[32];
    if (!x25519EcdhBytes(activeKeyObj, testPublic, sharedChip)) {
        LOG_WARN("SE050: ECDH failed, cannot compare against software");
        return true;
    }

    uint8_t sharedSoft[32];
    memcpy(sharedSoft, ourPublic, 32);
    if (!Curve25519::dh2(sharedSoft, testPrivate)) {
        LOG_WARN("SE050: software side of the comparison failed");
        return true;
    }

    if (memcmp(sharedChip, sharedSoft, 32) == 0) {
        LOG_INFO("SE050: ECDH matches software byte for byte - hardware X25519 is usable");
    } else {
        for (int i = 0; i < 32; i++)
            snprintf(&hex[i * 2], 3, "%02X", sharedChip[i]);
        LOG_ERROR("SE050: ECDH MISMATCH, chip=%s", hex);
        for (int i = 0; i < 32; i++)
            snprintf(&hex[i * 2], 3, "%02X", sharedSoft[i]);
        LOG_ERROR("SE050: ECDH MISMATCH, soft=%s", hex);
    }

#ifdef SE050_BENCHMARK
    benchEcdhNvm(); // the boot-time run; the console's 'B' does the same on demand
#endif

    // Same equivalence check for the signing key: sign in the chip, verify with the
    // Ed25519 implementation microReticulum uses. A fresh message every boot, so a
    // signature cached anywhere could not pass. The one thing this cannot catch is
    // a key that signs consistently but was not generated where we think - that
    // is what the policy and the never-exported seed are for.
    uint8_t sigPublic[32];
    if (!signingEnsure(sigPublic)) {
        LOG_WARN("SE050: signing key not available");
        return true;
    }
    for (int i = 0; i < 32; i++)
        snprintf(&hex[i * 2], 3, "%02X", sigPublic[i]);
    LOG_INFO("SE050: signing public key %s", hex);

    uint8_t msg[48];
    memcpy(msg, "rp2350_reticulum_eth_node se050 ", 32);
    se050PortRandom(&msg[32], 16);
    uint8_t sig[64];
    uint32_t signT0 = micros();
    if (!sign(msg, sizeof(msg), sig)) {
        LOG_WARN("SE050: EdDSA sign failed, cannot compare against software");
        return true;
    }
    uint32_t signUs = micros() - signT0;
    if (Ed25519::verify(sig, sigPublic, msg, sizeof(msg))) {
        LOG_INFO("SE050: EdDSA signature verifies in software - hardware Ed25519 is usable (%u ms per sign)", signUs / 1000);
    } else {
        // Bring-up diagnostic: say which byte order would have verified, if any, so
        // one flash settles it instead of a guess per boot.
        uint8_t altPub[32], altSig[64];
        reverse(sigPublic, altPub, 32);
        reverse(sig, altSig, 32);
        reverse(sig + 32, altSig + 32, 32);
        bool pubRev = Ed25519::verify(sig, altPub, msg, sizeof(msg));
        bool halvesRev = Ed25519::verify(altSig, sigPublic, msg, sizeof(msg));
        bool bothRev = Ed25519::verify(altSig, altPub, msg, sizeof(msg));
        reverse(sig, altSig, 64);
        bool wholeRev = Ed25519::verify(altSig, sigPublic, msg, sizeof(msg));
        LOG_ERROR("SE050: EdDSA MISMATCH (pub reversed: %s, sig halves reversed: %s, both: %s, sig whole reversed: %s)",
                  pubRev ? "ok" : "no", halvesRev ? "ok" : "no", bothRev ? "ok" : "no", wholeRev ? "ok" : "no");
    }

    return true;
}

// Where the NVM write is, if anywhere, in an X25519 agreement - measured, since the chip
// gives no way to see its NVM directly. Results and the reading of them:
// docs/se050_ecdh_nvm.md. Each APDU is a UserID session nested inside SCP03 (AES-CMAC +
// AES-CBC both ways) over I2C, so the wire alone is a few ms and "TAG_2 vs TAG_3" on its
// own cannot tell an NVM write from the two AES blocks TAG_2 carries more. Hence the
// controls: the same WriteECKey, byte for byte, into a persistent object (which does write
// NVM) next to the transient one; EdDSASign over 1 and 33 bytes (same computation, exactly
// two blocks apart) to price the wire; and the TAG_3 agreement against the persistent object
// (same bytes as the transient one). Three peer keys rotate so no write repeats the value an
// object already holds - a chip may skip those. Min is the statistic: the process is
// fixed-cost, the jitter is all above it. Leaves the chip as it found it, plus PEER_KEY_OBJ.
void SE050::benchEcdhNvm()
{
    if (reentered("benchEcdhNvm"))
        return;
    uint8_t ourPublic[32], tmp[32], be[32];
    if (!identityEnsure(ourPublic)) {
        LOG_WARN("SE050: bench: identity not available");
        return;
    }
    // Three software keypairs and the secrets the chip has to reproduce.
    uint8_t pubs[3][32], softs[3][32];
    for (int k = 0; k < 3; k++) {
        uint8_t prv[32];
        Curve25519::dh1(pubs[k], prv);
        memcpy(softs[k], ourPublic, 32);
        Curve25519::dh2(softs[k], prv);
    }
    // The agreement through the transient peer object, checked before it is timed. This
    // is also what creates the object on a chip that has none (its one NVM write).
    if (!x25519EcdhObject(activeKeyObj, pubs[0], tmp)) {
        LOG_WARN("SE050: bench: ECDH via the transient peer object failed, nothing to compare");
        return;
    }
    if (memcmp(tmp, softs[0], 32) != 0) {
        LOG_ERROR("SE050: bench: ECDH via the transient peer object does NOT match software");
        return;
    }
    LOG_INFO("SE050: bench: ECDH via the transient peer object matches software");

    constexpr int ROUNDS = 12;
    constexpr uint32_t CONTROL_OBJ = 0x524E5043u; // "RNPC", the persistent control, deleted at the end
    // The chip is polled for its answer every 10 ms in normal use, which quantises every
    // APDU to 10 ms and hides exactly the 1-3 ms this is after: 0.25 ms while measuring.
    // And the bus at 400 kHz (the chip takes up to 1 MHz with clock stretching, which the
    // RP2350 does) so the wire term shrinks to a quarter and an NVM write stands out of
    // it. Both restored below, whatever happens.
    pollIntervalUs = 250;
    bus.setClock(400000);
    uint32_t roundT[ROUNDS] = {}, roundP[ROUNDS] = {};
    struct Stat {
        uint32_t best = UINT32_MAX, worst = 0, total = 0;
        int done = 0;
        void add(uint32_t dt)
        {
            total += dt;
            best = min(best, dt);
            worst = max(worst, dt);
            done++;
        }
        uint32_t avg() const { return done ? total / done : 0; }
    } tBytes, tWriteT, tWriteP, tAgreeObj, tObjPath;

    uint16_t sw = 0;
    reverse(pubs[2], be, 32);
    bool control = false;
    if (ensureSession("benchmark")) {
        // A persistent object under the same policy, created fresh so its attributes
        // match the transient one's. Its initial value is pubs[2]; round 0 writes pubs[0].
        if (objectExists(CONTROL_OBJ) == 1 && !deleteObject(CONTROL_OBJ, &sw))
            LOG_WARN("SE050: benchmark: stale control object 0x%08x not deleted, SW=%04x", (unsigned)CONTROL_OBJ, sw);
        control = peerKeyWrite(CONTROL_OBJ, be, true, false, &sw);
        if (!control)
            LOG_WARN("SE050: benchmark: persistent control object not created, SW=%04x - no write comparison", sw);
    }
    // The transient object starts the rounds holding pubs[2] as well.
    if (!peerObjReady)
        x25519EcdhObject(activeKeyObj, pubs[2], tmp);
    else if (!peerKeyWrite(PEER_KEY_OBJ, be, false, true, &sw))
        peerObjReady = false;

    bool mismatch = false;
    for (int i = 0; i < ROUNDS && peerObjReady; i++) {
        // Written this round: pubs[i%3]. The end-to-end pass at the end writes pubs[(i+2)%3],
        // so the next round's write differs from what the object holds, and so does this one.
        const int k = i % 3, k2 = (i + 2) % 3;
        reverse(pubs[k], be, 32);

        uint32_t t0 = micros();
        bool ok = x25519EcdhBytes(activeKeyObj, pubs[k], tmp);
        uint32_t dt = micros() - t0;
        if (!ok) {
            LOG_WARN("SE050: benchmark aborted, byte-array ECDH failed in round %d", i + 1);
            break;
        }
        tBytes.add(dt);
        if (memcmp(tmp, softs[k], 32) != 0)
            mismatch = true;

        t0 = micros();
        ok = peerKeyWrite(PEER_KEY_OBJ, be, false, true, &sw);
        dt = micros() - t0;
        if (!ok) {
            LOG_WARN("SE050: benchmark aborted, transient WriteECKey SW=%04x in round %d", sw, i + 1);
            break;
        }
        tWriteT.add(dt);
        roundT[i] = dt;

        if (control) {
            t0 = micros();
            ok = peerKeyWrite(CONTROL_OBJ, be, false, false, &sw);
            dt = micros() - t0;
            if (!ok) {
                LOG_WARN("SE050: benchmark: persistent WriteECKey SW=%04x in round %d, control dropped", sw, i + 1);
                control = false;
            } else {
                tWriteP.add(dt);
                roundP[i] = dt;
            }
        }

        // The agreement alone against the value just written: TAG_3, no key bytes on the wire.
        uint8_t keyId[4], peerId[4];
        be32(activeKeyObj, keyId);
        be32(PEER_KEY_OBJ, peerId);
        const uint8_t hDh[4] = {0x80, 0x03, 0x01, 0x0F};
        const uint8_t dDh[12] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3], 0x43, 0x04, peerId[0], peerId[1], peerId[2], peerId[3]};
        uint8_t r[128];
        t0 = micros();
        int rl = sessionApdu(hDh, dDh, sizeof(dDh), true, r, sizeof(r), &sw);
        dt = micros() - t0;
        int vl;
        const uint8_t *v = tlv1(r, rl, &vl);
        if (sw != 0x9000 || !v || vl != 32) {
            LOG_WARN("SE050: benchmark aborted, ECDH via object SW=%04x in round %d", sw, i + 1);
            break;
        }
        tAgreeObj.add(dt);
        reverse(v, tmp, 32);
        if (memcmp(tmp, softs[k], 32) != 0)
            mismatch = true;

        // End to end, as exchange() pays it: write + agree.
        t0 = micros();
        ok = x25519EcdhObject(activeKeyObj, pubs[k2], tmp);
        dt = micros() - t0;
        if (!ok) {
            LOG_WARN("SE050: benchmark aborted, object path failed in round %d", i + 1);
            break;
        }
        tObjPath.add(dt);
        if (memcmp(tmp, softs[k2], 32) != 0)
            mismatch = true;
    }

    // Two more controls, so "TAG_2 costs the wire more, nothing else" rests on measurements
    // rather than on the byte count. (1) The wire itself: EdDSASign over 1 and 33 bytes
    // is the same computation (one SHA-512 block either way) and exactly two AES blocks
    // apart on the wire, like TAG_2 vs TAG_3. (2) An NVM write inside an agreement, if
    // there is one to see: the same TAG_3 agreement against the persistent control
    // object, byte for byte the transient one.
    Stat tSign1, tSign33, tAgreePersist;
    if (signingReady || ed25519Ensure(SIGNING_OBJ, tmp)) {
        uint8_t msg[33], sig[64];
        se050PortRandom(msg, sizeof(msg));
        for (int i = 0; i < ROUNDS; i++) {
            uint32_t t0 = micros();
            bool ok = ed25519Sign(SIGNING_OBJ, msg, 1, sig);
            uint32_t dt = micros() - t0;
            if (!ok)
                break;
            tSign1.add(dt);
            t0 = micros();
            ok = ed25519Sign(SIGNING_OBJ, msg, 33, sig);
            dt = micros() - t0;
            if (!ok)
                break;
            tSign33.add(dt);
        }
    }
    if (control) {
        uint8_t keyId[4], ctlId[4];
        be32(activeKeyObj, keyId);
        be32(CONTROL_OBJ, ctlId);
        const uint8_t hDh[4] = {0x80, 0x03, 0x01, 0x0F};
        const uint8_t dDh[12] = {0x41, 0x04, keyId[0], keyId[1], keyId[2], keyId[3], 0x43, 0x04, ctlId[0], ctlId[1], ctlId[2], ctlId[3]};
        for (int i = 0; i < ROUNDS; i++) {
            const int k = i % 3;
            reverse(pubs[k], be, 32);
            if (!peerKeyWrite(CONTROL_OBJ, be, false, false, &sw))
                break;
            uint8_t r[128];
            uint32_t t0 = micros();
            int rl = sessionApdu(hDh, dDh, sizeof(dDh), true, r, sizeof(r), &sw);
            uint32_t dt = micros() - t0;
            int vl;
            const uint8_t *v = tlv1(r, rl, &vl);
            if (sw != 0x9000 || !v || vl != 32)
                break;
            tAgreePersist.add(dt);
            reverse(v, tmp, 32);
            if (memcmp(tmp, softs[k], 32) != 0)
                mismatch = true;
        }
    }

    if (control && !deleteObject(CONTROL_OBJ, &sw))
        LOG_WARN("SE050: benchmark: control object 0x%08x not deleted, SW=%04x", (unsigned)CONTROL_OBJ, sw);
    pollIntervalUs = POLL_INTERVAL_MS * 1000;
    bus.setClock(100000);

    // The software agreement, for scale.
    uint8_t softShared[32], softPrv[32], softPub[32];
    Curve25519::dh1(softPub, softPrv);
    memcpy(softShared, ourPublic, 32);
    uint32_t t0 = micros();
    Curve25519::dh2(softShared, softPrv);
    uint32_t softUs = micros() - t0;

    // Tenths of a millisecond, the resolution that matters here.
#define SE050_MS(us) (unsigned)((us) / 1000), (unsigned)(((us) / 100) % 10)
    if (tBytes.done > 0)
        LOG_INFO("SE050: bench (I2C 400 kHz, poll 0.25 ms) ECDH byte array (TAG_2): %d rounds, min %u.%u ms, avg %u.%u ms, max %u.%u ms | software %u ms", tBytes.done,
                 SE050_MS(tBytes.best), SE050_MS(tBytes.avg()), SE050_MS(tBytes.worst), (unsigned)(softUs / 1000));
    if (tAgreeObj.done > 0)
        LOG_INFO("SE050: bench ECDH via object (TAG_3): %d rounds, min %u.%u ms, avg %u.%u ms, max %u.%u ms (two AES blocks fewer on the wire)",
                 tAgreeObj.done, SE050_MS(tAgreeObj.best), SE050_MS(tAgreeObj.avg()), SE050_MS(tAgreeObj.worst));
    if (tWriteT.done > 0)
        LOG_INFO("SE050: bench WriteECKey transient: %d rounds, min %u.%u ms, avg %u.%u ms, max %u.%u ms", tWriteT.done,
                 SE050_MS(tWriteT.best), SE050_MS(tWriteT.avg()), SE050_MS(tWriteT.worst));
    {
        // Round by round, so an outlier (a transient write that did pay the NVM price) shows.
        char rounds[160];
        int n = 0;
        for (int i = 0; i < ROUNDS && n < (int)sizeof(rounds) - 24; i++)
            n += snprintf(&rounds[n], sizeof(rounds) - n, " %u.%u/%u.%u", SE050_MS(roundT[i]), SE050_MS(roundP[i]));
        LOG_INFO("SE050: bench write transient/persistent per round (ms):%s", rounds);
    }
    if (tWriteP.done > 0) {
        int32_t delta = (int32_t)tWriteT.best - (int32_t)tWriteP.best;
        uint32_t mag = (uint32_t)(delta < 0 ? -delta : delta);
        LOG_INFO("SE050: bench WriteECKey persistent (same bytes, NVM for sure): %d rounds, min %u.%u ms, avg %u.%u ms, max %u.%u ms",
                 tWriteP.done, SE050_MS(tWriteP.best), SE050_MS(tWriteP.avg()), SE050_MS(tWriteP.worst));
        LOG_INFO("SE050: bench transient - persistent write = %s%u.%u ms (min vs min): %s", delta < 0 ? "-" : "+", SE050_MS(mag),
                 delta <= -1500 ? "the transient write stays out of NVM" : "NO clear gap - the transient write costs what an NVM write costs");
    }
    if (tSign33.done > 0)
        LOG_INFO("SE050: bench wire calibration, EdDSASign 33 B - 1 B (two AES blocks, same computation): min %u.%u - %u.%u = %u.%u ms",
                 SE050_MS(tSign33.best), SE050_MS(tSign1.best), SE050_MS(tSign33.best - tSign1.best));
    if (tAgreePersist.done > 0)
        LOG_INFO("SE050: bench ECDH via the PERSISTENT object (same bytes as TAG_3 transient): %d rounds, min %u.%u ms, avg %u.%u ms, max %u.%u ms",
                 tAgreePersist.done, SE050_MS(tAgreePersist.best), SE050_MS(tAgreePersist.avg()), SE050_MS(tAgreePersist.worst));
    if (tObjPath.done > 0)
        LOG_INFO("SE050: bench object path end to end (write + agree, what exchange() pays): %d rounds, min %u.%u ms, avg %u.%u ms, max %u.%u ms%s",
                 tObjPath.done, SE050_MS(tObjPath.best), SE050_MS(tObjPath.avg()), SE050_MS(tObjPath.worst),
                 mismatch ? " - SHARED SECRET MISMATCH in some round" : ", every round matched software");
#undef SE050_MS
}

#endif // HAS_SE050
