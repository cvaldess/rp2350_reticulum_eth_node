#include "Ota.h"

#include "OtpVault.h"
#include "Picobin.h"
#include "boot_pubkeys.h"
#include "build_id.h"
#include <LittleFS.h>
#include <PicoOTA.h>
#include <SHA256.h>
#include <hardware/regs/addressmap.h>
#include <hardware/watchdog.h>
#include <string.h>
#include <uECC.h>

Ota ota;

extern uint8_t _FS_start; // arduino-pico flash layout: sketch | LittleFS | EEPROM

static const char *STATE_FILE = "/ota_state";
static const char *IMAGE_FILE = "firmware.bin";      // the name the OTA command carries
static const char *PREV_FILE = "firmware.prev.bin";  // what was running when the last upload came in
static const char *BUILD_STAMP = NODE_BUILD_ID; // "<sha7>[-dirty] <UTC time>" from tools/build_id.py

static constexpr uint32_t BODY_IDLE_TIMEOUT_MS = 30000;
static constexpr size_t FS_KEEP_FREE = 64 * 1024; // room the Reticulum store must keep

static uint32_t sketchArea()
{
    return (uint32_t)&_FS_start - XIP_BASE;
}

static uint64_t fsFree()
{
    fs::FSInfo info;
    if (!LittleFS.info(info))
        return 0;
    return info.totalBytes > info.usedBytes ? info.totalBytes - info.usedBytes : 0;
}

// Which of the boot signing keys signed this digest, -1 if none did.
static int verifySignature(const uint8_t digest[32], const uint8_t sig[64])
{
    for (int k = 0; k < NODE_BOOT_PUBKEY_COUNT; k++)
        if (uECC_verify(NODE_BOOT_PUBKEYS[k], digest, 32, sig, uECC_secp256k1()))
            return k;
    return -1;
}

// The running image's own signature block, as the bootrom sees it at XIP_BASE.
static const Picobin::Signed &runningImage()
{
    static Picobin::Signed sig;
    static bool done = false;
    if (!done) {
        Picobin::inspect((const uint8_t *)XIP_BASE, sketchArea(), sig);
        done = true;
    }
    return sig;
}

const char *Ota::stateName(State s)
{
    switch (s) {
    case State::Pending:
        return "pending";
    case State::Confirmed:
        return "confirmed";
    case State::RolledBack:
        return "rolledback";
    case State::Failed:
        return "failed";
    default:
        return "none";
    }
}

// ------------------------------------------------------------------------------ state file
bool Ota::load()
{
    _state = State::None;
    _sha[0] = 0;
    _boots = 0;
    File f = LittleFS.open(STATE_FILE, "r");
    if (!f)
        return false;
    char line[96];
    while (f.available()) {
        size_t n = f.readBytesUntil('\n', line, sizeof(line) - 1);
        line[n] = 0;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        const char *v = eq + 1;
        if (strcmp(line, "state") == 0) {
            static const State known[] = {State::Pending, State::Confirmed, State::RolledBack, State::Failed};
            for (State s : known)
                if (strcmp(v, stateName(s)) == 0)
                    _state = s;
        } else if (strcmp(line, "sha") == 0) {
            strncpy(_sha, v, sizeof(_sha) - 1);
        } else if (strcmp(line, "boots") == 0) {
            _boots = strtoul(v, nullptr, 10);
        }
    }
    f.close();
    return true;
}

bool Ota::save()
{
    File f = LittleFS.open(STATE_FILE, "w");
    if (!f)
        return false;
    f.printf("state=%s\nsha=%s\nboots=%lu\n", stateName(_state), _sha, (unsigned long)_boots);
    f.close();
    return true;
}

// ------------------------------------------------------------------------------- trial boot
void Ota::begin()
{
    LittleFS.begin();
    load();
    switch (_state) {
    case State::Pending:
        _boots++;
        if (_boots > NODE_OTA_TRIAL_BOOTS) {
            Serial.printf("[ota] image %.8s... did not confirm in %lu boots\n", _sha, (unsigned long)_boots - 1);
            rollback();
            return;
        }
        save();
        _trialThisBoot = true;
        Serial.printf("[ota] trial boot %lu of %d for image %.8s..., %d s to confirm\n", (unsigned long)_boots,
                      NODE_OTA_TRIAL_BOOTS, _sha, NODE_OTA_TRIAL_TIMEOUT_S);
        break;
    case State::RolledBack:
        Serial.printf("[ota] running the previous image: %.8s... was rolled back\n", _sha);
        break;
    case State::Failed:
        Serial.printf("[ota] image %.8s... never confirmed and there was nothing to roll back to\n", _sha);
        break;
    default:
        break;
    }
    Serial.printf("[ota] build %s, board %s, image area %lu bytes\n", BUILD_STAMP, NODE_BOARD_ID,
                  (unsigned long)sketchArea());
}

// Puts the previous image back through the same OTA stub, or gives up if there is none
// (the running image came in over USB, or its file was already recycled).
void Ota::rollback()
{
    if (LittleFS.exists(PREV_FILE)) {
        picoOTA.begin();
        if (picoOTA.addFile(PREV_FILE) && picoOTA.commit()) {
            _state = State::RolledBack;
            save();
            Serial.println("[ota] rolling back to the previous image, rebooting");
            Serial.flush();
            delay(100);
            rp2040.reboot();
            return;
        }
        Serial.println("[ota] could not stage the previous image");
    } else {
        Serial.println("[ota] no previous image kept, staying on this one");
    }
    _state = State::Failed;
    save();
}

void Ota::confirm(const char *why)
{
    // Only the image that actually booted on trial may confirm: the one that received and
    // staged the upload is still Pending in RAM but must not confirm on its own behalf.
    if (_state != State::Pending || !_trialThisBoot)
        return;
    _state = State::Confirmed;
    _boots = 0;
    _trialThisBoot = false; // this image owes no more confirmation; a later upload it receives is not its own trial
    save();
    // The confirmed image's own file becomes the fallback at the next upload.
    LittleFS.remove(PREV_FILE);
    Serial.printf("[ota] image %.8s... confirmed (%s)\n", _sha, why);
}

void Ota::status(Print &out) const
{
    out.printf("[ota] build %s board %s state %s image %s boots %lu uptime %lu s fs free %llu image max %lu\n",
               BUILD_STAMP, NODE_BOARD_ID, stateName(_state), _sha[0] ? _sha : "-", (unsigned long)_boots,
               (unsigned long)(millis() / 1000), (unsigned long long)fsFree(), (unsigned long)sketchArea());
    const Picobin::Signed &img = runningImage();
    if (img.blockAddr)
        out.printf("[ota] running image signed: version %u.%u, key %d (%s), block 0x%08lx\n", img.major, img.minor,
                   img.keyIndex, img.keyIndex >= 0 ? "ours" : "NOT ours", (unsigned long)img.blockAddr);
    else
        out.println("[ota] running image is NOT signed");
}

// ------------------------------------------------------------------------------------ loop
void Ota::loop()
{
    if (_rebootAt != 0 && (int32_t)(millis() - _rebootAt) >= 0) {
        Serial.println("[ota] rebooting into the staged image");
        Serial.flush();
        rp2040.reboot();
    }
    // Only the trial boot times itself out. The image that just staged an upload is also
    // Pending in RAM but reboots through _rebootAt, not here.
    if (_trialThisBoot && _state == State::Pending && millis() >= (uint32_t)NODE_OTA_TRIAL_TIMEOUT_S * 1000) {
        Serial.printf("[ota] trial boot %lu not confirmed within %d s, rebooting\n", (unsigned long)_boots,
                      NODE_OTA_TRIAL_TIMEOUT_S);
        Serial.flush();
        rp2040.reboot();
    }
}

void Ota::handleStatus(EthernetClient &client)
{
    const Picobin::Signed &img = runningImage();
    OtpVault::Status otp;
    OtpVault::status(otp);
    char body[440];
    snprintf(body, sizeof(body),
             "{\"board\":\"%s\",\"build\":\"%s\",\"state\":\"%s\",\"sha256\":\"%s\",\"boots\":%lu,"
             "\"uptime_s\":%lu,\"fs_free\":%llu,\"image_max\":%lu,\"signed\":%s,\"version\":\"%u.%u\","
             "\"key\":%d,\"secure_boot\":%s,\"debug_disabled\":%s,\"chip_rev\":\"A%u\"}\n",
             NODE_BOARD_ID, BUILD_STAMP, stateName(_state), _sha, (unsigned long)_boots,
             (unsigned long)(millis() / 1000), (unsigned long long)fsFree(), (unsigned long)sketchArea(),
             img.blockAddr ? "true" : "false", img.major, img.minor, img.keyIndex, otp.secureBoot ? "true" : "false",
             otp.debugDisabled ? "true" : "false", otp.chipRevision);
    HttpApi::reply(client, 200, "application/json", body);
}

// Streams the body into IMAGE_FILE while hashing it. Afterwards the file must hash to what
// the uploader declared, carry a signature over that hash by one of the boot keys (sig, or
// nullptr when NODE_OTA_ALLOW_UNSIGNED let it through without one), start with the gzip magic
// and inflate to something that fits the sketch area (ISIZE, the gzip trailer): that is what
// the OTA stub will write to flash.
bool Ota::receiveBody(EthernetClient &client, size_t size, const uint8_t expectSha[32], const uint8_t *sig,
                      uint32_t &imageSize, const char **why)
{
    File f = LittleFS.open(IMAGE_FILE, "w");
    if (!f) {
        *why = "cannot create image file";
        return false;
    }
    SHA256 sha;
    sha.reset();
    static uint8_t buf[1024];
    size_t got = 0;
    uint32_t lastData = millis();
    uint8_t head[2] = {0, 0};
    uint8_t tail[4] = {0, 0, 0, 0};
    while (got < size) {
        watchdog_update(); // the whole upload runs inside one loop() pass; keep the watchdog fed
        int n = client.available();
        if (n <= 0) {
            if (!client.connected() || millis() - lastData > BODY_IDLE_TIMEOUT_MS) {
                f.close();
                LittleFS.remove(IMAGE_FILE);
                *why = client.connected() ? "body timeout" : "client went away";
                return false;
            }
            delay(1);
            continue;
        }
        size_t want = size - got;
        if ((size_t)n < want)
            want = n;
        if (want > sizeof(buf))
            want = sizeof(buf);
        int r = client.read(buf, want);
        if (r <= 0)
            continue;
        if (got < 2)
            for (int i = 0; i < r && got + i < 2; i++)
                head[got + i] = buf[i];
        // keep the last four bytes seen (the gzip ISIZE trailer)
        for (int i = 0; i < r; i++) {
            size_t pos = got + i;
            if (pos + 4 >= size)
                tail[pos + 4 - size] = buf[i];
        }
        if (f.write(buf, r) != (size_t)r) {
            f.close();
            LittleFS.remove(IMAGE_FILE);
            *why = "write failed (filesystem full?)";
            return false;
        }
        sha.update(buf, r);
        got += r;
        lastData = millis();
    }
    f.close();
    uint8_t digest[32];
    sha.finalize(digest, sizeof(digest));
    if (!HttpApi::constTimeEq(digest, expectSha, sizeof(digest))) {
        LittleFS.remove(IMAGE_FILE);
        *why = "sha256 mismatch";
        return false;
    }
    if (sig) {
        int key = verifySignature(digest, sig);
        if (key < 0) {
            LittleFS.remove(IMAGE_FILE);
            *why = "X-OTA-Sig does not verify against the boot keys";
            return false;
        }
        Serial.printf("[ota] upload signed by boot key %d\n", key);
    }
    if (head[0] != 0x1f || head[1] != 0x8b) {
        LittleFS.remove(IMAGE_FILE);
        *why = "not a gzip image";
        return false;
    }
    imageSize = (uint32_t)tail[0] | ((uint32_t)tail[1] << 8) | ((uint32_t)tail[2] << 16) | ((uint32_t)tail[3] << 24);
    if (imageSize == 0 || imageSize > sketchArea()) {
        LittleFS.remove(IMAGE_FILE);
        *why = "image does not fit the sketch area";
        return false;
    }
    return true;
}

void Ota::handleUpload(EthernetClient &client, const HttpApi::Request &req)
{
    const char *why = "";
    if (!httpApi.authorised(req, &why)) {
        Serial.printf("[ota] upload refused: %s\n", why);
        HttpApi::replyError(client, 401, why);
        return;
    }
    char board[40], shaHex[80];
    req.header("X-OTA-Board", board, sizeof(board));
    req.header("X-OTA-SHA256", shaHex, sizeof(shaHex));
    if (strcmp(board, NODE_BOARD_ID) != 0) {
        Serial.printf("[ota] upload refused: image for '%s', this is %s\n", board, NODE_BOARD_ID);
        HttpApi::replyError(client, 409, "image built for another board");
        return;
    }
    uint8_t expectSha[32];
    if (!HttpApi::hexToBytes(shaHex, expectSha, sizeof(expectSha))) {
        HttpApi::replyError(client, 400, "X-OTA-SHA256 missing or malformed");
        return;
    }
    char sigHex[136];
    uint8_t sig[64];
    bool haveSig = req.header("X-OTA-Sig", sigHex, sizeof(sigHex));
    if (haveSig && !HttpApi::hexToBytes(sigHex, sig, sizeof(sig))) {
        HttpApi::replyError(client, 400, "X-OTA-Sig malformed (128 hex chars, r||s)");
        return;
    }
#ifndef NODE_OTA_ALLOW_UNSIGNED
    if (!haveSig) {
        Serial.println("[ota] upload refused: no X-OTA-Sig (unsigned uploads are not accepted)");
        HttpApi::replyError(client, 403, "upload is not signed");
        return;
    }
#endif
    if (req.contentLength == 0 || req.contentLength > sketchArea()) {
        HttpApi::replyError(client, 400, "Content-Length missing or implausible");
        return;
    }
    // The image that was running when this upload came in is the rollback target. After a
    // rollback IMAGE_FILE holds the image that failed, so it is dropped instead.
    if (LittleFS.exists(IMAGE_FILE)) {
        if (_state == State::RolledBack)
            LittleFS.remove(IMAGE_FILE);
        else {
            LittleFS.remove(PREV_FILE);
            LittleFS.rename(IMAGE_FILE, PREV_FILE);
        }
    }
    // A small filesystem (the 2 MB carrier) may not hold two images next to the store: the
    // upload still goes through, without a rollback image.
    if (fsFree() < req.contentLength + FS_KEEP_FREE && LittleFS.exists(PREV_FILE)) {
        LittleFS.remove(PREV_FILE);
        Serial.println("[ota] no room to keep the previous image, a rollback will not be possible");
    }
    if (fsFree() < req.contentLength + FS_KEEP_FREE) {
        Serial.printf("[ota] upload refused: %lu bytes free, %u + %u needed\n", (unsigned long)fsFree(),
                      (unsigned)req.contentLength, (unsigned)FS_KEEP_FREE);
        HttpApi::replyError(client, 507, "not enough filesystem space");
        return;
    }
    Serial.printf("[ota] receiving %u bytes for %s\n", (unsigned)req.contentLength, board);
    uint32_t imageSize = 0;
    if (!receiveBody(client, req.contentLength, expectSha, haveSig ? sig : nullptr, imageSize, &why)) {
        Serial.printf("[ota] upload failed: %s\n", why);
        HttpApi::replyError(client, strstr(why, "X-OTA-Sig") ? 403 : 422, why);
        return;
    }
    picoOTA.begin();
    if (!picoOTA.addFile(IMAGE_FILE) || !picoOTA.commit()) {
        LittleFS.remove(IMAGE_FILE);
        Serial.println("[ota] could not stage the image (OTA command not written)");
        HttpApi::replyError(client, 500, "could not stage the image");
        return;
    }
    _state = State::Pending;
    _boots = 0;
    _trialThisBoot = false; // the pending image is the *next* boot's trial, not this running one's
    strncpy(_sha, shaHex, sizeof(_sha) - 1);
    save();
    char body[160];
    snprintf(body, sizeof(body), "{\"ok\":true,\"sha256\":\"%s\",\"size\":%u,\"image\":%lu}\n", shaHex,
             (unsigned)req.contentLength, (unsigned long)imageSize);
    HttpApi::reply(client, 200, "application/json", body);
    Serial.printf("[ota] staged %.8s... (%u bytes gzip, %lu bytes image), rebooting in 500 ms\n", shaHex,
                  (unsigned)req.contentLength, (unsigned long)imageSize);
    _rebootAt = millis() + 500;
}

// ------------------------------------------------------------------------------------ routes
static void thunkStatus(EthernetClient &client, const HttpApi::Request &req)
{
    (void)req;
    ota.handleStatus(client);
}

static void thunkUpload(EthernetClient &client, const HttpApi::Request &req)
{
    ota.handleUpload(client, req);
}

void otaRegisterRoutes()
{
    httpApi.route("GET", "/ota/status", thunkStatus);
    httpApi.route("PUT", "/ota", thunkUpload);
}
