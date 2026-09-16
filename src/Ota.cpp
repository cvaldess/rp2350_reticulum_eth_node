#include "Ota.h"

#include "build_id.h"
#include <LittleFS.h>
#include <PicoOTA.h>
#include <SHA256.h>
#include <hardware/regs/addressmap.h>
#include <string.h>
#include <strings.h>

Ota ota;

extern uint8_t _FS_start; // arduino-pico flash layout: sketch | LittleFS | EEPROM

static const char *STATE_FILE = "/ota_state";
static const char *IMAGE_FILE = "firmware.bin";      // the name the OTA command carries
static const char *PREV_FILE = "firmware.prev.bin";  // what was running when the last upload came in
static const char *BUILD_STAMP = NODE_BUILD_ID; // "<sha7>[-dirty] <UTC time>" from tools/build_id.py

static constexpr size_t HEAD_MAX = 2048;
static constexpr uint32_t HEAD_TIMEOUT_MS = 3000;
static constexpr uint32_t BODY_IDLE_TIMEOUT_MS = 30000;
static constexpr size_t FS_KEEP_FREE = 64 * 1024; // room the Reticulum store must keep

struct Ota::Request {
    char method[8];
    char path[32];
    char nonce[65];
    char auth[65];
    char sha[65];
    char board[40];
    size_t contentLength;
};

// ---------------------------------------------------------------------------------- helpers
static bool hexToBytes(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != n * 2)
        return false;
    for (size_t i = 0; i < n; i++) {
        uint8_t v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[i * 2 + k];
            v <<= 4;
            if (c >= '0' && c <= '9')
                v |= c - '0';
            else if (c >= 'a' && c <= 'f')
                v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                v |= c - 'A' + 10;
            else
                return false;
        }
        out[i] = v;
    }
    return true;
}

static void bytesToHex(const uint8_t *in, size_t n, char *out)
{
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[n * 2] = 0;
}

static bool constTimeEq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

// Header lookup, case-insensitive name, value trimmed and copied (bounded).
static bool header(const char *head, const char *name, char *out, size_t cap)
{
    size_t n = strlen(name);
    for (const char *p = head; (p = strstr(p, "\r\n")) != nullptr;) {
        p += 2;
        if (strncasecmp(p, name, n) == 0 && p[n] == ':') {
            p += n + 1;
            while (*p == ' ' || *p == '\t')
                p++;
            size_t len = 0;
            while (p[len] && p[len] != '\r' && len + 1 < cap)
                len++;
            memcpy(out, p, len);
            out[len] = 0;
            return true;
        }
    }
    return false;
}

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
}

// ------------------------------------------------------------------------------------ loop
void Ota::loop()
{
    static bool started = false;
    if (!started && Ethernet.localIP() != IPAddress(0, 0, 0, 0)) {
        _server.begin();
        started = true;
        Serial.printf("[ota] listening on %u\n", NODE_OTA_PORT);
    }
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
    if (started)
        serve();
}

bool Ota::readHead(EthernetClient &client, char *buf, size_t cap, size_t &len)
{
    len = 0;
    uint32_t t0 = millis();
    while (client.connected() && millis() - t0 < HEAD_TIMEOUT_MS) {
        while (client.available() && len + 1 < cap) {
            buf[len++] = client.read();
            buf[len] = 0;
            if (len >= 4 && memcmp(buf + len - 4, "\r\n\r\n", 4) == 0)
                return true;
        }
        if (len + 1 >= cap)
            return false;
        delay(1);
    }
    return false;
}

void Ota::serve()
{
    EthernetClient client = _server.accept();
    if (!client)
        return;
    static char head[HEAD_MAX];
    size_t len;
    if (!readHead(client, head, sizeof(head), len)) {
        replyError(client, 400, "bad request");
        client.stop();
        return;
    }
    Request req = {};
    if (sscanf(head, "%7s %31s", req.method, req.path) != 2) {
        replyError(client, 400, "bad request line");
        client.stop();
        return;
    }
    char tmp[16];
    if (header(head, "Content-Length", tmp, sizeof(tmp)))
        req.contentLength = strtoul(tmp, nullptr, 10);
    header(head, "X-OTA-Nonce", req.nonce, sizeof(req.nonce));
    header(head, "X-OTA-Auth", req.auth, sizeof(req.auth));
    header(head, "X-OTA-SHA256", req.sha, sizeof(req.sha));
    header(head, "X-OTA-Board", req.board, sizeof(req.board));

    if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/ota/nonce") == 0)
        handleNonce(client);
    else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/ota/status") == 0)
        handleStatus(client);
    else if (strcmp(req.method, "PUT") == 0 && strcmp(req.path, "/ota") == 0)
        handleUpload(client, req);
    else
        replyError(client, 404, "no such route");
    client.flush();
    client.stop();
}

void Ota::reply(EthernetClient &client, int code, const char *type, const char *body)
{
    client.printf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %u\r\nConnection: close\r\n\r\n", code,
                  code == 200 ? "OK" : "Error", type, (unsigned)strlen(body));
    client.print(body);
}

void Ota::replyError(EthernetClient &client, int code, const char *what)
{
    char body[128];
    snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}\n", what);
    reply(client, code, "application/json", body);
}

// A fresh 32-byte nonce, one shot, NODE_OTA_NONCE_TTL_S to use it.
void Ota::handleNonce(EthernetClient &client)
{
    for (size_t i = 0; i < sizeof(_nonce); i += 4) {
        uint32_t r = rp2040.hwrand32();
        memcpy(_nonce + i, &r, 4);
    }
    _nonceIssued = millis();
    _nonceValid = true;
    char hex[65];
    bytesToHex(_nonce, sizeof(_nonce), hex);
    reply(client, 200, "text/plain", hex);
}

void Ota::handleStatus(EthernetClient &client)
{
    char body[320];
    snprintf(body, sizeof(body),
             "{\"board\":\"%s\",\"build\":\"%s\",\"state\":\"%s\",\"sha256\":\"%s\",\"boots\":%lu,"
             "\"uptime_s\":%lu,\"fs_free\":%llu,\"image_max\":%lu}\n",
             NODE_BOARD_ID, BUILD_STAMP, stateName(_state), _sha, (unsigned long)_boots,
             (unsigned long)(millis() / 1000), (unsigned long long)fsFree(), (unsigned long)sketchArea());
    reply(client, 200, "application/json", body);
}

// Nonce known, fresh and unused; auth = SHA-256(nonce || PSK). Any failure burns the nonce and
// starts the cooldown, so guessing costs NODE_OTA_AUTH_COOLDOWN_S per try.
bool Ota::authorised(const Request &req, const char **why)
{
    if (_lastAuthFailure != 0 && millis() - _lastAuthFailure < (uint32_t)NODE_OTA_AUTH_COOLDOWN_S * 1000) {
        *why = "cooldown";
        return false;
    }
    bool ok = false;
    uint8_t nonce[32], auth[32], expect[32], psk[32];
    if (!_nonceValid || millis() - _nonceIssued > (uint32_t)NODE_OTA_NONCE_TTL_S * 1000) {
        *why = "no fresh nonce";
    } else if (!hexToBytes(req.nonce, nonce, sizeof(nonce)) || !constTimeEq(nonce, _nonce, sizeof(nonce))) {
        *why = "nonce mismatch";
    } else if (!hexToBytes(req.auth, auth, sizeof(auth)) || !hexToBytes(NODE_OTA_PSK_HEX, psk, sizeof(psk))) {
        *why = "bad auth encoding";
    } else {
        SHA256 sha;
        sha.reset();
        sha.update(_nonce, sizeof(_nonce));
        sha.update(psk, sizeof(psk));
        sha.finalize(expect, sizeof(expect));
        ok = constTimeEq(auth, expect, sizeof(expect));
        if (!ok)
            *why = "auth mismatch";
    }
    _nonceValid = false;
    if (!ok)
        _lastAuthFailure = millis();
    return ok;
}

// Streams the body into IMAGE_FILE while hashing it. Afterwards the file must hash to what
// the uploader declared, start with the gzip magic and inflate to something that fits the
// sketch area (ISIZE, the gzip trailer): that is what the OTA stub will write to flash.
bool Ota::receiveBody(EthernetClient &client, size_t size, const uint8_t expectSha[32], uint32_t &imageSize,
                      const char **why)
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
    if (!constTimeEq(digest, expectSha, sizeof(digest))) {
        LittleFS.remove(IMAGE_FILE);
        *why = "sha256 mismatch";
        return false;
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

void Ota::handleUpload(EthernetClient &client, const Request &req)
{
    const char *why = "";
    if (!authorised(req, &why)) {
        Serial.printf("[ota] upload refused: %s\n", why);
        replyError(client, 401, why);
        return;
    }
    if (strcmp(req.board, NODE_BOARD_ID) != 0) {
        Serial.printf("[ota] upload refused: image for '%s', this is %s\n", req.board, NODE_BOARD_ID);
        replyError(client, 409, "image built for another board");
        return;
    }
    uint8_t expectSha[32];
    if (!hexToBytes(req.sha, expectSha, sizeof(expectSha))) {
        replyError(client, 400, "X-OTA-SHA256 missing or malformed");
        return;
    }
    if (req.contentLength == 0 || req.contentLength > sketchArea()) {
        replyError(client, 400, "Content-Length missing or implausible");
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
        replyError(client, 507, "not enough filesystem space");
        return;
    }
    Serial.printf("[ota] receiving %u bytes for %s\n", (unsigned)req.contentLength, req.board);
    uint32_t imageSize = 0;
    if (!receiveBody(client, req.contentLength, expectSha, imageSize, &why)) {
        Serial.printf("[ota] upload failed: %s\n", why);
        replyError(client, 422, why);
        return;
    }
    picoOTA.begin();
    if (!picoOTA.addFile(IMAGE_FILE) || !picoOTA.commit()) {
        LittleFS.remove(IMAGE_FILE);
        Serial.println("[ota] could not stage the image (OTA command not written)");
        replyError(client, 500, "could not stage the image");
        return;
    }
    _state = State::Pending;
    _boots = 0;
    _trialThisBoot = false; // the pending image is the *next* boot's trial, not this running one's
    strncpy(_sha, req.sha, sizeof(_sha) - 1);
    save();
    char body[160];
    snprintf(body, sizeof(body), "{\"ok\":true,\"sha256\":\"%s\",\"size\":%u,\"image\":%lu}\n", req.sha,
             (unsigned)req.contentLength, (unsigned long)imageSize);
    reply(client, 200, "application/json", body);
    Serial.printf("[ota] staged %.8s... (%u bytes gzip, %lu bytes image), rebooting in 500 ms\n", req.sha,
                  (unsigned)req.contentLength, (unsigned long)imageSize);
    _rebootAt = millis() + 500;
}
