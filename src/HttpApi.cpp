#include "HttpApi.h"

#include <SHA256.h>
#include <string.h>
#include <strings.h>

HttpApi httpApi;

static constexpr size_t HEAD_MAX = 2048;
static constexpr uint32_t HEAD_TIMEOUT_MS = 3000;
static constexpr uint32_t BODY_TIMEOUT_MS = 5000;

static char s_head[HEAD_MAX]; // the request head of the request being served

// ---------------------------------------------------------------------------------- helpers
bool HttpApi::hexToBytes(const char *hex, uint8_t *out, size_t n)
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

void HttpApi::bytesToHex(const uint8_t *in, size_t n, char *out)
{
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[n * 2] = 0;
}

bool HttpApi::constTimeEq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

bool HttpApi::Request::header(const char *name, char *out, size_t cap) const
{
    out[0] = 0;
    if (!head)
        return false;
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

// ------------------------------------------------------------------------------------ replies
void HttpApi::reply(EthernetClient &client, int code, const char *type, const char *body)
{
    client.printf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %u\r\nConnection: close\r\n\r\n", code,
                  code == 200 ? "OK" : "Error", type, (unsigned)strlen(body));
    client.print(body);
}

void HttpApi::replyError(EthernetClient &client, int code, const char *what)
{
    char body[160];
    snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}\n", what);
    reply(client, code, "application/json", body);
}

bool HttpApi::readBody(EthernetClient &client, size_t size, char *buf, size_t cap)
{
    if (size + 1 > cap)
        return false;
    size_t got = 0;
    uint32_t t0 = millis();
    while (got < size && millis() - t0 < BODY_TIMEOUT_MS) {
        int n = client.read((uint8_t *)buf + got, size - got);
        if (n > 0) {
            got += n;
            t0 = millis();
        } else if (!client.connected()) {
            break;
        } else {
            delay(1);
        }
    }
    buf[got] = 0;
    return got == size;
}

// --------------------------------------------------------------------------------------- auth
void HttpApi::handleNonce(EthernetClient &client)
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

bool HttpApi::authorised(const Request &req, const char **why)
{
    if (_lastAuthFailure != 0 && millis() - _lastAuthFailure < (uint32_t)NODE_API_AUTH_COOLDOWN_S * 1000) {
        *why = "cooldown";
        return false;
    }
    char nonceHex[80], authHex[80];
    req.header("X-Auth-Nonce", nonceHex, sizeof(nonceHex));
    req.header("X-Auth", authHex, sizeof(authHex));

    bool ok = false;
    uint8_t nonce[32], auth[32], expect[32], psk[32];
    if (!_nonceValid || millis() - _nonceIssued > (uint32_t)NODE_API_NONCE_TTL_S * 1000) {
        *why = "no fresh nonce";
    } else if (!hexToBytes(nonceHex, nonce, sizeof(nonce)) || !constTimeEq(nonce, _nonce, sizeof(nonce))) {
        *why = "nonce mismatch";
    } else if (!hexToBytes(authHex, auth, sizeof(auth)) || !hexToBytes(NODE_API_PSK_HEX, psk, sizeof(psk))) {
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
    _nonceValid = false; // one shot, whatever the outcome
    if (!ok)
        _lastAuthFailure = millis();
    return ok;
}

// ------------------------------------------------------------------------------------- server
bool HttpApi::route(const char *method, const char *path, Handler handler)
{
    if (_routeCount >= MAX_ROUTES)
        return false;
    _routes[_routeCount++] = {method, path, handler};
    return true;
}

void HttpApi::loop()
{
    if (!_started && Ethernet.localIP() != IPAddress(0, 0, 0, 0)) {
        _server.begin();
        _started = true;
        Serial.printf("[api] listening on %u\n", NODE_API_PORT);
    }
    if (_started)
        serve();
}

bool HttpApi::readHead(EthernetClient &client, char *buf, size_t cap, size_t &len)
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

void HttpApi::serve()
{
    EthernetClient client = _server.accept();
    if (!client)
        return;
    size_t len;
    if (!readHead(client, s_head, HEAD_MAX, len)) {
        replyError(client, 400, "bad request");
        client.stop();
        return;
    }
    Request req = {};
    req.head = s_head;
    if (sscanf(s_head, "%7s %47s", req.method, req.path) != 2) {
        replyError(client, 400, "bad request line");
        client.stop();
        return;
    }
    char tmp[16];
    if (req.header("Content-Length", tmp, sizeof(tmp)))
        req.contentLength = strtoul(tmp, nullptr, 10);

    if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/nonce") == 0) {
        handleNonce(client);
    } else {
        Handler handler = nullptr;
        for (size_t i = 0; i < _routeCount && !handler; i++)
            if (strcmp(req.method, _routes[i].method) == 0 && strcmp(req.path, _routes[i].path) == 0)
                handler = _routes[i].handler;
        if (handler)
            handler(client, req);
        else
            replyError(client, 404, "no such route");
    }
    client.flush();
    client.stop();
}
