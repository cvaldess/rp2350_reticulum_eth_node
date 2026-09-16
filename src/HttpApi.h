// The node's HTTP surface on the LAN: one minimal HTTP/1.1 server that the OTA (src/Ota.cpp)
// and the runtime settings (src/NodeSettings.cpp) both hang their routes off, so there is one
// socket, one nonce and one place where a request is authenticated.
//
// Auth is the Meshtastic fork's OTA scheme: GET /nonce hands out 32 random bytes, one shot and
// short-lived, and a write quotes it with X-Auth = SHA-256(nonce || PSK). Any failure burns the
// nonce and starts a cooldown. It is a pre-shared key, so this is LAN-only by design.
#pragma once

#include <Arduino.h>
#include <Ethernet.h>

#include "node_config.h"

class HttpApi
{
  public:
    struct Request {
        char method[8];
        char path[48];
        size_t contentLength;
        const char *head; // the raw request head, for header()
        // Copies a header value (case-insensitive name) into out; false if it is absent.
        bool header(const char *name, char *out, size_t cap) const;
    };

    using Handler = void (*)(EthernetClient &client, const Request &req);

    // Starts listening as soon as there is an IP; safe to call every loop pass.
    void loop();
    // Routes are matched exactly, in registration order. Returns false if the table is full.
    bool route(const char *method, const char *path, Handler handler);

    // Checks X-Auth against the outstanding nonce. Consumes the nonce either way.
    bool authorised(const Request &req, const char **why);

    static void reply(EthernetClient &client, int code, const char *type, const char *body);
    static void replyError(EthernetClient &client, int code, const char *what);
    // Reads up to cap-1 bytes of body into buf and NUL-terminates it. For small payloads
    // (settings); the OTA streams its body itself instead of buffering it.
    static bool readBody(EthernetClient &client, size_t size, char *buf, size_t cap);

    static bool hexToBytes(const char *hex, uint8_t *out, size_t n);
    static void bytesToHex(const uint8_t *in, size_t n, char *out);
    static bool constTimeEq(const uint8_t *a, const uint8_t *b, size_t n);

  private:
    struct Route {
        const char *method;
        const char *path;
        Handler handler;
    };
    static constexpr size_t MAX_ROUTES = 8;

    void serve();
    bool readHead(EthernetClient &client, char *buf, size_t cap, size_t &len);
    void handleNonce(EthernetClient &client);

    EthernetServer _server{NODE_API_PORT};
    bool _started = false;
    Route _routes[MAX_ROUTES];
    size_t _routeCount = 0;

    uint8_t _nonce[32];
    uint32_t _nonceIssued = 0;
    bool _nonceValid = false;
    uint32_t _lastAuthFailure = 0;
};

extern HttpApi httpApi;
