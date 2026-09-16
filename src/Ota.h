// Ethernet OTA with a trial boot (docs/ota.md).
//
// Upload: a minimal HTTP/1.1 server on NODE_OTA_PORT takes the gzip'd image over the LAN,
// checks it (nonce + SHA-256(nonce||PSK), board name, SHA-256 of the body, gzip header and
// uncompressed size against the sketch area) and only then hands it to arduino-pico's OTA
// stub, which copies it into flash on the next boot. The stub verifies nothing, so every
// check lives here, before the command is committed.
//
// Trial: the new image boots with /ota_state = pending and has to confirm itself (SE050 probe
// passed and the first announce went out signed) within NODE_OTA_TRIAL_TIMEOUT_S, or it
// reboots. After NODE_OTA_TRIAL_BOOTS unconfirmed boots the previous image (kept as
// firmware.prev.bin when the new one was uploaded) is put back. A crash before setup() is
// not covered: that needs the stub itself to count boots.
#pragma once

#include <Arduino.h>
#include <Ethernet.h>

#include "node_config.h"

class Ota
{
  public:
    enum class State { None, Pending, Confirmed, RolledBack, Failed };

    // First thing in setup(): reads the state, counts the trial boot, rolls back if it is the
    // one too many. Mounts LittleFS (idempotent: the Reticulum store mounts it again later).
    void begin();
    // Serves one HTTP request per pass and enforces the trial timeout. Call from loop().
    void loop();
    // Marks the trial passed. No-op unless one is pending.
    void confirm(const char *why);

    State state() const { return _state; }
    bool pending() const { return _state == State::Pending; }
    void status(Print &out) const;

  private:
    struct Request;
    static const char *stateName(State s);
    bool load();
    bool save();
    void rollback();

    void serve();
    bool readHead(EthernetClient &client, char *buf, size_t cap, size_t &len);
    void handleNonce(EthernetClient &client);
    void handleStatus(EthernetClient &client);
    void handleUpload(EthernetClient &client, const Request &req);
    void reply(EthernetClient &client, int code, const char *type, const char *body);
    void replyError(EthernetClient &client, int code, const char *what);
    bool authorised(const Request &req, const char **why);
    bool receiveBody(EthernetClient &client, size_t size, const uint8_t expectSha[32], uint32_t &imageSize,
                     const char **why);

    EthernetServer _server{NODE_OTA_PORT};
    State _state = State::None;
    char _sha[65] = {0};   // hex SHA-256 of the staged / running gzip'd image
    uint32_t _boots = 0;   // unconfirmed boots of the pending image, this one included
    uint32_t _rebootAt = 0;
    // Set only by begin(), only when it booted into a Pending state: this running image is the
    // one on trial. Without it, the image that *receives* the upload would confirm the trial it
    // just staged (its own loop sees Pending + se050 + announcedOnce) before the new image boots.
    bool _trialThisBoot = false;

    uint8_t _nonce[32];
    uint32_t _nonceIssued = 0;
    bool _nonceValid = false;
    uint32_t _lastAuthFailure = 0;
};

extern Ota ota;
