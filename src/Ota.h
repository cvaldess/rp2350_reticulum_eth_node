// Ethernet OTA with a trial boot (docs/ota.md).
//
// Upload: PUT /ota on the shared HTTP API (src/HttpApi.h) takes the gzip'd image over the LAN,
// checks it (the API's nonce + SHA-256(nonce||PSK), the board name, the SHA-256 of the body, the
// gzip header and the uncompressed size against the sketch area) and only then hands it to
// arduino-pico's OTA stub, which copies it into flash on the next boot. The stub verifies
// nothing, so every check lives here, before the command is committed.
//
// Signature (docs/secure_boot.md): X-OTA-Sig is an ECDSA secp256k1 signature over the SHA-256
// of the gzip body by one of the boot signing keys (include/boot_pubkeys.h). Without it, or with
// one that does not verify, the upload is refused: on a board with secure boot the bootrom would
// reject an image nobody signed, and this rollback cannot run on an image that never boots.
// -D NODE_OTA_ALLOW_UNSIGNED (bench, board not yet secured) accepts an upload with no signature.
//
// Trial: the new image boots with /ota_state = pending and has to confirm itself (SE050 probe
// passed and the first announce went out signed) within NODE_OTA_TRIAL_TIMEOUT_S, or it
// reboots. After NODE_OTA_TRIAL_BOOTS unconfirmed boots the previous image (kept as
// firmware.prev.bin when the new one was uploaded) is put back. A crash before setup() is
// not covered: that needs the stub itself to count boots.
#pragma once

#include <Arduino.h>
#include <Ethernet.h>

#include "HttpApi.h"
#include "node_config.h"

class Ota
{
  public:
    enum class State { None, Pending, Confirmed, RolledBack, Failed };

    // First thing in setup(): reads the state, counts the trial boot, rolls back if it is the
    // one too many. Mounts LittleFS (idempotent: the Reticulum store mounts it again later).
    void begin();
    // Enforces the trial timeout and carries out the reboot into a staged image. Call from loop().
    void loop();
    // Marks the trial passed. No-op unless this boot is the one on trial.
    void confirm(const char *why);

    State state() const { return _state; }
    bool pending() const { return _state == State::Pending; }
    void status(Print &out) const;

    // Called by the route thunks in Ota.cpp.
    void handleStatus(EthernetClient &client);
    void handleUpload(EthernetClient &client, const HttpApi::Request &req);

  private:
    static const char *stateName(State s);
    bool load();
    bool save();
    void rollback();
    bool receiveBody(EthernetClient &client, size_t size, const uint8_t expectSha[32], const uint8_t *sig,
                     uint32_t &imageSize, const char **why);

    State _state = State::None;
    char _sha[65] = {0};   // hex SHA-256 of the staged / running gzip'd image
    uint32_t _boots = 0;   // unconfirmed boots of the pending image, this one included
    uint32_t _rebootAt = 0;
    // Set only by begin(), only when it booted into a Pending state: this running image is the
    // one on trial. Without it, the image that *receives* the upload would confirm the trial it
    // just staged (its own loop sees Pending + se050 + announcedOnce) before the new image boots.
    bool _trialThisBoot = false;
};

extern Ota ota;

// Registers /ota and /ota/status on the shared HTTP API.
void otaRegisterRoutes();
