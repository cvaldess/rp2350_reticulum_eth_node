#include "NodeSettings.h"

#include <ArduinoJson.h>
#include <LittleFS.h>
#include <string.h>

#include "HttpApi.h"

NodeSettings settings;

static const char *SETTINGS_FILE = "/node_settings";

// Index into _overridden, and the key in the file and in JSON.
enum Field { F_ANNOUNCE = 0, F_TXPOWER, F_NTP, F_TCP_HOST, F_TCP_PORT, F_COUNT };
static const char *KEY[F_COUNT] = {"announce_interval_s", "lora_tx_power_dbm", "ntp_interval_s", "tcp_host",
                                   "tcp_port"};

// Bounds. announce: below ~10 s a node would spend its duty cycle announcing; the upper end is a
// day. tx power is at the antenna (LoRaInterface clamps what the SX1262 can actually do).
static constexpr uint32_t ANNOUNCE_MIN = 10, ANNOUNCE_MAX = 86400;
static constexpr int TXPOWER_MIN = -9, TXPOWER_MAX = 30;
static constexpr uint32_t NTP_MIN = 60, NTP_MAX = 604800;

static bool validIpv4(const char *s)
{
    IPAddress ip;
    return ip.fromString(s);
}

void NodeSettings::setDefaults()
{
    _announceIntervalS = NODE_ANNOUNCE_INTERVAL_S;
    _loraTxPowerDbm = LORA_TX_POWER_DBM;
    _ntpIntervalS = NODE_NTP_INTERVAL_S;
    strncpy(_tcpHost, RNS_TCP_TARGET_HOST, sizeof(_tcpHost) - 1);
    _tcpHost[sizeof(_tcpHost) - 1] = 0;
    _tcpPort = RNS_TCP_TARGET_PORT;
    for (size_t i = 0; i < F_COUNT; i++)
        _overridden[i] = false;
}

void NodeSettings::begin()
{
    LittleFS.begin();
    setDefaults();
    if (load())
        Serial.printf("[settings] overrides loaded from %s\n", SETTINGS_FILE);
    Serial.printf("[settings] announce %lus, tx %d dBm, ntp %lus, rnsd %s:%u\n",
                  (unsigned long)_announceIntervalS, _loraTxPowerDbm, (unsigned long)_ntpIntervalS, _tcpHost,
                  _tcpPort);
}

bool NodeSettings::load()
{
    File f = LittleFS.open(SETTINGS_FILE, "r");
    if (!f)
        return false;
    bool any = false;
    char line[96];
    while (f.available()) {
        size_t n = f.readBytesUntil('\n', line, sizeof(line) - 1);
        line[n] = 0;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        const char *v = eq + 1;
        if (strcmp(line, KEY[F_ANNOUNCE]) == 0) {
            _announceIntervalS = strtoul(v, nullptr, 10);
            _overridden[F_ANNOUNCE] = any = true;
        } else if (strcmp(line, KEY[F_TXPOWER]) == 0) {
            _loraTxPowerDbm = (int8_t)strtol(v, nullptr, 10);
            _overridden[F_TXPOWER] = any = true;
        } else if (strcmp(line, KEY[F_NTP]) == 0) {
            _ntpIntervalS = strtoul(v, nullptr, 10);
            _overridden[F_NTP] = any = true;
        } else if (strcmp(line, KEY[F_TCP_HOST]) == 0) {
            strncpy(_tcpHost, v, sizeof(_tcpHost) - 1);
            _tcpHost[sizeof(_tcpHost) - 1] = 0;
            _overridden[F_TCP_HOST] = any = true;
        } else if (strcmp(line, KEY[F_TCP_PORT]) == 0) {
            _tcpPort = (uint16_t)strtoul(v, nullptr, 10);
            _overridden[F_TCP_PORT] = any = true;
        }
    }
    f.close();
    return any;
}

bool NodeSettings::save()
{
    File f = LittleFS.open(SETTINGS_FILE, "w");
    if (!f)
        return false;
    if (_overridden[F_ANNOUNCE])
        f.printf("%s=%lu\n", KEY[F_ANNOUNCE], (unsigned long)_announceIntervalS);
    if (_overridden[F_TXPOWER])
        f.printf("%s=%d\n", KEY[F_TXPOWER], _loraTxPowerDbm);
    if (_overridden[F_NTP])
        f.printf("%s=%lu\n", KEY[F_NTP], (unsigned long)_ntpIntervalS);
    if (_overridden[F_TCP_HOST])
        f.printf("%s=%s\n", KEY[F_TCP_HOST], _tcpHost);
    if (_overridden[F_TCP_PORT])
        f.printf("%s=%u\n", KEY[F_TCP_PORT], _tcpPort);
    f.close();
    return true;
}

bool NodeSettings::reset()
{
    // Only the boot-only fields need a reboot to go back, and only if they were overridden.
    bool bootOnlyWasSet = _overridden[F_TCP_HOST] || _overridden[F_TCP_PORT];
    setDefaults();
    LittleFS.remove(SETTINGS_FILE);
    if (bootOnlyWasSet)
        _rebootPending = true;
    if (_applyTxPower)
        _applyTxPower(_loraTxPowerDbm);
    Serial.println("[settings] overrides dropped, compile-time defaults apply");
    return true;
}

void NodeSettings::toJson(char *out, size_t cap) const
{
    char overridden[160] = "";
    for (size_t i = 0; i < F_COUNT; i++)
        if (_overridden[i])
            snprintf(overridden + strlen(overridden), sizeof(overridden) - strlen(overridden), "%s\"%s\"",
                     overridden[0] ? "," : "", KEY[i]);
    snprintf(out, cap,
             "{\"%s\":%lu,\"%s\":%d,\"%s\":%lu,\"%s\":\"%s\",\"%s\":%u,"
             "\"overridden\":[%s],\"reboot_pending\":%s,"
             "\"defaults\":{\"%s\":%d,\"%s\":%d,\"%s\":%d,\"%s\":\"%s\",\"%s\":%d}}\n",
             KEY[F_ANNOUNCE], (unsigned long)_announceIntervalS, KEY[F_TXPOWER], _loraTxPowerDbm, KEY[F_NTP],
             (unsigned long)_ntpIntervalS, KEY[F_TCP_HOST], _tcpHost, KEY[F_TCP_PORT], _tcpPort, overridden,
             _rebootPending ? "true" : "false", KEY[F_ANNOUNCE], NODE_ANNOUNCE_INTERVAL_S, KEY[F_TXPOWER],
             LORA_TX_POWER_DBM, KEY[F_NTP], NODE_NTP_INTERVAL_S, KEY[F_TCP_HOST], RNS_TCP_TARGET_HOST,
             KEY[F_TCP_PORT], RNS_TCP_TARGET_PORT);
}

// Validates the whole body first, so a request with one bad field changes nothing.
bool NodeSettings::applyJson(const char *json, char *err, size_t errCap, char *changed, size_t changedCap)
{
    JsonDocument doc;
    DeserializationError e = deserializeJson(doc, json);
    if (e) {
        snprintf(err, errCap, "bad JSON: %s", e.c_str());
        return false;
    }
    if (!doc.is<JsonObject>()) {
        snprintf(err, errCap, "body must be a JSON object");
        return false;
    }
    uint32_t announce = _announceIntervalS, ntp = _ntpIntervalS;
    int txpower = _loraTxPowerDbm;
    uint16_t port = _tcpPort;
    char host[sizeof(_tcpHost)];
    strncpy(host, _tcpHost, sizeof(host));
    bool set[F_COUNT] = {false, false, false, false, false};
    size_t known = 0;

    for (JsonPair kv : doc.as<JsonObject>()) {
        const char *k = kv.key().c_str();
        if (strcmp(k, KEY[F_ANNOUNCE]) == 0) {
            announce = kv.value().as<uint32_t>();
            if (announce < ANNOUNCE_MIN || announce > ANNOUNCE_MAX) {
                snprintf(err, errCap, "%s must be %lu..%lu", k, (unsigned long)ANNOUNCE_MIN,
                         (unsigned long)ANNOUNCE_MAX);
                return false;
            }
            set[F_ANNOUNCE] = true;
        } else if (strcmp(k, KEY[F_TXPOWER]) == 0) {
            txpower = kv.value().as<int>();
            if (txpower < TXPOWER_MIN || txpower > TXPOWER_MAX) {
                snprintf(err, errCap, "%s must be %d..%d", k, TXPOWER_MIN, TXPOWER_MAX);
                return false;
            }
            set[F_TXPOWER] = true;
        } else if (strcmp(k, KEY[F_NTP]) == 0) {
            ntp = kv.value().as<uint32_t>();
            if (ntp < NTP_MIN || ntp > NTP_MAX) {
                snprintf(err, errCap, "%s must be %lu..%lu", k, (unsigned long)NTP_MIN, (unsigned long)NTP_MAX);
                return false;
            }
            set[F_NTP] = true;
        } else if (strcmp(k, KEY[F_TCP_HOST]) == 0) {
            const char *v = kv.value().as<const char *>();
            if (!v || strlen(v) >= sizeof(_tcpHost) || !validIpv4(v)) {
                snprintf(err, errCap, "%s must be a dotted IPv4 address", k);
                return false;
            }
            strncpy(host, v, sizeof(host) - 1);
            host[sizeof(host) - 1] = 0;
            set[F_TCP_HOST] = true;
        } else if (strcmp(k, KEY[F_TCP_PORT]) == 0) {
            uint32_t p = kv.value().as<uint32_t>();
            if (p == 0 || p > 65535) {
                snprintf(err, errCap, "%s must be 1..65535", k);
                return false;
            }
            port = (uint16_t)p;
            set[F_TCP_PORT] = true;
        } else {
            snprintf(err, errCap, "unknown setting '%s'", k);
            return false;
        }
        known++;
    }
    if (known == 0) {
        snprintf(err, errCap, "no settings in the body");
        return false;
    }

    // Everything validated: commit. The PA is the only one that needs an action, and if the
    // radio refuses the new power nothing is stored, so the file never disagrees with the radio.
    if (set[F_TXPOWER] && txpower != _loraTxPowerDbm) {
        if (_applyTxPower && !_applyTxPower((int8_t)txpower)) {
            snprintf(err, errCap, "the radio refused %d dBm", txpower);
            return false;
        }
        _loraTxPowerDbm = (int8_t)txpower;
        _overridden[F_TXPOWER] = true;
    } else if (set[F_TXPOWER]) {
        _overridden[F_TXPOWER] = true;
    }
    if (set[F_ANNOUNCE]) {
        _announceIntervalS = announce;
        _overridden[F_ANNOUNCE] = true;
    }
    if (set[F_NTP]) {
        _ntpIntervalS = ntp;
        _overridden[F_NTP] = true;
    }
    if (set[F_TCP_HOST]) {
        strncpy(_tcpHost, host, sizeof(_tcpHost) - 1);
        _overridden[F_TCP_HOST] = true;
        _rebootPending = true;
    }
    if (set[F_TCP_PORT]) {
        _tcpPort = port;
        _overridden[F_TCP_PORT] = true;
        _rebootPending = true;
    }
    if (!save()) {
        snprintf(err, errCap, "could not write %s", SETTINGS_FILE);
        return false;
    }
    changed[0] = 0;
    for (size_t i = 0; i < F_COUNT; i++)
        if (set[i])
            snprintf(changed + strlen(changed), changedCap - strlen(changed), "%s%s", changed[0] ? "," : "", KEY[i]);
    Serial.printf("[settings] changed: %s%s\n", changed, _rebootPending ? " (reboot pending)" : "");
    return true;
}

void NodeSettings::status(Print &out) const
{
    char buf[512];
    toJson(buf, sizeof(buf));
    out.print("[settings] ");
    out.print(buf);
}

// ------------------------------------------------------------------------------------- routes
static void handleGetConfig(EthernetClient &client, const HttpApi::Request &req)
{
    (void)req;
    char body[512];
    settings.toJson(body, sizeof(body));
    HttpApi::reply(client, 200, "application/json", body);
}

static void handlePutConfig(EthernetClient &client, const HttpApi::Request &req)
{
    const char *why = "";
    if (!httpApi.authorised(req, &why)) {
        Serial.printf("[settings] write refused: %s\n", why);
        HttpApi::replyError(client, 401, why);
        return;
    }
    if (req.contentLength == 0 || req.contentLength > 400) {
        HttpApi::replyError(client, 400, "Content-Length missing or too large");
        return;
    }
    char body[416];
    if (!HttpApi::readBody(client, req.contentLength, body, sizeof(body))) {
        HttpApi::replyError(client, 400, "short body");
        return;
    }
    char err[96], changed[160];
    if (!settings.applyJson(body, err, sizeof(err), changed, sizeof(changed))) {
        HttpApi::replyError(client, 422, err);
        return;
    }
    char out[640];
    char cfg[512];
    settings.toJson(cfg, sizeof(cfg));
    cfg[strcspn(cfg, "\n")] = 0;
    snprintf(out, sizeof(out), "{\"ok\":true,\"changed\":\"%s\",\"reboot_pending\":%s,\"config\":%s}\n", changed,
             settings.rebootPending() ? "true" : "false", cfg);
    HttpApi::reply(client, 200, "application/json", out);
}

static void handleResetConfig(EthernetClient &client, const HttpApi::Request &req)
{
    const char *why = "";
    if (!httpApi.authorised(req, &why)) {
        HttpApi::replyError(client, 401, why);
        return;
    }
    settings.reset();
    char cfg[512];
    settings.toJson(cfg, sizeof(cfg));
    cfg[strcspn(cfg, "\n")] = 0;
    char out[640];
    snprintf(out, sizeof(out), "{\"ok\":true,\"reset\":true,\"config\":%s}\n", cfg);
    HttpApi::reply(client, 200, "application/json", out);
}

// Without USB, a setting that only takes effect at boot needs a way to ask for that boot.
static uint32_t s_rebootAt = 0;

static void handleReboot(EthernetClient &client, const HttpApi::Request &req)
{
    const char *why = "";
    if (!httpApi.authorised(req, &why)) {
        HttpApi::replyError(client, 401, why);
        return;
    }
    HttpApi::reply(client, 200, "application/json", "{\"ok\":true,\"rebooting\":true}\n");
    Serial.println("[api] reboot requested over HTTP");
    s_rebootAt = millis() + 500;
}

void nodeSettingsLoop()
{
    if (s_rebootAt != 0 && (int32_t)(millis() - s_rebootAt) >= 0) {
        Serial.flush();
        rp2040.reboot();
    }
}

void nodeSettingsRegisterRoutes()
{
    httpApi.route("GET", "/config", handleGetConfig);
    httpApi.route("PUT", "/config", handlePutConfig);
    httpApi.route("POST", "/config/reset", handleResetConfig);
    httpApi.route("POST", "/reboot", handleReboot);
}
