#include "NodeSettings.h"

#include <ArduinoJson.h>
#include <LittleFS.h>
#include <string.h>

#include "HttpApi.h"

NodeSettings settings;

static const char *SETTINGS_FILE = "/node_settings";

// Index into _overridden, and the key in the file and in JSON.
enum Field {
    F_ANNOUNCE = 0,
    F_TXPOWER,
    F_NTP,
    F_TCP_HOST,
    F_TCP_PORT,
    F_IP_MODE,
    F_IP,
    F_SUBNET,
    F_GATEWAY,
    F_DNS,
    F_COUNT
};
static const char *KEY[F_COUNT] = {"announce_interval_s", "lora_tx_power_dbm", "ntp_interval_s", "tcp_host", "tcp_port",
                                   "ip_mode",             "ip",                "subnet",         "gateway",  "dns"};
// The trial is state, not a setting: it lives in the same file but is not a KEY (no override, no default).
static const char *TRIAL_KEY = "ip_trial_boots";
static const char *TRIAL_REVERTED_KEY = "ip_trial_reverted";

// The bounds live in the header (NodeSettings::ANNOUNCE_MIN...) so the radio-side schema quotes
// the same numbers.
static constexpr uint32_t ANNOUNCE_MIN = NodeSettings::ANNOUNCE_MIN, ANNOUNCE_MAX = NodeSettings::ANNOUNCE_MAX;
static constexpr int TXPOWER_MIN = NodeSettings::TXPOWER_MIN, TXPOWER_MAX = NodeSettings::TXPOWER_MAX;
static constexpr uint32_t NTP_MIN = NodeSettings::NTP_MIN, NTP_MAX = NodeSettings::NTP_MAX;

static bool validIpv4(const char *s)
{
    IPAddress ip;
    return ip.fromString(s);
}

static void copyStr(char *dst, size_t cap, const char *src)
{
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = 0;
}

void NodeSettings::setDefaults()
{
    _announceIntervalS = NODE_ANNOUNCE_INTERVAL_S;
    _loraTxPowerDbm = LORA_TX_POWER_DBM;
    _ntpIntervalS = NODE_NTP_INTERVAL_S;
    copyStr(_tcpHost, sizeof(_tcpHost), RNS_TCP_TARGET_HOST);
    _tcpPort = RNS_TCP_TARGET_PORT;
    _ipStatic = false;
    _ip[0] = _subnet[0] = _gateway[0] = _dns[0] = 0;
    for (size_t i = 0; i < F_COUNT; i++)
        _overridden[i] = false;
}

void NodeSettings::begin()
{
    LittleFS.begin();
    setDefaults();
    if (load())
        Serial.printf("[settings] overrides loaded from %s\n", SETTINGS_FILE);
    Serial.printf("[settings] announce %lus, tx %d dBm, ntp %lus, rnsd %s:%u, ip %s%s%s\n",
                  (unsigned long)_announceIntervalS, _loraTxPowerDbm, (unsigned long)_ntpIntervalS, _tcpHost,
                  _tcpPort, _ipStatic ? "static " : "dhcp", _ip[0] ? (_ipStatic ? "" : " fallback ") : "",
                  _ip[0] ? _ip : "");

    // A static address that has not been reached yet is on trial from this boot. Like the OTA,
    // only the boot that starts on trial may confirm or revert it.
    if (_ipTrial == IpTrial::Pending) {
        if (!_ipStatic || !_ip[0]) {
            _ipTrial = IpTrial::None; // nothing static to prove any more
            save();
        } else {
            _ipTrialBoots++;
            if (_ipTrialBoots > NODE_IP_TRIAL_BOOTS) {
                revertIpToDhcp("not reached in enough boots");
                save();
                Serial.flush();
                delay(100);
                rp2040.reboot();
            }
            _ipTrialThisBoot = true;
            save();
            Serial.printf("[settings] static ip %s on trial, boot %lu of %d: any API request within %d s "
                          "confirms it, else back to DHCP\n",
                          _ip, (unsigned long)_ipTrialBoots, NODE_IP_TRIAL_BOOTS, NODE_IP_TRIAL_TIMEOUT_S);
        }
    }
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
            copyStr(_tcpHost, sizeof(_tcpHost), v);
            _overridden[F_TCP_HOST] = any = true;
        } else if (strcmp(line, KEY[F_TCP_PORT]) == 0) {
            _tcpPort = (uint16_t)strtoul(v, nullptr, 10);
            _overridden[F_TCP_PORT] = any = true;
        } else if (strcmp(line, KEY[F_IP_MODE]) == 0) {
            _ipStatic = strcmp(v, "static") == 0;
            _overridden[F_IP_MODE] = any = true;
        } else if (strcmp(line, KEY[F_IP]) == 0) {
            copyStr(_ip, sizeof(_ip), v);
            _overridden[F_IP] = any = true;
        } else if (strcmp(line, KEY[F_SUBNET]) == 0) {
            copyStr(_subnet, sizeof(_subnet), v);
            _overridden[F_SUBNET] = any = true;
        } else if (strcmp(line, KEY[F_GATEWAY]) == 0) {
            copyStr(_gateway, sizeof(_gateway), v);
            _overridden[F_GATEWAY] = any = true;
        } else if (strcmp(line, KEY[F_DNS]) == 0) {
            copyStr(_dns, sizeof(_dns), v);
            _overridden[F_DNS] = any = true;
        } else if (strcmp(line, TRIAL_KEY) == 0) {
            _ipTrial = IpTrial::Pending;
            _ipTrialBoots = strtoul(v, nullptr, 10);
        } else if (strcmp(line, TRIAL_REVERTED_KEY) == 0) {
            _ipTrial = IpTrial::Reverted;
        }
    }
    f.close();
    // A static mode without an address is not a configuration: read it as dhcp.
    if (_ipStatic && !_ip[0])
        _ipStatic = false;
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
    if (_overridden[F_IP_MODE])
        f.printf("%s=%s\n", KEY[F_IP_MODE], _ipStatic ? "static" : "dhcp");
    if (_overridden[F_IP])
        f.printf("%s=%s\n", KEY[F_IP], _ip);
    if (_overridden[F_SUBNET])
        f.printf("%s=%s\n", KEY[F_SUBNET], _subnet);
    if (_overridden[F_GATEWAY])
        f.printf("%s=%s\n", KEY[F_GATEWAY], _gateway);
    if (_overridden[F_DNS])
        f.printf("%s=%s\n", KEY[F_DNS], _dns);
    if (_ipTrial == IpTrial::Pending)
        f.printf("%s=%lu\n", TRIAL_KEY, (unsigned long)_ipTrialBoots);
    else if (_ipTrial == IpTrial::Reverted)
        f.printf("%s=1\n", TRIAL_REVERTED_KEY);
    f.close();
    return true;
}

bool NodeSettings::reset()
{
    // Only the boot-only fields need a reboot to go back, and only if they were overridden.
    bool bootOnlyWasSet = false;
    for (size_t i = F_TCP_HOST; i < F_COUNT; i++)
        bootOnlyWasSet |= _overridden[i];
    setDefaults();
    _ipTrial = IpTrial::None;
    _ipTrialThisBoot = false;
    LittleFS.remove(SETTINGS_FILE);
    if (bootOnlyWasSet)
        _rebootPending = true;
    if (_applyTxPower)
        _applyTxPower(_loraTxPowerDbm);
    Serial.println("[settings] overrides dropped, compile-time defaults apply");
    notifyChanged();
    return true;
}

// -------------------------------------------------------------------------------- addresses
bool NodeSettings::staticAddress(IPAddress &ip, IPAddress &subnet, IPAddress &gateway, IPAddress &dns) const
{
    if (!_ip[0] || !ip.fromString(_ip))
        return false;
    if (!_subnet[0] || !subnet.fromString(_subnet))
        subnet = IPAddress(255, 255, 255, 0);
    if (!_gateway[0] || !gateway.fromString(_gateway))
        gateway = IPAddress(ip[0] & subnet[0], ip[1] & subnet[1], ip[2] & subnet[2], (ip[3] & subnet[3]) | 1);
    if (!_dns[0] || !dns.fromString(_dns))
        dns = gateway;
    return true;
}

const char *NodeSettings::ipTrialName(IpTrial t)
{
    switch (t) {
    case IpTrial::Pending:
        return "pending";
    case IpTrial::Reverted:
        return "reverted";
    default:
        return "none";
    }
}

void NodeSettings::revertIpToDhcp(const char *why)
{
    Serial.printf("[settings] static ip %s %s: back to DHCP%s\n", _ip, why, _ip[0] ? " (kept as the fallback)" : "");
    _ipStatic = false;
    _overridden[F_IP_MODE] = true; // an explicit dhcp, so GET /config shows the revert happened
    _ipTrial = IpTrial::Reverted;
    _ipTrialBoots = 0;
    _ipTrialThisBoot = false;
    notifyChanged();
}

void NodeSettings::confirmIp()
{
    if (_ipTrial != IpTrial::Pending || !_ipTrialThisBoot)
        return;
    _ipTrial = IpTrial::None;
    _ipTrialBoots = 0;
    _ipTrialThisBoot = false;
    save();
    Serial.printf("[settings] static ip %s confirmed: a request reached the API there\n", _ip);
}

void NodeSettings::timeoutIpTrial()
{
    if (_ipTrial != IpTrial::Pending || !_ipTrialThisBoot)
        return;
    revertIpToDhcp("not reached within the trial");
    save();
    Serial.flush();
    delay(100);
    rp2040.reboot();
}

// ------------------------------------------------------------------------------------- json
void NodeSettings::toJson(char *out, size_t cap) const
{
    char overridden[240] = "";
    for (size_t i = 0; i < F_COUNT; i++)
        if (_overridden[i])
            snprintf(overridden + strlen(overridden), sizeof(overridden) - strlen(overridden), "%s\"%s\"",
                     overridden[0] ? "," : "", KEY[i]);
    snprintf(out, cap,
             "{\"%s\":%lu,\"%s\":%d,\"%s\":%lu,\"%s\":\"%s\",\"%s\":%u,"
             "\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"ip_trial\":\"%s\","
             "\"ip_source\":\"%s\",\"overridden\":[%s],\"reboot_pending\":%s,"
             "\"defaults\":{\"%s\":%d,\"%s\":%d,\"%s\":%d,\"%s\":\"%s\",\"%s\":%d,"
             "\"%s\":\"dhcp\",\"%s\":\"\",\"%s\":\"\",\"%s\":\"\",\"%s\":\"\"}}\n",
             KEY[F_ANNOUNCE], (unsigned long)_announceIntervalS, KEY[F_TXPOWER], _loraTxPowerDbm, KEY[F_NTP],
             (unsigned long)_ntpIntervalS, KEY[F_TCP_HOST], _tcpHost, KEY[F_TCP_PORT], _tcpPort, KEY[F_IP_MODE],
             _ipStatic ? "static" : "dhcp", KEY[F_IP], _ip, KEY[F_SUBNET], _subnet, KEY[F_GATEWAY], _gateway,
             KEY[F_DNS], _dns, ipTrialName(_ipTrial), _ipSource ? _ipSource() : "none", overridden,
             _rebootPending ? "true" : "false",
             KEY[F_ANNOUNCE], NODE_ANNOUNCE_INTERVAL_S, KEY[F_TXPOWER], LORA_TX_POWER_DBM, KEY[F_NTP],
             NODE_NTP_INTERVAL_S, KEY[F_TCP_HOST], RNS_TCP_TARGET_HOST, KEY[F_TCP_PORT], RNS_TCP_TARGET_PORT,
             KEY[F_IP_MODE], KEY[F_IP], KEY[F_SUBNET], KEY[F_GATEWAY], KEY[F_DNS]);
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
    bool ipStatic = _ipStatic;
    // The four address fields: an empty string clears one (back to "not set").
    char *addr[4] = {_ip, _subnet, _gateway, _dns};
    const Field addrField[4] = {F_IP, F_SUBNET, F_GATEWAY, F_DNS};
    char newAddr[4][16];
    for (int i = 0; i < 4; i++)
        copyStr(newAddr[i], sizeof(newAddr[i]), addr[i]);
    bool set[F_COUNT] = {false};
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
            copyStr(host, sizeof(host), v);
            set[F_TCP_HOST] = true;
        } else if (strcmp(k, KEY[F_TCP_PORT]) == 0) {
            uint32_t p = kv.value().as<uint32_t>();
            if (p == 0 || p > 65535) {
                snprintf(err, errCap, "%s must be 1..65535", k);
                return false;
            }
            port = (uint16_t)p;
            set[F_TCP_PORT] = true;
        } else if (strcmp(k, KEY[F_IP_MODE]) == 0) {
            const char *v = kv.value().as<const char *>();
            if (!v || (strcmp(v, "dhcp") != 0 && strcmp(v, "static") != 0)) {
                snprintf(err, errCap, "%s must be \"dhcp\" or \"static\"", k);
                return false;
            }
            ipStatic = strcmp(v, "static") == 0;
            set[F_IP_MODE] = true;
        } else {
            int a = -1;
            for (int i = 0; i < 4 && a < 0; i++)
                if (strcmp(k, KEY[addrField[i]]) == 0)
                    a = i;
            if (a < 0) {
                snprintf(err, errCap, "unknown setting '%s'", k);
                return false;
            }
            const char *v = kv.value().as<const char *>();
            if (!v || strlen(v) >= sizeof(newAddr[a]) || (v[0] && !validIpv4(v))) {
                snprintf(err, errCap, "%s must be a dotted IPv4 address, or \"\" to clear it", k);
                return false;
            }
            copyStr(newAddr[a], sizeof(newAddr[a]), v);
            set[addrField[a]] = true;
        }
        known++;
    }
    if (known == 0) {
        snprintf(err, errCap, "no settings in the body");
        return false;
    }
    if (ipStatic && !newAddr[0][0]) {
        snprintf(err, errCap, "%s=static needs an %s", KEY[F_IP_MODE], KEY[F_IP]);
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
        copyStr(_tcpHost, sizeof(_tcpHost), host);
        _overridden[F_TCP_HOST] = true;
        _rebootPending = true;
    }
    if (set[F_TCP_PORT]) {
        _tcpPort = port;
        _overridden[F_TCP_PORT] = true;
        _rebootPending = true;
    }
    // Addresses. A static configuration that differs from the one running (mode or any field)
    // goes on trial at the next boot; a dhcp one never does, DHCP keeps the last word there.
    bool addrChanged = false;
    for (int i = 0; i < 4; i++) {
        if (!set[addrField[i]])
            continue;
        if (strcmp(addr[i], newAddr[i]) != 0)
            addrChanged = true;
        copyStr(addr[i], 16, newAddr[i]);
        _overridden[addrField[i]] = newAddr[i][0] != 0;
        _rebootPending = true;
    }
    if (set[F_IP_MODE]) {
        if (ipStatic != _ipStatic)
            addrChanged = true;
        _ipStatic = ipStatic;
        _overridden[F_IP_MODE] = true;
        _rebootPending = true;
    }
    if (addrChanged) {
        _ipTrial = _ipStatic ? IpTrial::Pending : IpTrial::None;
        _ipTrialBoots = 0;
        _ipTrialThisBoot = false;
    }
    if (!save()) {
        snprintf(err, errCap, "could not write %s", SETTINGS_FILE);
        return false;
    }
    changed[0] = 0;
    for (size_t i = 0; i < F_COUNT; i++)
        if (set[i])
            snprintf(changed + strlen(changed), changedCap - strlen(changed), "%s%s", changed[0] ? "," : "", KEY[i]);
    Serial.printf("[settings] changed: %s%s%s\n", changed, _rebootPending ? " (reboot pending)" : "",
                  _ipTrial == IpTrial::Pending ? " (static ip on trial at the next boot)" : "");
    notifyChanged();
    return true;
}

void NodeSettings::status(Print &out) const
{
    char buf[768];
    toJson(buf, sizeof(buf));
    out.print("[settings] ");
    out.print(buf);
}

// ------------------------------------------------------------------------------------- routes
static void handleGetConfig(EthernetClient &client, const HttpApi::Request &req)
{
    (void)req;
    char body[768];
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
    char err[96], changed[240];
    if (!settings.applyJson(body, err, sizeof(err), changed, sizeof(changed))) {
        HttpApi::replyError(client, 422, err);
        return;
    }
    char out[1024];
    char cfg[768];
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
    char cfg[768];
    settings.toJson(cfg, sizeof(cfg));
    cfg[strcspn(cfg, "\n")] = 0;
    char out[1024];
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
    nodeSettingsRequestReboot("HTTP");
}

void nodeSettingsRequestReboot(const char *why)
{
    Serial.printf("[api] reboot requested over %s\n", why);
    s_rebootAt = millis() + 500;
}

void nodeSettingsLoop()
{
    if (s_rebootAt != 0 && (int32_t)(millis() - s_rebootAt) >= 0) {
        Serial.flush();
        rp2040.reboot();
    }
    // The static-IP trial: nobody reached the API at that address in time, so it is presumed
    // wrong (or unreachable from where it matters) and DHCP comes back at the next boot.
    static bool s_ipTrialTimedOut = false;
    if (!s_ipTrialTimedOut && settings.ipTrial() == NodeSettings::IpTrial::Pending &&
        millis() >= (uint32_t)NODE_IP_TRIAL_TIMEOUT_S * 1000) {
        s_ipTrialTimedOut = true;
        settings.timeoutIpTrial();
    }
}

void nodeSettingsRegisterRoutes()
{
    httpApi.route("GET", "/config", handleGetConfig);
    httpApi.route("PUT", "/config", handlePutConfig);
    httpApi.route("POST", "/config/reset", handleResetConfig);
    httpApi.route("POST", "/reboot", handleReboot);
    httpApi.onRequest([]() { settings.confirmIp(); });
}
