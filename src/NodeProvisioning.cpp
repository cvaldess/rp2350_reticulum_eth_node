#include "NodeProvisioning.h"

#include "NodeSettings.h"

#include <Arduino.h>
#include <string.h>

#ifdef RNS_USE_PROVISIONING

#include <microReticulum/Provisioning/Provisioning.h>

using namespace RNS::Provisioning;

namespace
{
// Namespace id in the third-party range; ids are append-only and never reused once a build
// has shipped (the library's provisioning_integration_guide.md, "id stability"). Settings
// 1-10 in the order docs/config.md lists them, metrics from 20, commands from 30.
constexpr uint16_t NS_NODE = 200;
namespace F
{
constexpr uint16_t AnnounceIntervalS = 1, LoraTxPowerDbm = 2, NtpIntervalS = 3, TcpHost = 4, TcpPort = 5, IpMode = 6,
                   Ip = 7, Subnet = 8, Gateway = 9, Dns = 10;
constexpr uint16_t RebootPending = 20, IpTrial = 21, IpSource = 22, LastError = 23;
constexpr uint16_t ResetOverrides = 30;
// next-id: settings 11, metrics 24, commands 31
} // namespace F
constexpr int64_t IP_MODE_DHCP = 0, IP_MODE_STATIC = 1;

// Why the last COMMIT was refused, for the client: the engine's COMMIT reply only carries a
// count of what was applied, not NodeSettings' reason.
char lastError[96] = "";

// `"key":value,` onto a JSON object under construction. Strings are at most 15 characters
// (the field constraints), so escaping is a formality, but a quote in a hostname must not
// be able to break the object.
void jsonAdd(char *out, size_t cap, const char *key, const char *value, bool quoted)
{
    size_t n = strlen(out);
    n += snprintf(out + n, cap - n, "%s\"%s\":", n > 1 ? "," : "", key);
    if (!quoted) {
        snprintf(out + n, cap - n, "%s", value);
        return;
    }
    if (n >= cap - 4) {
        out[n] = 0;
        return;
    }
    out[n++] = '"';
    for (const char *c = value; *c && n < cap - 4; c++) {
        if (*c == '"' || *c == '\\')
            out[n++] = '\\';
        out[n++] = *c;
    }
    out[n++] = '"';
    out[n] = 0;
}

// The commit hook: every pending setting, as one PUT to NodeSettings. It validates the lot
// and changes nothing if any of it is wrong, exactly like the HTTP route, in which case the
// drafts are dropped so the engine promotes nothing. On success the drafts stay and the
// engine promotes them into its working map (a mirror) and flags the reboot-required ones;
// there are no field setters, so nothing is applied twice.
void onCommit(Namespace &ns)
{
    char json[400] = "{";
    char num[24];
    Value v;
    struct {
        uint16_t id;
        const char *key;
    } const ints[] = {{F::AnnounceIntervalS, "announce_interval_s"},
                      {F::LoraTxPowerDbm, "lora_tx_power_dbm"},
                      {F::NtpIntervalS, "ntp_interval_s"},
                      {F::TcpPort, "tcp_port"}};
    for (const auto &f : ints) {
        if (ns.draft(f.id, v)) {
            snprintf(num, sizeof(num), "%lld", (long long)v.as_int());
            jsonAdd(json, sizeof(json), f.key, num, false);
        }
    }
    struct {
        uint16_t id;
        const char *key;
    } const strings[] = {{F::TcpHost, "tcp_host"}, {F::Ip, "ip"}, {F::Subnet, "subnet"}, {F::Gateway, "gateway"}, {F::Dns, "dns"}};
    for (const auto &f : strings) {
        if (ns.draft(f.id, v))
            jsonAdd(json, sizeof(json), f.key, v.as_string().c_str(), true);
    }
    if (ns.draft(F::IpMode, v))
        jsonAdd(json, sizeof(json), "ip_mode", v.as_int() == IP_MODE_STATIC ? "static" : "dhcp", true);

    if (strlen(json) == 1)
        return; // only commands pending (reset_overrides): nothing for NodeSettings here
    strncat(json, "}", sizeof(json) - strlen(json) - 1);

    char err[sizeof(lastError)], changed[192];
    if (!settings.applyJson(json, err, sizeof(err), changed, sizeof(changed))) {
        snprintf(lastError, sizeof(lastError), "%s", err);
        Serial.printf("[prov] commit refused: %s\n", err);
        for (const auto &f : ints)
            ns.clear_draft(f.id);
        for (const auto &f : strings)
            ns.clear_draft(f.id);
        ns.clear_draft(F::IpMode);
        return;
    }
    lastError[0] = 0;
    Serial.printf("[prov] commit applied by radio: %s\n", changed);
}
} // namespace

void nodeProvisioningRegister()
{
    Provisioner &p = Provisioner::instance();
    p.register_namespace("Node", NS_NODE)
        .field_int("announce_interval_s", F::AnnounceIntervalS, FF_LIVE_APPLY, NODE_ANNOUNCE_INTERVAL_S,
                   NodeSettings::ANNOUNCE_MIN, NodeSettings::ANNOUNCE_MAX, nullptr,
                   []() { return (int64_t)settings.announceIntervalS(); })
        .field_int("lora_tx_power_dbm", F::LoraTxPowerDbm, FF_LIVE_APPLY, LORA_TX_POWER_DBM, NodeSettings::TXPOWER_MIN,
                   NodeSettings::TXPOWER_MAX, nullptr, []() { return (int64_t)settings.loraTxPowerDbm(); })
        .field_int("ntp_interval_s", F::NtpIntervalS, FF_LIVE_APPLY, NODE_NTP_INTERVAL_S, NodeSettings::NTP_MIN,
                   NodeSettings::NTP_MAX, nullptr, []() { return (int64_t)settings.ntpIntervalS(); })
        .field_string("tcp_host", F::TcpHost, FF_REBOOT_REQUIRED, RNS_TCP_TARGET_HOST, 15, nullptr,
                      []() { return std::string(settings.tcpHost()); })
        .field_int("tcp_port", F::TcpPort, FF_REBOOT_REQUIRED, RNS_TCP_TARGET_PORT, 1, 65535, nullptr,
                   []() { return (int64_t)settings.tcpPort(); })
        .field_enum("ip_mode", F::IpMode, FF_REBOOT_REQUIRED, IP_MODE_DHCP, {IP_MODE_DHCP, IP_MODE_STATIC},
                    {"dhcp", "static"}, nullptr,
                    []() { return settings.ipStaticOnly() ? IP_MODE_STATIC : IP_MODE_DHCP; })
        .field_string("ip", F::Ip, FF_REBOOT_REQUIRED, "", 15, nullptr, []() { return std::string(settings.ip()); })
        .field_string("subnet", F::Subnet, FF_REBOOT_REQUIRED, "", 15, nullptr,
                      []() { return std::string(settings.subnet()); })
        .field_string("gateway", F::Gateway, FF_REBOOT_REQUIRED, "", 15, nullptr,
                      []() { return std::string(settings.gateway()); })
        .field_string("dns", F::Dns, FF_REBOOT_REQUIRED, "", 15, nullptr, []() { return std::string(settings.dns()); })
        // What GET /config also reports.
        .metric_bool("reboot_pending", F::RebootPending, []() { return settings.rebootPending(); })
        .metric_string("ip_trial", F::IpTrial, []() { return std::string(settings.ipTrialName()); })
        .metric_string("ip_source", F::IpSource, []() { return std::string(settings.ipSourceName()); })
        .metric_string("last_error", F::LastError, []() { return std::string(lastError); })
        // POST /config/reset. A reboot (wire op 9) is the engine's own.
        .command_void("reset_overrides", F::ResetOverrides, []() { return settings.reset(); })
        .on_commit(onCommit)
        .end();
    // REBOOT (op 9) reboots the way POST /reboot does: after the reply has gone out. And a
    // FACTORY_RESET drops the overrides too - the engine only knows about its own mirror.
    p.on_reboot([]() { nodeSettingsRequestReboot("radio"); });
    p.on_factory_reset([]() { settings.reset(); });
    settings.onChanged(nodeProvisioningSync);
    // Start it here rather than letting Reticulum::start() do it, so the storage root is an
    // absolute LittleFS path instead of the library's relative default ("./config").
    // Idempotent: the start inside Reticulum::start() is then a no-op. The filesystem is
    // registered and the fluent Reticulum setters have run by the time this is called, which
    // is the order the integration guide asks for (provisioned values win over the fluent ones).
    p.begin("/config");
}

void nodeProvisioningSync()
{
    Namespace *ns = Provisioner::instance().registry().find(NS_NODE);
    if (!ns)
        return;
    ns->put_working(F::AnnounceIntervalS, Value((long long)settings.announceIntervalS()));
    ns->put_working(F::LoraTxPowerDbm, Value((long long)settings.loraTxPowerDbm()));
    ns->put_working(F::NtpIntervalS, Value((long long)settings.ntpIntervalS()));
    ns->put_working(F::TcpHost, Value(settings.tcpHost()));
    ns->put_working(F::TcpPort, Value((long long)settings.tcpPort()));
    ns->put_working(F::IpMode, Value::make_enum(settings.ipStaticOnly() ? IP_MODE_STATIC : IP_MODE_DHCP));
    ns->put_working(F::Ip, Value(settings.ip()));
    ns->put_working(F::Subnet, Value(settings.subnet()));
    ns->put_working(F::Gateway, Value(settings.gateway()));
    ns->put_working(F::Dns, Value(settings.dns()));
}

#else // no Provisioning in this build: the settings stay HTTP-only

void nodeProvisioningRegister() {}
void nodeProvisioningSync() {}

#endif
