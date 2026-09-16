"""Read and change a node's runtime settings over the LAN (docs/config.md).

    python tools/node_config.py --host 192.168.1.191                       # show
    python tools/node_config.py --host 192.168.1.191 --set announce_interval_s=600
    python tools/node_config.py --host 192.168.1.191 --set lora_tx_power_dbm=0 --set ntp_interval_s=3600
    python tools/node_config.py --host 192.168.1.191 --reset               # back to build defaults
    python tools/node_config.py --host 192.168.1.191 --reboot              # apply a boot-only change

Values are typed by the node, not here: anything that parses as an integer is sent as one, the
rest as a string. Writes use the same nonce + SHA-256(nonce || PSK) as the OTA, and the PSK comes
from include/node_config.h unless --psk says otherwise.
"""
import argparse
import json
import sys

from ota_upload import auth_headers, get_nonce, psk_from_config, request


def show(cfg):
    over = set(cfg.get("overridden", []))
    defaults = cfg.get("defaults", {})
    print("%-22s %-18s %s" % ("setting", "value", "source"))
    for k in [k for k in cfg if k not in ("overridden", "defaults", "reboot_pending")]:
        src = "set" if k in over else "default (%s)" % defaults.get(k, "?")
        print("%-22s %-18s %s" % (k, cfg[k], src))
    if cfg.get("reboot_pending"):
        print("\na setting that only takes effect at boot has changed: --reboot to apply it")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=4244)
    ap.add_argument("--set", action="append", metavar="KEY=VALUE", default=[])
    ap.add_argument("--reset", action="store_true", help="drop every override")
    ap.add_argument("--reboot", action="store_true", help="reboot the node (boot-only settings)")
    ap.add_argument("--psk", help="64 hex chars (default: from include/node_config.h)")
    ap.add_argument("--json", action="store_true", help="print raw JSON instead of a table")
    args = ap.parse_args()

    if not args.set and not args.reset and not args.reboot:
        code, text = request(args.host, args.port, "GET", "/config", timeout=10)
        if code != 200:
            raise SystemExit("GET /config: HTTP %d %s" % (code, text))
        cfg = json.loads(text)
        print(text.strip() if args.json else "", end="")
        if not args.json:
            show(cfg)
        return

    psk = bytes.fromhex(args.psk or psk_from_config())

    if args.set:
        payload = {}
        for item in args.set:
            if "=" not in item:
                raise SystemExit("--set wants KEY=VALUE, got %r" % item)
            k, v = item.split("=", 1)
            try:
                payload[k] = int(v)
            except ValueError:
                payload[k] = v
        body = json.dumps(payload)
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        headers.update(auth_headers(get_nonce(args.host, args.port), psk))
        code, text = request(args.host, args.port, "PUT", "/config", body=body, headers=headers, timeout=20)
        print("PUT /config: HTTP %d" % code)
        if code != 200:
            print(text)
            sys.exit(1)
        show(json.loads(text)["config"])

    if args.reset:
        headers = auth_headers(get_nonce(args.host, args.port), psk)
        headers["Content-Length"] = "0"
        code, text = request(args.host, args.port, "POST", "/config/reset", headers=headers, timeout=20)
        print("POST /config/reset: HTTP %d" % code)
        if code != 200:
            print(text)
            sys.exit(1)
        show(json.loads(text)["config"])

    if args.reboot:
        headers = auth_headers(get_nonce(args.host, args.port), psk)
        headers["Content-Length"] = "0"
        code, text = request(args.host, args.port, "POST", "/reboot", headers=headers, timeout=20)
        print("POST /reboot: HTTP %d %s" % (code, text))
        if code != 200:
            sys.exit(1)


if __name__ == "__main__":
    main()
