"""Boot signing keys (docs/secure_boot.md): show them, and export the public halves to the firmware.

    python tools/keys.py show                 # pubkey + OTP fingerprint of each key
    python tools/keys.py export               # rewrite include/boot_pubkeys.h from the PEMs

The private keys live outside the repo (NODE_KEYS_DIR, default ~/.rp2350-keys): bootkey0.pem is
the working key, bootkey1.pem the offline spare. Only the public keys are committed; the node
uses them to check the detached signature on an OTA upload, and their fingerprints are what goes
into OTP BOOTKEY0/BOOTKEY1. Generate a key with
    openssl ecparam -name secp256k1 -genkey -noout -out bootkey0.pem
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from picobin import bootkey_fingerprint  # noqa: E402

KEY_NAMES = ("bootkey0", "bootkey1")


def keys_dir():
    return os.environ.get("NODE_KEYS_DIR") or os.path.join(os.path.expanduser("~"), ".rp2350-keys")


def key_path(name):
    return os.path.join(keys_dir(), name + ".pem")


def load_private(path):
    from ecdsa import SECP256k1, SigningKey
    with open(path, "rb") as f:
        sk = SigningKey.from_pem(f.read())
    if sk.curve != SECP256k1:
        raise SystemExit("%s is not a secp256k1 key" % path)
    return sk


def public_bytes(sk):
    return sk.get_verifying_key().to_string()  # 64 bytes, X || Y


def load_all():
    out = []
    for name in KEY_NAMES:
        p = key_path(name)
        if os.path.exists(p):
            out.append((name, public_bytes(load_private(p))))
    if not out:
        raise SystemExit("no keys in %s (bootkey0.pem, bootkey1.pem)" % keys_dir())
    return out


def export_header(keys):
    path = os.path.join(HERE, "..", "include", "boot_pubkeys.h")
    lines = ["// Public halves of the boot signing keys (tools/keys.py export). The private keys never",
             "// enter the repo. The node checks an OTA's X-OTA-Sig against these; their SHA-256",
             "// fingerprints are the OTP BOOTKEY entries (docs/secure_boot.md).",
             "#pragma once", "#include <stdint.h>", "",
             "#define NODE_BOOT_PUBKEY_COUNT %d" % len(keys),
             "static const uint8_t NODE_BOOT_PUBKEYS[NODE_BOOT_PUBKEY_COUNT][64] = {"]
    for name, pub in keys:
        lines.append("    // %s, fingerprint %s" % (name, bootkey_fingerprint(pub).hex()))
        rows = [", ".join("0x%02x" % b for b in pub[i:i + 16]) for i in range(0, 64, 16)]
        lines.append("    {" + ",\n     ".join(rows) + "},")
    lines += ["};", ""]
    with open(path, "wb") as f:
        f.write("\n".join(lines).encode("utf-8"))
    return path


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    keys = load_all()
    for name, pub in keys:
        print("%s (%s)" % (name, key_path(name)))
        print("  pubkey      %s" % pub.hex())
        print("  fingerprint %s" % bootkey_fingerprint(pub).hex())
    if cmd == "export":
        print("wrote", os.path.normpath(export_header(keys)))
    elif cmd != "show":
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
