"""Push a build to a node over Ethernet and watch it confirm itself (docs/ota.md).

    python tools/ota_upload.py .pio/build/pico2_w5500_e22/firmware.uf2 --host 192.168.1.191 --wait
    python tools/ota_upload.py --host 192.168.1.192 --status

Takes the UF2 PlatformIO produces, turns it back into the flat image the OTA stub writes
(blocks are 256 bytes at absolute flash addresses), gzips it, and PUTs it with the same
proof the Meshtastic fork's HTTP OTA uses: a one-shot nonce from the node and
SHA-256(nonce || PSK). The board name comes from the UF2's path (.pio/build/<env>/) unless
--board says otherwise; the node refuses an image built for the other carrier.

The PSK is read from include/node_config.h (NODE_OTA_PSK_HEX) unless --psk is given.
Only the standard library is needed.
"""
import argparse
import gzip
import hashlib
import http.client
import json
import os
import re
import struct
import sys
import time

UF2_MAGIC0, UF2_MAGIC1, UF2_MAGIC_END = 0x0A324655, 0x9E5D5157, 0x0AB16F30
UF2_NOT_MAIN_FLASH = 0x00000001
XIP_BASE = 0x10000000
XIP_END = XIP_BASE + 16 * 1024 * 1024


def uf2_to_image(data):
    """Flat image from XIP_BASE; gaps between blocks are 0xFF like erased flash."""
    if len(data) % 512:
        raise SystemExit("not a UF2 file (size is not a multiple of 512)")
    blocks = {}
    for off in range(0, len(data), 512):
        m0, m1, flags, addr, size, _no, _num, _fam = struct.unpack_from("<8I", data, off)
        end, = struct.unpack_from("<I", data, off + 508)
        if m0 != UF2_MAGIC0 or m1 != UF2_MAGIC1 or end != UF2_MAGIC_END:
            raise SystemExit("not a UF2 file (bad block magic at offset %d)" % off)
        if flags & UF2_NOT_MAIN_FLASH or not (XIP_BASE <= addr < XIP_END):
            continue
        blocks[addr] = data[off + 32:off + 32 + size]
    if not blocks:
        raise SystemExit("UF2 has no flash blocks")
    lo, hi = min(blocks), max(a + len(b) for a, b in blocks.items())
    if lo != XIP_BASE:
        raise SystemExit("image does not start at XIP_BASE (first block at 0x%08x)" % lo)
    image = bytearray(b"\xff" * (hi - lo))
    for addr, payload in blocks.items():
        image[addr - lo:addr - lo + len(payload)] = payload
    return bytes(image)


def load_image(path):
    with open(path, "rb") as f:
        data = f.read()
    if path.lower().endswith(".uf2"):
        return uf2_to_image(data)
    if data[:2] == b"\x1f\x8b":
        raise SystemExit("give the .uf2 or the raw .bin, not a .gz")
    return data


def board_from_path(path):
    m = re.search(r"[\\/]build[\\/]([^\\/]+)[\\/]", os.path.abspath(path))
    return m.group(1) if m else None


def psk_from_config():
    here = os.path.dirname(os.path.abspath(__file__))
    cfg = os.path.join(here, "..", "include", "node_config.h")
    with open(cfg, encoding="utf-8") as f:
        m = re.search(r'#define\s+NODE_OTA_PSK_HEX\s+"([0-9a-fA-F]{64})"', f.read())
    if not m:
        raise SystemExit("NODE_OTA_PSK_HEX not found in include/node_config.h; pass --psk")
    return m.group(1)


def request(host, port, method, path, body=None, headers=None, timeout=60):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace").strip()
    finally:
        conn.close()


def status(host, port):
    code, text = request(host, port, "GET", "/ota/status", timeout=10)
    if code != 200:
        raise SystemExit("status: HTTP %d %s" % (code, text))
    return json.loads(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("firmware", nargs="?", help="firmware.uf2 (or raw .bin) to upload")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=4244)
    ap.add_argument("--board", help="env name the node must match (default: from the UF2 path)")
    ap.add_argument("--psk", help="64 hex chars (default: NODE_OTA_PSK_HEX from include/node_config.h)")
    ap.add_argument("--status", action="store_true", help="just print /ota/status and exit")
    ap.add_argument("--wait", type=int, nargs="?", const=180, metavar="SECONDS",
                    help="after the upload, poll /ota/status until the new build is confirmed")
    args = ap.parse_args()

    if args.status or not args.firmware:
        print(json.dumps(status(args.host, args.port), indent=2))
        return

    board = args.board or board_from_path(args.firmware)
    if not board:
        raise SystemExit("cannot tell the board from the path; pass --board <env>")
    psk = bytes.fromhex(args.psk or psk_from_config())

    image = load_image(args.firmware)
    body = gzip.compress(image, compresslevel=9, mtime=0)
    sha = hashlib.sha256(body).hexdigest()
    print("image %d bytes, gzip %d bytes, sha256 %s, board %s" % (len(image), len(body), sha, board))

    before = status(args.host, args.port)
    print("node: build '%s' state %s" % (before.get("build"), before.get("state")))
    if before.get("board") != board:
        raise SystemExit("node says it is %s, refusing to push a %s image" % (before.get("board"), board))
    if len(image) > before.get("image_max", 0):
        raise SystemExit("image (%d) larger than the node's sketch area (%d)" % (len(image), before["image_max"]))

    code, nonce = request(args.host, args.port, "GET", "/ota/nonce", timeout=10)
    if code != 200 or len(nonce) != 64:
        raise SystemExit("nonce: HTTP %d %s" % (code, nonce))
    auth = hashlib.sha256(bytes.fromhex(nonce) + psk).hexdigest()

    t0 = time.time()
    code, text = request(args.host, args.port, "PUT", "/ota", body=body, headers={
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(body)),
        "X-OTA-Nonce": nonce,
        "X-OTA-Auth": auth,
        "X-OTA-SHA256": sha,
        "X-OTA-Board": board,
    }, timeout=120)
    print("upload: HTTP %d %s (%.1f s)" % (code, text, time.time() - t0))
    if code != 200:
        sys.exit(1)
    if args.wait is None:
        print("staged; the node reboots and copies the image now. Verify with --status.")
        return

    # The node reboots twice (stub copy, then the new image) and confirms once the SE050
    # answered and an announce went out; the build stamp tells the two images apart.
    deadline = time.time() + args.wait
    last = None
    while time.time() < deadline:
        time.sleep(3)
        try:
            now = status(args.host, args.port)
        except Exception:
            continue
        line = "build '%s' state %s boots %s uptime %ss" % (now.get("build"), now.get("state"), now.get("boots"),
                                                             now.get("uptime_s"))
        if line != last:
            print("node:", line)
            last = line
        if now.get("sha256") == sha and now.get("state") == "confirmed":
            print("CONFIRMED: the node runs the uploaded image (%.0f s)" % (time.time() - t0))
            return
        if now.get("sha256") == sha and now.get("state") in ("rolledback", "failed"):
            raise SystemExit("the node gave up on the uploaded image: %s" % now.get("state"))
        if now.get("build") == before.get("build") and now.get("state") == "rolledback":
            raise SystemExit("rolled back to the previous build")
    raise SystemExit("no confirmation within %d s" % args.wait)


if __name__ == "__main__":
    main()
