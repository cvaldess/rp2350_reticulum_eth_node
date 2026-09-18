"""RP2350 picobin block loops: find the signed IMAGE_DEF in a flat image and check it the way
the bootrom does (RP2350 datasheet 5.9, 5.10.2), plus the boot key fingerprint picotool burns.

    python tools/picobin.py .pio/build/pico2_w5500_e22/firmware.uf2   # describe + verify

Used by tools/ota_upload.py (refuse an image the bootrom would refuse) and tools/keys.py.
Needs the `ecdsa` package for the signature check (pip install ecdsa); parsing is stdlib only.
"""
import hashlib
import struct
import sys

XIP_BASE = 0x10000000

BLOCK_START = 0xFFFFDED3
BLOCK_END = 0xAB123579
ITEM_IMAGE_TYPE = 0x42
ITEM_VERSION = 0x48
ITEM_LOAD_MAP = 0x06
ITEM_HASH_DEF = 0x47
ITEM_SIGNATURE = 0x09
ITEM_HASH_VALUE = 0x4B
ITEM_LAST = 0x7F
IMAGE_TYPE_EXE = 0x1

# The bootrom looks for the first block header in the first 4 kB of the image.
FIRST_BLOCK_SEARCH = 4096
MAX_BLOCK_BYTES = 384  # IMAGE_DEF blocks larger than this are ignored by the bootrom


class Block:
    def __init__(self, offset, items, link):
        self.offset = offset  # byte offset of the header within the image
        self.items = items    # list of (type, size_words, item_offset)
        self.link = link      # relative byte offset to the next block header

    def item(self, typ):
        for t, size, off in self.items:
            if t == typ:
                return size, off
        return None

    @property
    def is_image_def(self):
        return bool(self.items) and self.items[0][0] == ITEM_IMAGE_TYPE


def parse_block(img, off):
    """One block at img[off:]; None if it is not well formed."""
    if off + 4 > len(img) or struct.unpack_from("<I", img, off)[0] != BLOCK_START:
        return None
    items = []
    p = off + 4
    while True:
        if p + 4 > len(img) or p - off > MAX_BLOCK_BYTES:
            return None
        b0 = img[p]
        typ = b0 & 0x7F
        two_byte = b0 & 0x80
        size = img[p + 1] | (img[p + 2] << 8) if two_byte else img[p + 1]
        items.append((typ, size, p))
        if typ == ITEM_LAST:
            p += 4
            break
        if size == 0:
            return None
        p += 4 * size
    if p + 8 > len(img):
        return None
    link = struct.unpack_from("<i", img, p)[0]
    if struct.unpack_from("<I", img, p + 4)[0] != BLOCK_END:
        return None
    return Block(off, items, link)


def block_loop(img):
    """The closed loop of blocks the bootrom would follow, in list order; [] if there is none."""
    first = None
    for off in range(0, min(len(img), FIRST_BLOCK_SEARCH) - 3, 4):
        if struct.unpack_from("<I", img, off)[0] == BLOCK_START and parse_block(img, off):
            first = off
            break
    if first is None:
        return []
    blocks = []
    off = first
    for _ in range(16):
        b = parse_block(img, off)
        if not b:
            return []
        blocks.append(b)
        nxt = off + b.link
        if nxt == first:
            return blocks
        if nxt < 0 or nxt >= len(img):
            return []
        off = nxt
    return []


def signed_image_def(img):
    """The IMAGE_DEF the bootrom boots (the last one in the loop) if it carries a signature."""
    defs = [b for b in block_loop(img) if b.is_image_def]
    if not defs:
        return None
    last = defs[-1]
    return last if last.item(ITEM_SIGNATURE) else None


def load_map(img, block):
    """[(storage_offset_in_image, size)] of the regions the hash covers; None if malformed."""
    found = block.item(ITEM_LOAD_MAP)
    if not found:
        return None
    size, off = found
    hdr = struct.unpack_from("<I", img, off)[0]
    entries = (hdr >> 24) & 0x7F
    absolute = (hdr >> 31) & 1
    if size != 1 + 3 * entries:
        return None
    regions = []
    for i in range(entries):
        storage, runtime, n = struct.unpack_from("<III", img, off + 4 + 12 * i)
        if storage == 0:
            continue  # zero-fill entry, nothing stored
        if not absolute:
            storage = (off + storage) & 0xFFFFFFFF  # relative to the load map item
            storage = XIP_BASE + storage if storage < XIP_BASE else storage
        if n > 0x10000000:  # "size" may also be an end address for the last entry
            n = n - runtime
        regions.append((storage - XIP_BASE, n))
    return regions


def image_hash(img, block):
    """SHA-256 the bootrom checks: load-map regions, then the block words HASH_DEF names."""
    regions = load_map(img, block)
    hd = block.item(ITEM_HASH_DEF)
    if regions is None or not hd:
        return None
    words = struct.unpack_from("<I", img, hd[1] + 4)[0] & 0xFFFF
    h = hashlib.sha256()
    for start, n in regions:
        if start < 0 or start + n > len(img):
            return None
        h.update(img[start:start + n])
    h.update(img[block.offset:block.offset + 4 * words])
    return h.digest()


def signature(img, block):
    """(pubkey 64 bytes X||Y, signature 64 bytes r||s) from the SIGNATURE item."""
    sig = block.item(ITEM_SIGNATURE)
    if not sig or sig[0] != 33:
        return None
    off = sig[1] + 4
    return img[off:off + 64], img[off + 64:off + 128]


def version(img, block):
    v = block.item(ITEM_VERSION)
    if not v:
        return None
    minor, major = struct.unpack_from("<HH", img, v[1] + 4)
    return major, minor


def verify(img):
    """(ok, detail, pubkey) — ok only if the bootrom would accept the image with that pubkey's
    fingerprint in OTP: the last IMAGE_DEF is signed, its hash matches and the ECDSA checks."""
    block = signed_image_def(img)
    if not block:
        return False, "no signed IMAGE_DEF in the block loop", None
    digest = image_hash(img, block)
    if digest is None:
        return False, "malformed LOAD_MAP or HASH_DEF", None
    hv = block.item(ITEM_HASH_VALUE)
    if hv:
        stored = img[hv[1] + 4:hv[1] + 4 + 32]
        if stored != digest:
            return False, "HASH_VALUE does not match the image", None
    sig = signature(img, block)
    if not sig:
        return False, "malformed SIGNATURE item", None
    pub, rs = sig
    try:
        from ecdsa import SECP256k1, VerifyingKey
        from ecdsa.util import sigdecode_string
    except ImportError:
        raise SystemExit("pip install ecdsa (needed to check the image signature)")
    try:
        vk = VerifyingKey.from_string(pub, curve=SECP256k1)
        vk.verify_digest(rs, digest, sigdecode=sigdecode_string)
    except Exception as e:  # BadSignatureError, MalformedPointError
        return False, "signature does not verify (%s)" % e.__class__.__name__, pub
    return True, "signed, hash and signature verify", pub


def bootkey_fingerprint(pub64):
    """What picotool burns into BOOTKEYn_0..15: SHA-256 of the 64-byte public key (X||Y)."""
    return hashlib.sha256(pub64).digest()


def known_pubkeys(header_path=None):
    """The 64-byte public keys in include/boot_pubkeys.h (tools/keys.py export); [] if absent."""
    import os
    import re
    if header_path is None:
        header_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "include", "boot_pubkeys.h")
    if not os.path.exists(header_path):
        return []
    with open(header_path, encoding="utf-8") as f:
        text = f.read()
    keys = []
    for body in re.findall(r"\{([^{}]+)\}", text.split("NODE_BOOT_PUBKEYS", 1)[-1]):
        vals = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", body)]
        if len(vals) == 64:
            keys.append(bytes(vals))
    return keys


def uf2_to_image(data):
    from_uf2 = {}
    for off in range(0, len(data) - 511, 512):
        m0, m1, flags, addr, size = struct.unpack_from("<5I", data, off)
        if m0 != 0x0A324655 or m1 != 0x9E5D5157 or flags & 1 or not (XIP_BASE <= addr < XIP_BASE + (16 << 20)):
            continue
        from_uf2[addr] = data[off + 32:off + 32 + size]
    if not from_uf2:
        raise SystemExit("no flash blocks in the UF2")
    lo, hi = min(from_uf2), max(a + len(b) for a, b in from_uf2.items())
    img = bytearray(b"\xff" * (hi - lo))
    for a, b in from_uf2.items():
        img[a - lo:a - lo + len(b)] = b
    return bytes(img)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()
    img = uf2_to_image(data) if path.lower().endswith(".uf2") else data
    print("image %d bytes" % len(img))
    loop = block_loop(img)
    for b in loop:
        kinds = ["IMAGE_DEF" if b.is_image_def else "block"]
        for t, size, off in b.items:
            name = {ITEM_IMAGE_TYPE: "type", ITEM_VERSION: "version", ITEM_LOAD_MAP: "load_map",
                    ITEM_HASH_DEF: "hash_def", ITEM_SIGNATURE: "signature", ITEM_HASH_VALUE: "hash_value",
                    ITEM_LAST: "last"}.get(t, "0x%02x" % t)
            kinds.append(name)
        print("  block @0x%08x: %s" % (XIP_BASE + b.offset, " ".join(kinds)))
    block = signed_image_def(img)
    if block:
        v = version(img, block)
        print("  signed IMAGE_DEF @0x%08x version %s" % (XIP_BASE + block.offset, "%d.%d" % v if v else "-"))
        for start, n in load_map(img, block) or []:
            print("  hashed 0x%08x..0x%08x (%d bytes)" % (XIP_BASE + start, XIP_BASE + start + n, n))
    ok, detail, pub = verify(img)
    if pub:
        print("  pubkey %s" % pub.hex())
        print("  bootkey fingerprint %s" % bootkey_fingerprint(pub).hex())
    print("VERIFY: %s (%s)" % ("OK" if ok else "FAIL", detail))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
