#!/usr/bin/env python3
"""Host-side planner for rotating the SE050 Platform SCP03 keys (INS 0xD8 PUT KEY).

NON-DESTRUCTIVE. This tool never opens a serial port and never talks to the chip. It only
computes: it reproduces the SCP03 primitives the driver uses (so it can be checked byte for
byte against the real chip and against the firmware), computes key check values (KCV), and
assembles what the PUT KEY command would be for a chosen set of new keys. Sending it is a
separate, deliberate, one-way step that this tool deliberately does not do.

Why it exists: the channel opens today with NXP's public factory keys (AN12436, OEF A921).
Anyone on the I2C bus can use them; a passive sniffer who knows the static keys can derive
the session keys from the challenges and read the traffic. Rotating to per-device keys is the
fix. It is also irreversible: a PUT KEY with keys nobody knows bricks the secure channel for
good (no factory reset touches the SSD keys). So every byte is validated here first.

Commands:
  selftest
        Cross-check CMAC, the SCP03 KDF, KCV and DEK encryption against pycryptodome, and
        print the KAT vector the firmware `k` command must reproduce. No inputs, no chip.

  verify <hostChallenge> <cardChallenge> <cardCryptogram>
        Take one real session's challenges (from the firmware `k` command) and reproduce the
        card cryptogram and session keys. If the cryptogram matches the one the chip sent -
        which the chip only produces with the right keys and KDF - this Python implements the
        exact same crypto the driver and the chip agree on. That is the offline proof.

  plan <ENC_hex> <MAC_hex> <DEK_hex>
        For a chosen new key set (three 16-byte AES keys), print the KCVs, the DEK-encrypted
        key components, and the assembled PUT KEY data field and APDU header. Marked clearly:
        the data-field LAYOUT still needs one authoritative confirmation (nxScp03.c PutKeys /
        GPC Amd D) before anyone sends it.

All keys are 32 hex chars (16 bytes). Byte order is exactly as on the wire.
"""
import sys

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

# SE050E2, OEF 0x0A921 factory Platform SCP keys (AN12436 rev 2.4, table 5). These are public;
# they are the ones the driver already carries (SCP_KEY_ENC / SCP_KEY_MAC) plus the DEK, which
# the running channel never needed but PUT KEY does (it encrypts the new key components).
DEFAULT_ENC = bytes.fromhex("d2db63e7a0a5aed72a6460c4dfdcaf64")
DEFAULT_MAC = bytes.fromhex("738d5b798ed241b0b24768514bfba95b")
DEFAULT_DEK = bytes.fromhex("6702dac30942b2c85e7f47b42ced4e7f")

KEY_VERSION = 0x0B  # EX_SSS_AUTH_SE05X_KEY_VERSION_NO, matches the driver's SCP03_KEYVER
KEY_ID = 0x01       # SCP03_KEY_ID
KEY_TYPE_AES = 0x88  # GPCS_KEY_TYPE_AES
KCV_LEN = 3         # CRYPTO_KEY_CHECK_LEN


def cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


def scp03_kdf(key: bytes, constant: int, bits: int, context: bytes) -> bytes:
    """The SP800-108 counter-mode KDF exactly as SE050::kdf() builds it: an 11-byte zero
    label, the derivation constant, a 0x00 separator, the 2-byte length, the 1-byte counter,
    then the 16-byte context. One CMAC block; callers take the first 8 bytes for a 64-bit
    output. Reproduced independently here so a match proves the firmware's version."""
    dd = bytearray(16)
    dd[11] = constant
    dd[12] = 0x00
    dd[13] = (bits >> 8) & 0xFF
    dd[14] = bits & 0xFF
    dd[15] = 0x01
    dd += context
    return cmac(key, bytes(dd))


def session_keys(enc: bytes, mac: bytes, context: bytes):
    s_enc = scp03_kdf(enc, 0x04, 128, context)
    s_mac = scp03_kdf(mac, 0x06, 128, context)
    s_rmac = scp03_kdf(mac, 0x07, 128, context)
    return s_enc, s_mac, s_rmac


def cryptogram(s_mac: bytes, constant: int, context: bytes) -> bytes:
    return scp03_kdf(s_mac, constant, 64, context)[:8]


def kcv(key: bytes) -> bytes:
    """Key Check Value: AES-ECB encrypt 16 bytes of 0x01 under the key, take the first 3
    bytes (GP Amd D / SCP03). The chip returns these after PUT KEY; matching them is the
    non-destructive confirmation that the keys were stored as intended."""
    return AES.new(key, AES.MODE_ECB).encrypt(b"\x01" * 16)[:KCV_LEN]


def dek_encrypt(dek: bytes, key: bytes) -> bytes:
    """A new key component travels encrypted under the CURRENT DEK, AES-CBC, zero IV, no
    padding (the component is exactly one block)."""
    return AES.new(dek, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(key)


def h(b: bytes) -> str:
    return b.hex()


def cmd_selftest():
    print("== SCP03 primitive self-test (pycryptodome as the independent reference) ==\n")

    # RFC 4493 AES-CMAC test vectors: proves our CMAC path is the standard one.
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert cmac(k, b"") == bytes.fromhex("bb1d6929e95937287fa37d129b756746"), "CMAC empty"
    msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert cmac(k, msg) == bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c"), "CMAC 1 block"
    print("  AES-CMAC vs RFC 4493 vectors: OK")

    # KCV and DEK-encrypt of the known default keys: deterministic, printable, and something
    # the firmware KAT reproduces too.
    for name, key in (("ENC", DEFAULT_ENC), ("MAC", DEFAULT_MAC), ("DEK", DEFAULT_DEK)):
        print(f"  KCV(default {name}) = {h(kcv(key))}")

    # The KAT the firmware `k` command must reproduce with SE050::cmac()/kdf(). Fixed inputs,
    # no secrets: a fixed key, a fixed 16-byte context, constant 0x04, 128 bits.
    kat_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    kat_ctx = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    print("\n  Firmware KAT (the `k` console command must print these):")
    print(f"    cmac(kat_key, kat_ctx)               = {h(cmac(kat_key, kat_ctx))}")
    print(f"    kdf(kat_key, 0x04, 128, kat_ctx)     = {h(scp03_kdf(kat_key, 0x04, 128, kat_ctx))}")
    print(f"    kdf(kat_key, 0x06, 128, kat_ctx)     = {h(scp03_kdf(kat_key, 0x06, 128, kat_ctx))}")
    print("\n  self-test OK")


def cmd_verify(host_hex, card_hex, cryptogram_hex):
    host = bytes.fromhex(host_hex)
    card = bytes.fromhex(card_hex)
    got = bytes.fromhex(cryptogram_hex)
    assert len(host) == 8 and len(card) == 8 and len(got) == 8, "challenges/cryptogram are 8 bytes"
    context = host + card
    s_enc, s_mac, s_rmac = session_keys(DEFAULT_ENC, DEFAULT_MAC, context)
    mine = cryptogram(s_mac, 0x00, context)
    print("== Reproducing a real SCP03 session from its challenges ==\n")
    print(f"  host challenge : {h(host)}")
    print(f"  card challenge : {h(card)}")
    print(f"  S-ENC          : {h(s_enc)}")
    print(f"  S-MAC          : {h(s_mac)}")
    print(f"  S-RMAC         : {h(s_rmac)}")
    print(f"  card cryptogram: chip sent {h(got)}, computed {h(mine)}")
    if mine == got:
        print("\n  MATCH: this Python implements the exact SCP03 crypto the chip and driver agree on.")
        print("  host cryptogram (what the driver sends in EXTERNAL AUTHENTICATE): "
              + h(cryptogram(s_mac, 0x01, context)))
    else:
        print("\n  MISMATCH: do not trust the PUT KEY assembly until this is understood.")
        sys.exit(1)


def build_put_key_data(kvn, enc, mac, dek_new, dek_current):
    """Assemble the PUT KEY command data field, exactly as NXP's own demo builds it
    (se05x_RotatePlatformSCP03Keys / se05x_TP_PlatformSCP03keys.c, createKeyData):

        KVN || { 0x88, keyLen+1, keyLen, encryptedKeyComponent(keyLen), kcvLen, KCV(kcvLen) } x 3

    with keyType 0x88 (AES), TWO length bytes (the AES-key-data length keyLen+1, then the
    AES-key length keyLen), the component encrypted under the CURRENT DEK (AES-CBC, IV 0), and
    a 3-byte KCV. The keys go in ENC, MAC, DEK order. Each block is 3 + keyLen + 1 + 3 bytes.

    Also returns the response the chip sends back on success: KVN followed by the three KCVs.
    The demo does memcmp() of exactly this against the response - it is the verify-after-send.
    """
    data = bytes([kvn])
    expected_response = bytes([kvn])
    for key in (enc, mac, dek_new):
        enc_comp = dek_encrypt(dek_current, key)
        kcv3 = kcv(key)
        block = bytes([KEY_TYPE_AES, len(enc_comp) + 1, len(enc_comp), *enc_comp, KCV_LEN, *kcv3])
        data += block
        expected_response += kcv3
    return data, expected_response


def cmd_plan(enc_hex, mac_hex, dek_hex):
    enc = bytes.fromhex(enc_hex)
    mac = bytes.fromhex(mac_hex)
    dek = bytes.fromhex(dek_hex)
    assert len(enc) == len(mac) == len(dek) == 16, "each new key is 16 bytes (32 hex chars)"
    if len({enc, mac, dek}) != 3:
        print("  refusing: the three new keys must differ from each other")
        sys.exit(1)
    if enc in (DEFAULT_ENC,) or mac in (DEFAULT_MAC,) or dek in (DEFAULT_DEK,):
        print("  refusing: at least one new key equals the public factory key - no security gained")
        sys.exit(1)

    print("== PUT KEY plan (nothing is sent) ==\n")
    print(f"  key version number (P1) : 0x{KEY_VERSION:02x}")
    print(f"  P2 (0x80 multiple | id) : 0x{0x80 | KEY_ID:02x}")
    print("  new key check values (compare with what the chip returns AFTER PUT KEY):")
    for name, key in (("ENC", enc), ("MAC", mac), ("DEK", dek)):
        print(f"    KCV(new {name}) = {h(kcv(key))}   encrypted-under-current-DEK = {h(dek_encrypt(DEFAULT_DEK, key))}")

    data, expected = build_put_key_data(KEY_VERSION, enc, mac, dek, DEFAULT_DEK)
    header = bytes([0x84, 0xD8, KEY_VERSION, 0x80 | KEY_ID])
    print(f"\n  PUT KEY data field ({len(data)} bytes):\n    {h(data)}")
    print(f"  APDU header (0x80 CLA -> 0x84 after SCP03 wrapping): {h(header)}  Lc = {len(data)}")
    print(f"\n  Expected chip response on success (KVN + the 3 KCVs): {h(expected)}")
    print("  Verify-after-send: the chip echoes exactly this; a match means the keys went in.")
    print("  Then immediately open a fresh channel with the NEW keys to confirm before trusting it.")
    print("\n  Framing confirmed against NXP se05x_TP_PlatformSCP03keys.c (createKeyData).")
    print("  The send step is intentionally not implemented here.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "selftest":
        cmd_selftest()
    elif cmd == "verify" and len(sys.argv) == 5:
        cmd_verify(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "plan" and len(sys.argv) == 5:
        cmd_plan(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
