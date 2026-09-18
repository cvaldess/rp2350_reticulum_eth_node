"""PlatformIO post-script: seal the image (hash + secp256k1 signature) so an RP2350 with
secure boot enabled will run it (docs/secure_boot.md).

Runs after the platform has produced firmware.elf/.bin/.uf2. With the signing key present:
  firmware.sealed.elf   the ELF plus picotool's signed IMAGE_DEF block (.sigx)
  firmware.uf2 / .bin   REPLACED by the sealed image (what BOOTSEL, `pio run -t upload` and
                        tools/ota_upload.py use), the unsigned ones kept as firmware.unsigned.*
  firmware.otp.json     the OTP rows picotool would burn for this key (bootkey0 + flags)
and the result is checked with tools/picobin.py the way the bootrom checks it; a build whose
image would not boot on a secured board fails here, not on the bench.

Without the key (NODE_SIGN_KEY, or bootkey0.pem in NODE_KEYS_DIR / ~/.rp2350-keys) the build
stays unsigned and says so loudly: fine for a blank board, refused by a secured one.
"""
import os
import shutil
import subprocess
import sys

Import("env")  # noqa: F821 (PlatformIO injects it)

root = env.subst("$PROJECT_DIR")  # noqa: F821
sys.path.insert(0, os.path.join(root, "tools"))
import picobin  # noqa: E402

IMAGE_MAJOR = 1  # bumped by hand when the image format or the key changes


def signing_key():
    path = os.environ.get("NODE_SIGN_KEY")
    if not path:
        keys_dir = os.environ.get("NODE_KEYS_DIR") or os.path.join(os.path.expanduser("~"), ".rp2350-keys")
        path = os.path.join(keys_dir, "bootkey0.pem")
    return path if os.path.isfile(path) else None


def picotool():
    pkg = env.PioPlatform().get_package_dir("tool-picotool-rp2040-earlephilhower")  # noqa: F821
    exe = os.path.join(pkg, "picotool.exe" if os.name == "nt" else "picotool") if pkg else "picotool"
    return exe if os.path.isfile(exe) else "picotool"


def commit_count():
    try:
        n = int(subprocess.check_output(["git", "rev-list", "--count", "HEAD"], cwd=root,
                                        stderr=subprocess.DEVNULL).decode().strip())
        return n & 0xFFFF
    except Exception:
        return 0


def run(args):
    print(" ".join('"%s"' % a if " " in a else a for a in args))
    subprocess.check_call(args)


def seal(target, source, env):
    # Hooked on firmware.bin, the last of the three the platform builds (the UF2 is a post
    # action of the ELF, the .bin an objcopy target after it), so nothing overwrites the result.
    binf = target[0].get_path()
    base = binf[:-4]
    elf, uf2 = base + ".elf", base + ".uf2"
    key = signing_key()
    if not key:
        print("\n" + "!" * 78 + "\n!! UNSIGNED BUILD: no signing key (NODE_SIGN_KEY / ~/.rp2350-keys/bootkey0.pem).\n"
              "!! A board with secure boot enabled will refuse this image.\n" + "!" * 78 + "\n")
        return
    sealed = base + ".sealed.elf"
    otp_json = base + ".otp.json"
    if os.path.exists(otp_json):
        os.remove(otp_json)  # picotool edits an existing file; start clean
    minor = commit_count()
    run([picotool(), "seal", "--quiet", "--hash", "--sign", elf, sealed, key, otp_json,
         "--major", str(IMAGE_MAJOR), "--minor", str(minor)])
    for path in (uf2, binf):
        if os.path.exists(path):
            shutil.copyfile(path, base + ".unsigned" + path[len(base):])
    run([picotool(), "uf2", "convert", "--quiet", "-t", "elf", sealed, uf2])
    run([env.subst("$OBJCOPY"), "-O", "binary", sealed, binf])

    with open(uf2, "rb") as f:
        img = picobin.uf2_to_image(f.read())
    ok, detail, pub = picobin.verify(img)
    if not ok:
        raise SystemExit("seal: the sealed image does not verify: %s" % detail)
    known = picobin.known_pubkeys(os.path.join(root, "include", "boot_pubkeys.h"))
    if known and pub not in known:
        raise SystemExit("seal: signed with a key that is not in include/boot_pubkeys.h (run tools/keys.py export)")
    with open(binf, "rb") as f:
        raw = f.read()
    # The UF2 pads the last 256-byte block; the .bin stops at the last byte of the image.
    if raw != img[:len(raw)] or len(img) - len(raw) >= 256:
        raise SystemExit("seal: firmware.bin and firmware.uf2 differ after sealing")
    print("sealed: version %d.%d, %d bytes, key fingerprint %s, %s" %
          (IMAGE_MAJOR, minor, len(img), picobin.bootkey_fingerprint(pub).hex()[:16], detail))


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", env.VerboseAction(seal, "Sealing image (hash + signature)"))  # noqa: F821
