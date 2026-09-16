"""Capture what a board prints while it boots, over the USB console.

    python bench/serial_boot_log.py COM64                 # send 'r', then log the boot for 20 s
    python bench/serial_boot_log.py COM64 --no-reboot 60  # just wait for the next boot (an OTA, say)

The RP2350 re-enumerates on reboot, so the port vanishes and comes back; this keeps trying to
reopen it and prints everything from the moment it answers, which is the only way to see the
boot banner, the [ota] trial lines and the OTA stub's outcome from the PC. Stop the
serial_soak.py logger on that port first: Windows gives the port to one process.
"""
import argparse
import sys
import time

import serial


def open_port(port, deadline):
    while time.time() < deadline:
        try:
            return serial.Serial(port, 115200, timeout=0.2)
        except serial.SerialException:
            time.sleep(0.2)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port")
    ap.add_argument("seconds", nargs="?", type=float, default=20.0, help="how long to log after the port is back")
    ap.add_argument("--no-reboot", action="store_true", help="do not send 'r'; wait for the board to reboot by itself")
    ap.add_argument("--wait", type=float, default=120.0, help="seconds to wait for the port to (re)appear")
    args = ap.parse_intermixed_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if not args.no_reboot:
        s = open_port(args.port, time.time() + 10)
        if not s:
            raise SystemExit("cannot open %s" % args.port)
        s.write(b"r")
        s.flush()
        time.sleep(0.3)
        s.close()
        print("--- sent 'r', waiting for %s to come back" % args.port)
        time.sleep(1.5)
    else:
        print("--- waiting for %s" % args.port)
        # If the board is up now, wait until the port goes away first (the reboot), then reopen.
        s = open_port(args.port, time.time() + 2)
        if s:
            s.close()
            deadline = time.time() + args.wait
            while time.time() < deadline:
                try:
                    serial.Serial(args.port, 115200, timeout=0.1).close()
                    time.sleep(0.2)
                except serial.SerialException:
                    break

    s = open_port(args.port, time.time() + args.wait)
    if not s:
        raise SystemExit("port did not come back within %.0f s" % args.wait)
    print("--- %s is back, logging %.0f s" % (args.port, args.seconds))
    t0 = time.time()
    buf = b""
    while time.time() - t0 < args.seconds:
        try:
            d = s.read(4096)
        except serial.SerialException:
            print("--- port went away again")
            break
        if d:
            buf += d
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                print("%6.1f %s" % (time.time() - t0, line.decode("utf-8", "replace").rstrip()))
    s.close()


if __name__ == "__main__":
    main()
