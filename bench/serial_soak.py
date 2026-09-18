"""Overnight serial logger for one bench board.

Keeps the USB console open, appends everything the node prints to a log file with a local
timestamp, and every `interval` seconds asks for the status commands (default "eh": Ethernet /
TCP / LoRa counters and heap). Reconnects if the port disappears (reboot, re-enumeration).

    python bench/serial_soak.py COM64 bench/logs/bench1.log
    python bench/serial_soak.py --usb 2e8a:000f:C2D7C1786C637F15 bench/logs/bench1.log

--usb resolves the device by VID:PID:serial (pyserial hwid) instead of a fixed port name: on
Linux /dev/ttyACM* is assigned in connection order, so after a reboot or a re-enumeration (an
OTA, a reset) two boards can swap device files. The board's USB serial is its RP2350 chip ID
(see docs/secure_boot.md `Oi`, or `picotool info -d` before securing a board); read it once with
--list. A fixed port name (positional, Windows COM* or a stable /dev/serial/by-id path) still
works unchanged.
"""
import argparse
import os
import sys
import time

import serial
import serial.tools.list_ports


def find_by_usb(spec):
    """spec = 'vid:pid:serial' (hex, case-insensitive). None if not currently plugged in."""
    vid_s, pid_s, serial_s = spec.split(":", 2)
    vid, pid = int(vid_s, 16), int(pid_s, 16)
    for p in serial.tools.list_ports.comports():
        if p.vid == vid and p.pid == pid and (p.serial_number or "").upper() == serial_s.upper():
            return p.device
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", nargs="?", help="fixed port (COM64, /dev/ttyACM0, ...)")
    ap.add_argument("logfile", nargs="?")
    ap.add_argument("--usb", metavar="VID:PID:SERIAL", help="resolve the port by USB identity instead")
    ap.add_argument("--interval", type=float, default=60.0)
    ap.add_argument("--cmds", default="eh")
    ap.add_argument("--list", action="store_true", help="print vid:pid:serial of every port and exit")
    args = ap.parse_args()

    if args.list:
        for p in serial.tools.list_ports.comports():
            usb = f"{p.vid:04x}:{p.pid:04x}:{p.serial_number}" if p.vid is not None else "(not USB)"
            print(f"{p.device}\t{usb}\t{p.description}")
        return
    if args.usb and args.port and not args.logfile:
        # --usb takes the port slot out of the two positionals: "--usb V:P:S logfile" leaves
        # only one positional, which argparse assigns to the first (port), not logfile.
        args.port, args.logfile = None, args.port
    if not args.usb and not args.port:
        ap.error("give a port, or --usb VID:PID:SERIAL")
    if not args.logfile:
        ap.error("logfile is required")

    os.makedirs(os.path.dirname(os.path.abspath(args.logfile)), exist_ok=True)
    log = open(args.logfile, "ab", buffering=0)

    def write(line):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{stamp} {line}\n".encode("utf-8", "replace"))

    write(f"--- soak start target={args.usb or args.port} interval={args.interval}s cmds={args.cmds}")
    ser = None
    last_cmd = 0.0
    pending = b""
    missing_logged = False
    while True:
        if ser is None:
            port = find_by_usb(args.usb) if args.usb else args.port
            if port is None:
                if not missing_logged:
                    write(f"--- device {args.usb} not present, waiting")
                    missing_logged = True
                time.sleep(2)
                continue
            try:
                ser = serial.Serial(port, 115200, timeout=0.5)
                write(f"--- port opened ({port})" if args.usb else "--- port opened")
                missing_logged = False
            except Exception as e:
                time.sleep(2)
                continue
        try:
            if time.time() - last_cmd >= args.interval:
                last_cmd = time.time()
                ser.write(args.cmds.encode())
                ser.flush()
            data = ser.read(4096)
            if data:
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    write(line.decode("utf-8", "replace").rstrip("\r"))
        except Exception as e:
            write(f"--- port error: {e!r}, reopening")
            try:
                ser.close()
            except Exception:
                pass
            ser = None
            time.sleep(2)


if __name__ == "__main__":
    main()
