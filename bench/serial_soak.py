"""Overnight serial logger for one bench board.

Keeps the USB console open, appends everything the node prints to a log file with a PC
timestamp, and every `interval` seconds asks for the status commands (default "eh": Ethernet /
TCP / LoRa counters and heap). Reconnects if the port disappears (reboot, re-enumeration).

    python bench/serial_soak.py COM64 bench/logs/bench1.log
    python bench/serial_soak.py COM9  bench/logs/bench2.log --interval 60 --cmds eh
"""
import argparse
import os
import sys
import time

import serial


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port")
    ap.add_argument("logfile")
    ap.add_argument("--interval", type=float, default=60.0)
    ap.add_argument("--cmds", default="eh")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.logfile)), exist_ok=True)
    log = open(args.logfile, "ab", buffering=0)

    def write(line):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{stamp} {line}\n".encode("utf-8", "replace"))

    write(f"--- soak start port={args.port} interval={args.interval}s cmds={args.cmds}")
    ser = None
    last_cmd = 0.0
    pending = b""
    while True:
        if ser is None:
            try:
                ser = serial.Serial(args.port, 115200, timeout=0.5)
                write("--- port opened")
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
