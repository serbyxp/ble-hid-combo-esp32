#!/usr/bin/env python3
"""Simple CLI client for the ESP32 UART HID bridge.

The script detects a `/dev/ttyUSB*` device (or uses the port provided
with `--port`), sends newline-delimited JSON commands that match the
firmware expectations, and optionally waits for the bridge to report it
is ready.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List

import serial

DEFAULT_BAUD = 115200
READY_EVENT = "ready"
STATUS_TYPE = "status"


@dataclass
class SerialConfig:
    port: str
    baud: int = DEFAULT_BAUD
    wait_ready: bool = True
    ready_timeout: float = 5.0


def find_default_port() -> str:
    matches = sorted(glob.glob("/dev/ttyUSB*"))
    if not matches:
        raise SystemExit("No /dev/ttyUSB* ports found; pass --port explicitly")
    return matches[0]


def open_serial(cfg: SerialConfig) -> serial.Serial:
    return serial.Serial(cfg.port, cfg.baud, timeout=0.2)


def wait_for_ready(ser: serial.Serial, timeout: float) -> None:
    if timeout <= 0:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        raw = ser.readline()
        if not raw:
            continue
        try:
            msg = json.loads(raw.decode(errors="ignore"))
        except json.JSONDecodeError:
            continue
        if msg.get("type") == STATUS_TYPE and msg.get("event") == READY_EVENT:
            print("[uart] bridge reported ready", file=sys.stderr)
            return
    raise SystemExit("Timed out waiting for ready status from bridge")


def send_json(ser: serial.Serial, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":")) + "\n"
    ser.write(data.encode("utf-8"))


def monitor_serial(ser: serial.Serial) -> None:
    try:
        while True:
            raw = ser.readline()
            if raw:
                try:
                    decoded = raw.decode().rstrip()
                except UnicodeDecodeError:
                    decoded = raw.hex()
                print(decoded)
    except KeyboardInterrupt:
        pass


def parse_keys(tokens: Iterable[str]) -> List[int]:
    out: List[int] = []
    for tok in tokens:
        if not tok:
            continue
        base = 16 if tok.lower().startswith("0x") else 10
        try:
            value = int(tok, base)
        except ValueError as exc:
            raise SystemExit(f"Invalid key code '{tok}': {exc}") from exc
        if not 0 <= value <= 0xFF:
            raise SystemExit(f"Key code '{tok}' out of range (0-255)")
        out.append(value)
    if len(out) > 6:
        raise SystemExit("At most 6 key codes are supported")
    while len(out) < 6:
        out.append(0)
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send UART HID bridge commands")
    parser.add_argument(
        "-p",
        "--port",
        help="Serial port (default: first /dev/ttyUSB*)",
    )
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for ready status message",
    )
    parser.add_argument(
        "--ready-timeout",
        type=float,
        default=5.0,
        help="Seconds to wait for ready status",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="Print any incoming UART lines after sending the command",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    mouse = sub.add_parser("mouse", help="Send a relative mouse movement")
    mouse.add_argument("dx", type=int, help="X delta")
    mouse.add_argument("dy", type=int, help="Y delta")
    mouse.add_argument("wheel", type=int, nargs="?", default=0, help="Wheel delta")
    mouse.add_argument("--b1", type=int, choices=(0, 1), default=0, help="Button 1 state")
    mouse.add_argument("--b2", type=int, choices=(0, 1), default=0, help="Button 2 state")
    mouse.add_argument("--b3", type=int, choices=(0, 1), default=0, help="Button 3 state")

    key = sub.add_parser("key", help="Send a keyboard report")
    key.add_argument("--mods", type=lambda s: int(s, 0), default=0, help="Modifier bitmap (e.g. 0x02)")
    key.add_argument(
        "keys",
        nargs="*",
        default=(),
        help="Up to 6 key codes (decimal or hex)",
    )

    consumer = sub.add_parser("consumer", help="Send a consumer control usage")
    consumer.add_argument(
        "usage",
        type=lambda s: int(s, 0),
        nargs="?",
        help="16-bit usage value (decimal or hex)",
    )
    consumer.add_argument("--lo", type=lambda s: int(s, 0), help="Low byte of the usage (decimal or hex)")
    consumer.add_argument("--hi", type=lambda s: int(s, 0), help="High byte of the usage (decimal or hex)")

    battery = sub.add_parser("battery", help="Update reported battery percentage")
    battery.add_argument("pct", type=int, help="Battery percent 0-100")

    config = sub.add_parser("config", help="Update feature toggles")
    config.add_argument("--wifi", choices=("on", "off"))
    config.add_argument("--web", choices=("on", "off"))
    config.add_argument("--uart", choices=("on", "off"))

    sub.add_parser("listen", help="Only listen for incoming UART messages")

    return parser


def run(args: argparse.Namespace) -> None:
    port = args.port or find_default_port()
    cfg = SerialConfig(port=port, baud=args.baud, wait_ready=not args.no_wait, ready_timeout=args.ready_timeout)

    with open_serial(cfg) as ser:
        if cfg.wait_ready and args.command != "listen":
            wait_for_ready(ser, cfg.ready_timeout)
        elif cfg.wait_ready and args.command == "listen":
            try:
                wait_for_ready(ser, cfg.ready_timeout)
            except SystemExit:
                pass

        if args.command == "mouse":
            payload = {
                "type": "mouse",
                "dx": args.dx,
                "dy": args.dy,
                "wheel": args.wheel,
                "b1": args.b1,
                "b2": args.b2,
                "b3": args.b3,
            }
            send_json(ser, payload)
        elif args.command == "key":
            payload = {
                "type": "key",
                "mods": args.mods,
                "keys": parse_keys(args.keys),
            }
            send_json(ser, payload)
        elif args.command == "consumer":
            if args.usage is not None:
                usage = max(0, min(0xFFFF, args.usage))
                payload = {"type": "consumer", "usage": usage}
            else:
                if args.lo is None or args.hi is None:
                    raise SystemExit("Specify either a usage value or both --lo and --hi")
                usage_lo = max(0, min(0xFF, args.lo))
                usage_hi = max(0, min(0xFF, args.hi))
                payload = {
                    "type": "consumer",
                    "usage_low": usage_lo,
                    "usage_high": usage_hi,
                }
            send_json(ser, payload)
        elif args.command == "battery":
            pct = max(0, min(100, args.pct))
            payload = {"type": "battery", "pct": pct}
            send_json(ser, payload)
        elif args.command == "config":
            payload = {"type": "config"}
            if args.wifi:
                payload["wifi"] = args.wifi == "on"
            if args.web:
                payload["web"] = args.web == "on"
            if args.uart:
                payload["uart"] = args.uart == "on"
            send_json(ser, payload)
        elif args.command == "listen":
            pass  # nothing to send
        else:
            raise SystemExit(f"Unhandled command {args.command}")

        if args.listen or args.command == "listen":
            monitor_serial(ser)


if __name__ == "__main__":
    parser = build_parser()
    run(parser.parse_args())
