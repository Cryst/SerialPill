#!/usr/bin/env python3
"""Build a Shelly-compatible OTA package ("Update from file") for SerialPill.

The package mirrors the official Pill package layout (manifest.json + parts). Only the
`app` part is SerialPill; bootloader, partition table and boot state are the stock Shelly
ones, so the stock updater accepts and boots it. SerialPill then migrates itself to the
standard ESP-IDF bootloader on its first boot.

Also writes dist/serialpill-ota.bin (plain app image for SerialPill's own OTA) and copies
the standard bootloader that gets embedded into the firmware.
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
STOCK = os.path.join(HERE, "..", "shelly-fw", "Pill-2.0.1.zip")


def app_version(app):
    # esp_app_desc_t follows the first segment header: magic 0xABCD5432 at offset 32
    off = app.find(struct.pack("<I", 0xABCD5432))
    if off < 0:
        return "0.0.0"
    return app[off + 16:off + 48].split(b"\0")[0].decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--bootloader")
    ap.add_argument("--stock", default=STOCK, help="official Shelly Pill package (for boot/pt/boot_state/fs)")
    ap.add_argument("--out", default="dist")
    a = ap.parse_args()

    app = open(a.app, "rb").read()
    ver = app_version(app)
    os.makedirs(a.out, exist_ok=True)
    stock = zipfile.ZipFile(a.stock)
    man = json.loads(stock.read("manifest.json"))

    build = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    man["version"] = ver
    man["build_id"] = f"{build}/serialpill-{ver}"
    man["build_timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    man["parts"]["app"].update({
        "src": "SerialPill.bin",
        "size": len(app),
        "cs_sha256": hashlib.sha256(app).hexdigest(),
    })

    out = os.path.join(a.out, f"SerialPill-{ver}-shelly-ota.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr("manifest.json", json.dumps(man, indent=1))
        for part in man["parts"].values():
            src = part.get("src")
            if not src:
                continue
            data = app if src == "SerialPill.bin" else stock.read(src)
            z.writestr(src, data)
    shutil.copyfile(a.app, os.path.join(a.out, f"SerialPill-{ver}-ota.bin"))
    print(f"{out} ({os.path.getsize(out)} B), app {len(app)} B, version {ver}")


if __name__ == "__main__":
    main()
