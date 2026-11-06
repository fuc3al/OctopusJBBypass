#!/usr/bin/env python3
"""
patch_binary.py — static (no-dylib) patch for the two app-level jailbreak checks.

Kills L1 + L2 only (DTT + JailbreakCheck). Promon SHIELD (L3) is untouched;
use the dylib route for that.

Verified targets (Octopus 9.50.0, sha256 df953e3a...):

  main  +[JailbreakCheck isJailbroken]          va 0x100010c1c  foff 0x010C1C
  main  +[JailbreakCheck jailbreakStatusCode]   va 0x100010c40  foff 0x010C40
  DTT   +[DTTJailbreakDetection isJailbroken]   va 0x0000004000  foff 0x004000

Usage:
  python patch_binary.py --app Payload/OctopusQuickBuild.app [--only jc|dtt] [--restore]
"""
import argparse
import os
import struct
import sys

MAIN = "OctopusQuickBuild"
DTT = os.path.join("Frameworks", "DTTJailbreakDetection.framework", "DTTJailbreakDetection")

# 0x52 80 00 00 => mov w0, #0 ; 0xd65f03c0 = ret
MOV_W0_0_RET = bytes.fromhex("00008052c0035fd6")
MOV_X0_0_RET = bytes.fromhex("000080d2c0035fd6")   # mov x0,#0 ; ret  (return nil)

SITES = {
    "jc_isJailbroken":  (MAIN, 0x010C1C, MOV_W0_0_RET, "fd7bbfa9", "mov w0,#0; ret"),
    "jc_statusCode":    (MAIN, 0x010C40, MOV_X0_0_RET, "ff8301d1", "mov x0,#0; ret (nil)"),
    "dtt_isJailbroken": (DTT,  0x004000, MOV_W0_0_RET, "ff0301d1", "mov w0,#0; ret"),
}


def apply(app_dir, key, patch_bytes, restore):
    rel, off, new, expect, desc = SITES[key]
    path = os.path.join(app_dir, rel)
    if not os.path.isfile(path):
        return "SKIP  %-18s %s missing" % (key, rel)
    with open(path, "r+b") as f:
        f.seek(off)
        cur = f.read(4)
        if cur.hex() != expect and not restore:
            return "SKIP  %-18s unexpected bytes %s (expected %s)" % (key, cur.hex(), expect)
        if restore:
            return "INFO  %-18s restore needs a backup copy; re-extract the IPA instead" % key
        f.seek(off)
        f.write(new)
    return "OK    %-18s %s+%#x  %s" % (key, rel, off, desc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, help="extracted Payload/OctopusQuickBuild.app")
    ap.add_argument("--only", choices=["jc", "dtt"], help="patch only one layer")
    ap.add_argument("--restore", action="store_true")
    a = ap.parse_args()

    keys = ["jc_isJailbroken", "jc_statusCode", "dtt_isJailbroken"]
    if a.only == "jc":
        keys = ["jc_isJailbroken", "jc_statusCode"]
    elif a.only == "dtt":
        keys = ["dtt_isJailbroken"]

    for k in keys:
        print(apply(a.app, k, SITES[k][2], a.restore))
    print("\nnext: re-sign the bundle, then repack the .ipa")


if __name__ == "__main__":
    sys.exit(main())
