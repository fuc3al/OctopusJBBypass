#!/usr/bin/env python3
"""
inject_dylib.py — add an LC_LOAD_DYLIB to a Mach-O by growing the header
padding (no shifting of any section data), optionally stripping the old
LC_CODE_SIGNATURE so a re-sign step (zsign / ldid / codesign) starts clean.

Works on x86/x64 Windows + Python 3.8+, no third-party modules.

Usage (recommended: operate on an already-extracted app directory)

    python inject_dylib.py --app  Payload/OctopusQuickBuild.app \
                           --dylib build/libOctopusJBHook.dylib \
                           [--name @executable_path/Frameworks/libOctopusJBHook.dylib] \
                           [--no-strip-codesig] [--dry-run]

    python inject_dylib.py --ipa 八達通-9.50.0.ipa --out Octopus-jb.ipa \
                           --dylib build/libOctopusJBHook.dylib
"""
import argparse
import os
import shutil
import struct
import sys
import tempfile
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
SIZEOF_HEADER = 32

DEFAULT_INSTALL_NAME = "@executable_path/Frameworks/libOctopusJBHook.dylib"


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def read_commands(data):
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    off = SIZEOF_HEADER
    cmds = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if size < 8 or off + size > SIZEOF_HEADER + sizeofcmds:
            raise SystemExit("corrupt load command at %#x (size=%d)" % (off, size))
        cmds.append((cmd, off, size))
        off += size
    if off != SIZEOF_HEADER + sizeofcmds:
        raise SystemExit("ncmds/sizeofcmds mismatch: walked %#x, header says %#x"
                         % (off, SIZEOF_HEADER + sizeofcmds))
    return ncmds, sizeofcmds, cmds


def first_section_file_offset(data, cmds):
    """Smallest file offset of any section == first byte after header padding."""
    best = None
    for cmd, off, size in cmds:
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from("<I", data, off + 64)[0]
        so = off + 72
        for _ in range(nsects):
            s_off = struct.unpack_from("<I", data, so + 48)[0]
            if best is None or (s_off and s_off < best):
                best = s_off
            so += 80
    return best


def build_dylib_command(install_name):
    payload = install_name.encode("utf-8") + b"\0"
    cmdsize = align(24 + len(payload), 8)
    buf = bytearray(cmdsize)
    struct.pack_into("<II", buf, 0, LC_LOAD_DYLIB, cmdsize)
    struct.pack_into("<IIII", buf, 8, 24, 0, 0x10000, 0x10000)  # name off, ts, cur, compat
    buf[24:24 + len(payload)] = payload
    return bytes(buf)


def inject(macho_path, install_name, strip_codesig=True, dry_run=False):
    with open(macho_path, "rb") as f:
        data = bytearray(f.read())

    if struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        raise SystemExit("%s: not a thin 64-bit Mach-O" % macho_path)

    ncmds, sizeofcmds, cmds = read_commands(data)
    limit = first_section_file_offset(data, cmds)
    if limit is None:
        raise SystemExit("cannot determine header padding boundary")

    kept = []
    dropped = []
    for cmd, off, size in cmds:
        if strip_codesig and cmd == LC_CODE_SIGNATURE:
            dropped.append((cmd, off, size))
            continue
        kept.append(bytes(data[off:off + size]))

    new_lc = build_dylib_command(install_name)
    new_end = SIZEOF_HEADER + sum(len(c) for c in kept) + len(new_lc)

    print("  header padding : %#x..%#x (%d bytes free)"
          % (SIZEOF_HEADER + sizeofcmds, limit, limit - (SIZEOF_HEADER + sizeofcmds)))
    print("  load commands  : %d kept, %d dropped (LC_CODE_SIGNATURE), +1 LC_LOAD_DYLIB"
          % (len(kept), len(dropped)))
    print("  new end        : %#x  (limit %#x, headroom %d)"
          % (new_end, limit, limit - new_end))

    if new_end > limit:
        raise SystemExit("not enough header padding — need --shift mode (not implemented)")

    body = b"".join(kept) + new_lc
    if dry_run:
        print("  [dry-run] nothing written")
        return True

    data[SIZEOF_HEADER:new_end] = body
    # zero the tail of the old command area so nothing stale is parsed
    old_end = SIZEOF_HEADER + sizeofcmds
    if old_end > new_end:
        data[new_end:old_end] = b"\0" * (old_end - new_end)
    struct.pack_into("<I", data, 16, len(kept) + 1)
    struct.pack_into("<I", data, 20, len(body))

    with open(macho_path, "wb") as f:
        f.write(data)

    # verify by re-parsing
    ncmds2, sizeofcmds2, cmds2 = read_commands(data)
    names = [c for c in cmds2 if c[0] == LC_LOAD_DYLIB]
    print("  verified       : ncmds=%d sizeofcmds=%d LC_LOAD_DYLIB x%d"
          % (ncmds2, sizeofcmds2, len(names)))
    return True


def do_app_dir(app_dir, dylib, install_name, strip_codesig, dry_run):
    exe = "OctopusQuickBuild"
    macho = os.path.join(app_dir, exe)
    if not os.path.isfile(macho):
        raise SystemExit("%s not found" % macho)
    print("[*] patching %s" % macho)
    inject(macho, install_name, strip_codesig, dry_run)

    if dry_run:
        return
    fw = os.path.join(app_dir, "Frameworks")
    os.makedirs(fw, exist_ok=True)
    dst = os.path.join(fw, os.path.basename(install_name))
    shutil.copy2(dylib, dst)
    print("[*] embedded dylib -> %s" % dst)
    print("[*] next: re-sign the bundle (zsign / ldid -S / codesign), then repack")


def do_ipa(ipa_path, out_path, dylib, install_name, strip_codesig, dry_run):
    tmp = tempfile.mkdtemp(prefix="octojb-")
    try:
        with zipfile.ZipFile(ipa_path) as z:
            z.extractall(tmp)
        app = os.path.join(tmp, "Payload", "OctopusQuickBuild.app")
        if not os.path.isdir(app):
            raise SystemExit("Payload/OctopusQuickBuild.app missing in %s" % ipa_path)
        do_app_dir(app, dylib, install_name, strip_codesig, dry_run)
        if dry_run:
            return
        print("[*] repacking -> %s" % out_path)
        out_abs = os.path.abspath(out_path)
        with zipfile.ZipFile(out_abs, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for root, _dirs, files in os.walk(tmp):
                for fn in files:
                    full = os.path.join(root, fn)
                    z.write(full, os.path.relpath(full, tmp))
        print("[*] done: %s (%.1f MB)" % (out_abs, os.path.getsize(out_abs) / 1048576.0))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--app", help="extracted OctopusQuickBuild.app directory")
    src.add_argument("--ipa", help="source .ipa")
    ap.add_argument("--out", help="output .ipa (with --ipa)")
    ap.add_argument("--dylib", required=True, help="built libOctopusJBHook.dylib")
    ap.add_argument("--name", default=DEFAULT_INSTALL_NAME, help="install name to inject")
    ap.add_argument("--no-strip-codesig", action="store_true",
                    help="keep LC_CODE_SIGNATURE (only if you will re-sign in place)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    strip = not a.no_strip_codesig
    if a.app:
        do_app_dir(a.app, a.dylib, a.name, strip, a.dry_run)
    else:
        if not a.out:
            raise SystemExit("--ipa requires --out")
        do_ipa(a.ipa, a.out, a.dylib, a.name, strip, a.dry_run)


if __name__ == "__main__":
    sys.exit(main())
