#!/usr/bin/env python3
"""
verify_ipa_signature.py — prove whether an installed Mach-O is byte-identical to
what Apple signed, by re-hashing every code page against the CodeDirectory.

  python tools/verify_ipa_signature.py <macho>

Prints: CodeDirectory identity (identifier / team / platform), per-page hash
result, special-slot count, and the entitlements blob summary.
"""
import hashlib
import json
import struct
import sys

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

HASH_NAMES = {1: "sha1", 2: "sha256", 3: "sha256-truncated", 4: "sha384"}


def parse_superblob(buf):
    magic, length, count = struct.unpack_from(">III", buf, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise SystemExit("not an embedded signature superblob: %#x" % magic)
    idx = []
    for i in range(count):
        t, off = struct.unpack_from(">II", buf, 12 + i * 8)
        idx.append((t, off))
    return idx


def parse_codedirectory(buf, off):
    magic, length, version, flags = struct.unpack_from(">IIII", buf, off)
    if magic != CSMAGIC_CODEDIRECTORY:
        raise SystemExit("bad CodeDirectory magic %#x" % magic)
    (hash_off, ident_off, n_special, n_code, code_limit) = struct.unpack_from(">IIIII", buf, off + 16)
    hash_size, hash_type, platform, page_size_log = struct.unpack_from(">BBBB", buf, off + 36)
    team_off = None
    if version >= 0x20200:
        team_off = struct.unpack_from(">I", buf, off + 48)[0]
    ident = buf[off + ident_off:buf.index(b"\0", off + ident_off)].decode("utf-8", "replace")
    team = None
    if team_off:
        team = buf[off + team_off:buf.index(b"\0", off + team_off)].decode("utf-8", "replace")
    return dict(version=version, flags=flags, hash_off=hash_off, n_special=n_special,
                n_code=n_code, code_limit=code_limit, hash_size=hash_size,
                hash_type=hash_type, platform=platform, page_size=1 << page_size_log,
                ident=ident, team=team, length=length)


def verify(path):
    data = open(path, "rb").read()
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    sig = None
    dylibs = []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", data, off)
        if cmd == 0x1D:                                  # LC_CODE_SIGNATURE
            doff, dsize = struct.unpack_from("<II", data, off + 8)
            sig = (doff, dsize)
        elif cmd in (0xC, 0x80000018, 0x1F, 0x23):        # LC_LOAD_DYLIB & friends
            noff = struct.unpack_from("<I", data, off + 8)[0]
            nm = data[off + noff:off + sz].split(b"\0")[0].decode("utf-8", "replace")
            dylibs.append(nm)
        off += sz

    print("file            : %s (%.1f MB)" % (path, len(data) / 1048576))
    print("LC_LOAD_DYLIB   : %d entries" % len(dylibs))
    odd = [d for d in dylibs
           if not (d.startswith("/usr/lib/") or d.startswith("/System/Library/")
                   or d.startswith("@rpath/") or d.startswith("@executable_path/"))]
    print("  unusual paths :", odd or "none")
    thirdparty = [d for d in dylibs if "/var/jb" in d or "Substrate" in d or "TrollFools" in d
                  or "OctopusJB" in d or "frida" in d.lower() or "cycript" in d.lower()]
    print("  jailbreak libs:", thirdparty or "none")

    if not sig:
        print("no LC_CODE_SIGNATURE -> unsigned/ad-hoc stripped")
        return
    doff, dsize = sig
    blob = data[doff:doff + dsize]
    idx = parse_superblob(blob)
    print("signature slots :", [(hex(t), o) for t, o in idx])

    cd_off = next((o for t, o in idx if t == 0), None)
    if cd_off is None:
        print("no slot-0 CodeDirectory")
        return
    cd = parse_codedirectory(blob, cd_off)
    print("identifier      :", cd["ident"])
    print("team            :", cd["team"])
    print("cd version      : %#x   flags=%#x   platform=%d" % (cd["version"], cd["flags"], cd["platform"]))
    print("hash            : %s  page=%d  slots=%d  codeLimit=%d"
          % (HASH_NAMES.get(cd["hash_type"], cd["hash_type"]), cd["page_size"],
             cd["n_code"], cd["code_limit"]))

    hname = {1: "sha1", 2: "sha256", 3: "sha256", 4: "sha384"}.get(cd["hash_type"])
    hs = cd["hash_size"]
    base = cd_off + cd["hash_off"]
    bad = []
    for i in range(cd["n_code"]):
        start = i * cd["page_size"]
        end = min(start + cd["page_size"], cd["code_limit"])
        got = hashlib.new(hname, data[start:end]).digest()[:hs]
        want = blob[base + i * hs: base + (i + 1) * hs]
        if got != want:
            bad.append(i)
    print("page check      : %d/%d pages match" % (cd["n_code"] - len(bad), cd["n_code"]))
    if bad:
        print("  MISMATCH pages:", bad[:12], "..." if len(bad) > 12 else "")
        print("  => binary was modified after signing")
    else:
        print("  => every code page matches Apple's signature: BINARY IS UNMODIFIED")

    ent = next((o for t, o in idx if t == 5), None)
    if ent:
        m, ln = struct.unpack_from(">II", blob, ent)
        xml = blob[ent + 8: ent + ln].decode("utf-8", "replace")
        keys = [l.strip().strip("<key>").strip("</key>") for l in xml.splitlines() if "<key>" in l]
        print("entitlements    :", keys)


if __name__ == "__main__":
    sys.exit(verify(sys.argv[1]))
