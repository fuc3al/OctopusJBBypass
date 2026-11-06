#!/usr/bin/env python3
"""deploy_tweak.py — 把编译好的 dylib 当作 ellekit/Substrate tweak 装进目标 App。

为什么不用 TrollFools 注入：TrollFools 会改 Mach-O 并重新签名，App Store 的加密
二进制（LC_ENCRYPTION_INFO cryptid=1）一换签名就不再被 FairPlay 解密，启动即死。
ellekit 是进程级注入，App 签名和二进制都不动（见 docs/03-crash-analysis.md）。

配置走环境变量：
    IPHONE_HOST / IPHONE_USER / IPHONE_PASS    SSH
    IPHONE_SERIAL                              pymobiledevice3 用的 UDID（仅 syslog 用）

用法:
    python tools/deploy_tweak.py install  --dylib build/libFoo.dylib --bundle com.example.app
    python tools/deploy_tweak.py remove   --name libFoo
    python tools/deploy_tweak.py logout   --group-plist-path /var/mobile/.../group.com.example.app.plist
    python tools/deploy_tweak.py launch   --bundle com.example.app
"""
import argparse
import os
import plistlib
import sys
import tempfile

import paramiko

HOST = os.environ.get("IPHONE_HOST", "")
USER = os.environ.get("IPHONE_USER", "mobile")
PASS = os.environ.get("IPHONE_PASS", "")
TWEAK_DIR = os.environ.get("IPHONE_TWEAK_DIR", "/var/jb/usr/lib/TweakInject")
PATH_ENV = "export PATH=/var/jb/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin;"

FILTER_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Filter</key>
\t<dict>
\t\t<key>Bundles</key>
\t\t<array>
\t\t\t<string>%s</string>
\t\t</array>
\t</dict>
</dict>
</plist>
"""


class Dev:
    def __init__(self):
        if not HOST or not PASS:
            sys.exit("set IPHONE_HOST and IPHONE_PASS first")
        self.cl = paramiko.SSHClient()
        self.cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.cl.connect(HOST, username=USER, password=PASS, timeout=10,
                        allow_agent=False, look_for_keys=False)
        self.sf = self.cl.open_sftp()

    def run(self, cmd, sudo=False, t=90):
        c = cmd if not sudo else "echo %s | sudo -S -p '' sh -c '%s'" % (PASS, cmd.replace("'", "'\\''"))
        i, o, e = self.cl.exec_command(c, timeout=t)
        return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).strip()

    def close(self):
        try:
            self.sf.close()
            self.cl.close()
        except Exception:
            pass


def cmd_install(dev, a):
    name = os.path.splitext(os.path.basename(a.dylib))[0]
    stage = "/var/mobile/%s.dylib" % name
    dev.sf.put(a.dylib, stage)
    print("staged ->", stage)

    tmp = os.path.join(tempfile.gettempdir(), name + ".plist")
    open(tmp, "w", encoding="utf-8").write(FILTER_PLIST % a.bundle)
    stage_plist = "/var/mobile/%s.plist" % name
    dev.sf.put(tmp, stage_plist)

    print(dev.run("mkdir -p %s && cp %s %s/%s.dylib && cp %s %s/%s.plist && "
                  "chown root:wheel %s/%s.dylib %s/%s.plist && "
                  "chmod 755 %s/%s.dylib && chmod 644 %s/%s.plist && echo INSTALLED"
                  % (TWEAK_DIR, stage, TWEAK_DIR, name, stage_plist, TWEAK_DIR, name,
                     TWEAK_DIR, name, TWEAK_DIR, name, TWEAK_DIR, name, TWEAK_DIR, name),
                  sudo=True))
    print(dev.run(PATH_ENV + " killall -9 %s 2>/dev/null; uiopen -b %s; sleep 8; "
                  "ps -A -o pid,comm | grep -i %s || echo NOT-RUNNING"
                  % (a.proc, a.bundle, a.proc)))


def cmd_remove(dev, a):
    print(dev.run("rm -f %s/%s.dylib %s/%s.plist && echo REMOVED"
                  % (TWEAK_DIR, a.name, TWEAK_DIR, a.name), sudo=True))


def cmd_logout(dev, a):
    """真登出：摘掉 App Group 里的 session 键，再重启 cfprefsd。"""
    local = os.path.join(tempfile.gettempdir(), "group.plist")
    dev.sf.get(a.group_plist_path, local)
    d = plistlib.load(open(local, "rb"))
    removed = [k for k in list(d) if a.match in k]
    for k in removed:
        d.pop(k, None)
    if not removed:
        print("no key matching %r; nothing to do" % a.match)
        return
    plistlib.dump(d, open(local, "wb"), fmt=plistlib.FMT_BINARY)
    stage = "/var/mobile/group_edit.plist"
    dev.sf.put(local, stage)
    print("removed:", removed)
    print(dev.run("cp %s %s && chown mobile:mobile %s && chmod 600 %s && echo REPLACED"
                  % (stage, a.group_plist_path, a.group_plist_path, a.group_plist_path), sudo=True))
    print(dev.run("rm -f %s; killall -9 cfprefsd 2>/dev/null; echo CFPreFSD-RESTARTED" % stage, sudo=True))


def cmd_launch(dev, a):
    print(dev.run(PATH_ENV + " killall -9 %s 2>/dev/null; sleep 1; uiopen -b %s; sleep 10; "
                  "ps -A -o pid,comm | grep -i %s || echo NOT-RUNNING"
                  % (a.proc, a.bundle, a.proc)))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="op", required=True)

    p = sub.add_parser("install")
    p.add_argument("--dylib", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--proc", default="", help="进程名，用于 killall/ps")
    p.set_defaults(fn=cmd_install)

    p = sub.add_parser("remove")
    p.add_argument("--name", required=True)
    p.set_defaults(fn=cmd_remove)

    p = sub.add_parser("logout")
    p.add_argument("--group-plist-path", required=True)
    p.add_argument("--match", default="session")
    p.set_defaults(fn=cmd_logout)

    p = sub.add_parser("launch")
    p.add_argument("--bundle", required=True)
    p.add_argument("--proc", default="")
    p.set_defaults(fn=cmd_launch)

    a = ap.parse_args()
    if not getattr(a, "proc", ""):
        a.proc = a.bundle.rsplit(".", 1)[-1]
    dev = Dev()
    try:
        a.fn(dev, a)
    finally:
        dev.close()


if __name__ == "__main__":
    main()
