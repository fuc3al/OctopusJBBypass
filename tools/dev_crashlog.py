#!/usr/bin/env python3
"""dev_crashlog.py — 拉取并归纳设备上的崩溃报告（pymobiledevice3）。

    IPHONE_SERIAL=<udid> python tools/dev_crashlog.py --pull ./crashes
    IPHONE_SERIAL=<udid> python tools/dev_crashlog.py --sig ./crashes Octopus

只依赖 pymobiledevice3 的 crash 服务（无需越狱、无需 SSH）。
"""
import argparse
import glob
import json
import os
import subprocess
import sys

UDID = os.environ.get("IPHONE_SERIAL", "")


def pull(dest):
    if not UDID:
        sys.exit("set IPHONE_SERIAL")
    os.makedirs(dest, exist_ok=True)
    rc = subprocess.call([sys.executable, "-m", "pymobiledevice3", "crash", "pull",
                          "--udid", UDID, dest])
    return rc


def sig(path):
    """返回 (版本, 异常类型, 信号, 镜像数, 帧数, 顶部两帧)。"""
    raw = open(path, encoding="utf-8", errors="replace").read()
    head, _, body = raw.partition("\n")
    try:
        h = json.loads(head)
    except Exception:
        h = {}
    try:
        d = json.loads(body)
    except Exception:
        d = {}
    exc = d.get("exception", {})
    th = d.get("threads", [])
    ft = d.get("faultingThread") or 0
    frames = th[ft].get("frames", []) if ft < len(th) else []
    imgs = d.get("usedImages", [])

    def nm(i):
        return imgs[i].get("name", "?") if i is not None and i < len(imgs) else "?"

    top = [nm(f.get("imageIndex")) + "/" + str(f.get("symbol")) for f in frames[:2]]
    return (h.get("app_version"), exc.get("type"), exc.get("signal"),
            len(imgs), len(frames), top)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull", metavar="DIR")
    ap.add_argument("--sig", metavar="DIR")
    ap.add_argument("--match", default="", help="文件名过滤，例如 App 名")
    a = ap.parse_args()

    if a.pull:
        sys.exit(pull(a.pull))

    if a.sig:
        files = sorted(glob.glob(os.path.join(a.sig, "*.ips")))
        if a.match:
            files = [f for f in files if a.match.lower() in os.path.basename(f).lower()]
        for f in files[-20:]:
            print(os.path.basename(f))
            print("   ", sig(f))


if __name__ == "__main__":
    main()
