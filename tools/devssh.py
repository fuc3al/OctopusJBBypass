#!/usr/bin/env python3
"""devssh.py — 极简 SSH/SFTP 驱动，用于连一台已越狱的测试 iPhone。

配置全部走环境变量，代码里不留任何主机/口令：

    IPHONE_HOST=192.0.2.10 IPHONE_USER=mobile IPHONE_PASS=*** \
        python tools/devssh.py --cmd "ls /var/jb"

用法:
    --cmd "..."            远程执行
    --sudo                 套 sudo（需要 IPHONE_PASS，且该用户在 sudoers）
    --put  本地=>远程       上传（Windows 路径里带盘符时请用 => 分隔）
    --get  远程=>本地
"""
import argparse
import os
import sys

import paramiko

HOST = os.environ.get("IPHONE_HOST", "")
USER = os.environ.get("IPHONE_USER", "mobile")
PASS = os.environ.get("IPHONE_PASS", "")
PORT = int(os.environ.get("IPHONE_SSH_PORT", "22"))


def connect():
    if not HOST or not PASS:
        sys.exit("set IPHONE_HOST and IPHONE_PASS first")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=10,
              allow_agent=False, look_for_keys=False)
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd")
    ap.add_argument("--sudo", action="store_true")
    ap.add_argument("--put", action="append", default=[], metavar="LOCAL=>REMOTE")
    ap.add_argument("--get", action="append", default=[], metavar="REMOTE=>LOCAL")
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()

    cl = connect()
    if a.put or a.get:
        sf = cl.open_sftp()
        for spec in a.put:
            local, remote = spec.split("=>", 1)
            sf.put(local, remote)
            print("put %s -> %s (%.0f KiB)" % (local, remote, os.path.getsize(local) / 1024))
        for spec in a.get:
            remote, local = spec.split("=>", 1)
            sf.get(remote, local)
            print("got %s -> %s" % (remote, local))
        sf.close()

    if a.cmd:
        cmd = a.cmd
        if a.sudo:
            cmd = "echo %s | sudo -S -p '' sh -c '%s'" % (PASS, cmd.replace("'", "'\\''"))
        i, o, e = cl.exec_command(cmd, timeout=a.timeout)
        out = o.read().decode("utf-8", "replace")
        err = e.read().decode("utf-8", "replace")
        sys.stdout.write(out)
        if err.strip():
            sys.stdout.write("\n[stderr] " + err[:2000] + "\n")
        rc = o.channel.recv_exit_status()
        if rc:
            print("[exit %d]" % rc)
    cl.close()


if __name__ == "__main__":
    main()
