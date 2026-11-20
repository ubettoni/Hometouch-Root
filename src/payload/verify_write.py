#!/usr/bin/env python3
"""verify_write.py - [STORICO] verifica la primitiva di scrittura #32 con un marker.

> **SUPERATO (13/11/2026).** Questo script costruisce **un solo** zip con symlink +
> entry `r/...`: con l'`unzip` del firmware (deferred symlinks) NON scrive il file,
> indipendentemente dal frame. Per la procedura corretta (due stadi) usare
> `apply_2stage.py`. Resta come diagnostica del comportamento a stadio singolo.

Costruisce uno zip con symlink `r -> /var/tmp/ftp` (la chroot FTP) + marker,
lo applica con `#48` + `#32` (**con** `#`, 13/11/2026) e controlla che il marker
compaia nella LIST della FTP.

Usa UNA SOLA sessione OWN per tutta l'operazione (come apply_payload_crc32.py):
la FTP resta aperta tra #31 e #32, quindi non serve riaprirla.
"""
from __future__ import print_function

import os
import sys
import time
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))

from conf_apply_test import Ftp, wait_port, port_open, posix_cksum
from own_session import OwnSession
import zipbuild

IP = "192.168.1.197"
PWD = "552977430"
DL = os.path.join(HERE, "work")
os.makedirs(DL, exist_ok=True)
MARKER = "VERIFY_WRITE_OK.txt"


def crc32(d):
    return zlib.crc32(d) & 0xFFFFFFFF


def ftp_list():
    f = Ftp()
    try:
        return f.listdir()
    finally:
        try:
            f.quit()
        except Exception:
            pass


def main():
    s = OwnSession(IP, PWD, timeout=30)
    s.handshake()
    print("handshake OK", flush=True)

    print("#48 ->", s.cmd("*#13**48*0##", timeout=30), flush=True)
    print("#30 ->", s.cmd("*#13**#30*0##", timeout=30), flush=True)
    if not wait_port(21, 25):
        raise SystemExit("FTP non aperta")
    print("#31 ->", s.cmd("*#13**#31*0##", timeout=60), flush=True)
    time.sleep(4)
    cur = os.path.join(DL, "verify_conf.zip")
    f = Ftp()
    try:
        n = f.retr("conf.zip", cur)
        print("RETR conf.zip:", n, flush=True)
    finally:
        f.quit()
    conf = zipfile.ZipFile(cur).read("conf.xml", pwd=b"bticino")
    print("conf.xml:", len(conf), "byte", flush=True)

    blob = zipbuild.build_zip([
        {"name": "conf.xml", "data": conf},
        {"name": "r", "data": b"/var/tmp/ftp", "mode": 0o120777, "store": True},
        {"name": "r/" + MARKER, "data": b"write-through-symlink OK\n", "mode": 0o100644},
    ])
    p = os.path.join(DL, "verify_write.zip")
    open(p, "wb").write(blob)
    print("zip verify: %d byte crc32=%d" % (len(blob), crc32(blob)), flush=True)

    # FTP e' ancora aperta (stessa sessione): carico e applico
    f = Ftp()
    try:
        try:
            f.dele("conf.zip")
        except Exception:
            pass
        print("STOR:", f.stor("conf.zip", p), flush=True)
        print("LIST pre:", repr(f.listdir()), flush=True)
    finally:
        f.quit()

    r = s.cmd("*#13**#32*%d*0*%d##" % (len(blob), posix_cksum(blob)), timeout=180)
    print("#32 ->", r, flush=True)
    time.sleep(4)
    print("#42 ->", s.cmd("*#13**42##", timeout=60), flush=True)
    time.sleep(5)

    listing = ftp_list()
    print("LIST post:", repr(listing), flush=True)
    time.sleep(2)
    print("#33 ->", s.cmd("*#13**#33*0##", timeout=20), flush=True)
    s.close()

    if MARKER in str(listing):
        print("*** VERIFICA OK: il marker %s e' stato scritto dalla primitiva #32." % MARKER, flush=True)
        return 0
    print("!!! marker NON trovato: la scrittura non e' confermata (ACK non affidabile).", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
