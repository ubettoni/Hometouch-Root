#!/usr/bin/env python3
"""apply_2stage.py - invia al device i due zip generati da build_payload.py.

Sequenza (guida §19.5):

    #48 (plain)  -> inizializza la directory FTP
    #33          -> chiude eventuale FTP
    #30          -> apre FTP (porta 21)
    STOR stage1.zip -> conf.zip
    *#13**#32*<size1>*0*<cksum_1>##       APPLY (CON `#`; cksum POSIX, tools/cksum.py)
    STOR stage2.zip -> conf.zip
    *#13**#32*<size2>*0*<cksum_2>##       APPLY
    LIST         -> deve contenere PAYLOAD_OK.txt (oracolo)
    #33          -> chiude FTP

Non riavvia il device: stampa il comando da eseguire dopo la conferma.

Fatto importante (misurato il 13/11/2026)
----------------------------------------
L'apply `#32` esegue anche `run_parse_xml` e applica il `conf.xml` contenuto nello zip:
il demone ESU (`bt_device`) si riavvia e **chiude la sessione OWN e la connessione FTP**.
Quindi, dopo ogni `#32`, lo script:

1. considera chiusa la sessione (nessuna eccezione fatale);
2. si riconnette all'ESU (nuovo handshake) e riapre l'FTP (`#30`) se serve;
3. prosegue con lo stadio successivo.

Il frame di risposta **non** è un oracolo: l'apply riuscito può rispondere `*#*0##`.
L'unico oracolo è `PAYLOAD_OK.txt` nella chroot FTP.

Uso:
    python payload/apply_2stage.py                 # usa work/payload/manifest.json
    python payload/apply_2stage.py --dry-run       # mostra solo cosa farebbe
    python payload/apply_2stage.py --stage-wait 8  # attesa maggiore tra gli stadi
"""
from __future__ import print_function

import argparse
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

from conf_apply_test import Ftp, wait_port
from own_session import OwnSession
from cksum import device_cksum, frame_cmd

# IP del device target (es. 192.168.1.197). Sovrascrivibile da riga di comando: --ip <indirizzo>
IP = "192.168.1.1"
# Password OPEN del device (es. 552977430). Sovrascrivibile da riga di comando: --password <pwd>
PWD = "552977430"
MANIFEST = os.path.join(HERE, "work", "payload", "manifest.json")
MARKER = "PAYLOAD_OK.txt"


def drain(s, timeout=3.0):
    """Legge tutti i frame disponibili fino al timeout. Ritorna la lista."""
    frames = []
    try:
        s.sock.settimeout(timeout)
    except Exception:
        pass
    while True:
        try:
            frames.append(s.recv_frame(timeout=timeout))
        except Exception:
            break
    return frames


def upload(f, path, name="conf.zip"):
    try:
        f.dele(name)
    except Exception:
        pass
    rep = f.stor(name, path)
    print("   STOR %-10s %-40s %s" % (name, os.path.basename(path), rep), flush=True)
    return rep


def probe_banner(ip, port, timeout=2.5):
    """Legge l'eventuale banner SSH sulla 2222 (solo informativo)."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        try:
            return s.recv(128)
        except socket.timeout:
            return b""
    except OSError:
        return b""
    finally:
        s.close()


class Runner(object):
    """Tiene la sessione ESU e la connessione FTP, riconnettendosi quando cadono."""

    def __init__(self, args):
        self.args = args
        self.s = None
        self.f = None

    # --- ESU -------------------------------------------------------------
    def connect(self, attempts=30, delay=2.0):
        last = None
        for _ in range(attempts):
            try:
                s = OwnSession(self.args.ip, self.args.password, timeout=30)
                hs = s.handshake()
                drain(s, 0.5)
                print("   ESU connesso (%s)" % hs, flush=True)
                self.s = s
                return s
            except Exception as exc:          # handshake rifiutato o socket chiuso
                last = exc
                time.sleep(delay)
        raise SystemExit("ERRORE: ESU non raggiungibile (%s)" % last)

    def send(self, frame, timeout=6.0):
        """Invia un frame. Ritorna i frame letti, oppure None se la sessione cade."""
        if self.s is None:
            self.connect()
        print("   %-42s" % frame, end="", flush=True)
        try:
            self.s.send(frame)
        except Exception as exc:
            print(" -> sessione chiusa (%s)" % type(exc).__name__, flush=True)
            self.s = None
            return None
        frames = drain(self.s, timeout=timeout)
        print(" -> %r" % frames, flush=True)
        return frames

    def drop(self):
        """Dimentica la sessione corrente (il demone ESU si e' riavviato)."""
        if self.s is not None:
            try:
                self.s.close()
            except Exception:
                pass
        self.s = None

    # --- FTP -------------------------------------------------------------
    def close_ftp(self):
        if self.f is not None:
            try:
                self.f.quit()
            except Exception:
                pass
            self.f = None

    def ftp(self, open_if_needed=True):
        """Ritorna una connessione FTP nuova.

        `open_if_needed=True` manda `#30` se la 21 e' chiusa — ma `#30` **azzera** la
        chroot FTP: usarlo solo PRIMA di caricare uno zip, mai prima di leggere il marker.
        Con `open_if_needed=False` ritorna None se la 21 e' chiusa.
        """
        if not wait_port(21, 3):
            if not open_if_needed:
                return None
            for _ in range(3):
                if self.s is None:
                    self.connect()
                self.send("*#13**#30*0##")
                if wait_port(21, 30):
                    break
                print("   FTP non ancora aperta, nuovo #30 ...", flush=True)
                time.sleep(3)
        if not wait_port(21, 3):
            if not open_if_needed:
                return None
            raise SystemExit("ERRORE: FTP non si e' aperta sulla 21")
        self.close_ftp()                      # la vecchia control connection e' morta
        self.f = Ftp(self.args.ip)
        print("   FTP aperta", flush=True)
        return self.f

    def listdir(self):
        try:
            return self.f.listdir()
        except Exception:
            print("   LIST fallita: nuova connessione FTP", flush=True)
            self.ftp()
            return self.f.listdir()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Invia il payload a due stadi (stage1 + stage2).")
    ap.add_argument("--ip", default=IP)
    ap.add_argument("--password", default=PWD)
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--stage-wait", type=float, default=6.0,
                    help="attesa dopo ogni apply (secondi)")
    ap.add_argument("--max-retry", type=int, default=3,
                    help="tentativi completi (stage1+stage2): il primo #32 puo' applicare la "
                         "config e chiudere la sessione PRIMA dell'unzip (default 3)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.manifest):
        raise SystemExit("ERRORE: manifest mancante: %s\nEsegui prima python payload/build_payload.py"
                         % args.manifest)
    m = json.load(open(args.manifest, encoding="utf-8"))
    s1, s2 = m["stage1"], m["stage2"]
    blobs = {}
    for st in (s1, s2):
        if not os.path.exists(st["file"]):
            raise SystemExit("ERRORE: zip mancante: %s" % st["file"])
        blobs[st["file"]] = open(st["file"], "rb").read()

    print("manifest : %s" % args.manifest)
    print("fw       : %s   link: %s   mark: %s" % (m["fw"], m["link"], m.get("mark")))
    print("modalita': %s" % m.get("mode", "netcat"))
    if m.get("ssh"):
        for k in (m["ssh"].get("keys") or [m["ssh"]]):
            print("chiave   : %s %s" % (k.get("type", "?"), k.get("fingerprint", "?")))
    for tag, st in (("stage1", s1), ("stage2", s2)):
        blob = blobs[st["file"]]
        print("%-8s : %d byte cksum=%d" % (tag, len(blob), device_cksum(blob)))
    if args.dry_run:
        print("\n--dry-run: nessun contatto col device.")
        print("  frame s1: %s" % frame_cmd(s1["size"], device_cksum(blobs[s1["file"]])))
        print("  frame s2: %s" % frame_cmd(s2["size"], device_cksum(blobs[s2["file"]])))
        return 0

    r = Runner(args)
    ok = False
    listing = ""
    used = 0
    try:
        print("\n--- preparazione ---", flush=True)
        r.connect()
        r.send("*#13**48*0##")
        r.send("*#13**#33*0##", timeout=4.0)
        time.sleep(2)

        # Il primo #32 puo' applicare il conf.xml e far morire bt_device PRIMA (o durante)
        # l'unzip: la scrittura resta parziale. Quindi ogni tentativo rifa' ENTRAMBI gli
        # stadi (i symlink sono idempotenti) e verifica il marker SENZA mandare #30.
        for attempt in range(1, args.max_retry + 1):
            print("\n=== tentativo %d/%d ===" % (attempt, args.max_retry), flush=True)

            print("--- stage 1: symlink ---", flush=True)
            f = r.ftp()                       # #30 e' lecito: stiamo per caricare
            upload(f, s1["file"])
            time.sleep(1)
            r.send(frame_cmd(s1["size"], device_cksum(blobs[s1["file"]])), timeout=60)
            time.sleep(args.stage_wait)
            if r.s is None or not wait_port(21, 5):
                print("   il device ha chiuso la sessione: riconnessione ...", flush=True)
                r.drop()
                r.connect()

            print("--- stage 2: file ---", flush=True)
            f = r.ftp()
            upload(f, s2["file"])
            time.sleep(1)
            r.send(frame_cmd(s2["size"], device_cksum(blobs[s2["file"]])), timeout=60)
            time.sleep(args.stage_wait)
            if r.s is None or not wait_port(21, 5):
                print("   sessione chiusa (apply della config): riconnessione ...", flush=True)
                r.drop()
                r.connect()
            used = attempt

            # verifica SENZA #30 (azzererebbe la chroot e cancellerebbe il marker)
            listing = ""
            if wait_port(21, 3):
                try:
                    r.close_ftp()
                    r.f = Ftp(args.ip)
                    listing = r.f.listdir()
                except Exception as exc:
                    print("   LIST fallita (%s)" % type(exc).__name__, flush=True)
            print("   LIST: %r" % listing, flush=True)
            if MARKER in listing:
                ok = True
                break
            if attempt < args.max_retry:
                print("   marker assente: nuovo tentativo completo", flush=True)
                time.sleep(8)

        if not listing:
            print("   (FTP chiusa: il marker non e' leggibile senza #30, che azzera la\n"
                  "    chroot. Verifica definitiva dopo il riavvio, con la password.)", flush=True)
    finally:
        r.close_ftp()
        try:
            r.send("*#13**#33*0##", timeout=4.0)
        except Exception as exc:
            print("   #33 non inviato (%s)" % type(exc).__name__, flush=True)
        r.drop()

    print()
    pwd_auth = bool((m.get("ssh") or {}).get("password_auth"))
    if ok:
        print("RISULTATO: PAYLOAD SCRITTO (marker %s presente, tentativo %d)." % (MARKER, used))
    else:
        print("RISULTATO: marker %s non visibile (tentativi: %d)." % (MARKER, used))
        print("  L'apply puo' essere comunque riuscito: l'oracolo forte e' l'accesso dopo il boot.")
    if m.get("mode", "netcat") == "dropbear":
        b = probe_banner(args.ip, 2222)
        if b.startswith(b"SSH-"):
            print("2222 risponde: %s" % b.decode("latin-1").strip())
    print("Prossimo passo, con conferma: python reboot_hometouch.py")
    if pwd_auth:
        pw = (m["ssh"].get("password") or "…")
        print("Poi:                          python payload/check_root.py --password \"%s\" --port 22"
              % pw)
        print("                              python payload/check_root.py --password \"%s\"" % pw)
    else:
        print("Poi:                          python payload/check_root.py --ssh-key %s"
              % os.path.expanduser("~/.ssh/id_hometouch"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
