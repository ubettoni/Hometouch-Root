#!/usr/bin/env python3
"""crack_shadow.py - verifica/attacca gli hash `$5$` di /etc/shadow (offline).

Usa `payload/tools/sha256crypt.py`. Serve per due cose:

1. **validare** l'implementazione contro un hash di cui si conosce la password
   (nel firmware `cfguser` ha la password `22K2mk7d` dell'FTP);
2. provare una lista di password candidate contro l'hash di `root`.

Uso:
    python payload/tools/crack_shadow.py --selftest
    python payload/tools/crack_shadow.py --shadow btweb_only.ext4/etc/shadow
    python payload/tools/crack_shadow.py --shadow ... --wordlist parole.txt
"""
from __future__ import print_function

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from sha256crypt import sha256_crypt, parse, verify  # noqa: E402

# password note/plausibili per questo progetto (liste candidate per attacco offline)
# Sono state rimosse password device-specifiche (es. OPEN password, MyHomeServer);
# usarle come riferimento per costruire una wordlist personalizzata.
# Le candidate sono password comuni per dispositivi home router/IoT; per un attacco
# mirato si consiglia di fornire una wordlist personalizzata via --wordlist.
CANDIDATES = [
    # generiche da installatore/uso comune
    "admin", "install", "installer", "installatore", "bt", "smartdes", "SMARTDES",
    "root", "toor", "password", "passwd", "1234", "123456", "12345678", "0000",
    # varianti comuni per dispositivi home router/IoT
    "12345", "bTicino", "hometouch", "HomeTouch", "hometouch3488", "BT-3488",
    "3488", "2090692",
]


def load_shadow(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                out.append((parts[0], parts[1]))
    return out


def selftest():
    """Vettori ufficiali + l'hash reale di cfguser (password 22K2mk7d)."""
    ok = True

    # 1) vettori ufficiali Drepper
    vectors = [
        ("Hello world!", "saltstring", None,
         "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        ("Hello world!", "saltstringsaltstring", 10000,
         "$5$rounds=10000$saltstringsaltstring$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"),
    ]
    for pw, salt, rounds, expect in vectors:
        got = sha256_crypt(pw, salt, rounds)
        mark = "OK  " if got == expect else "FAIL"
        if got != expect:
            ok = False
        print("%s vettore : %s" % (mark, got))
        if got != expect:
            print("        atteso: %s" % expect)

    # 2) hash reale di cfguser (password dell'FTP, nota)
    cfg = "$5$W/Jv/wldgh8KXWKw$h2ddXlz256F6ND.pYmRW6NlQWlYaD20575ELnwx03S5"
    print("verify('22K2mk7d', cfguser) =", verify("22K2mk7d", cfg))
    if not verify("22K2mk7d", cfg):
        ok = False
    print("verify('sbagliata', cfguser) =", verify("sbagliata", cfg))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verifica/attacca hash $5$ di /etc/shadow.")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--shadow", help="file shadow da analizzare")
    ap.add_argument("--wordlist", help="file con una password per riga (in aggiunta ai default)")
    ap.add_argument("--user", default="root", help="utente da attaccare (default root)")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.shadow:
        ap.error("serve --shadow (o --selftest)")

    entries = dict(load_shadow(args.shadow))
    if args.user not in entries:
        print("utente %r non presente nel file" % args.user)
        return 2
    target = entries[args.user]
    got = parse(target)
    if got is None:
        print("l'hash di %s non e' SHA-256 crypt: %r" % (args.user, target))
        return 2
    rounds, salt, digest = got
    print("utente   : %s" % args.user)
    print("salt     : %s" % salt)
    print("rounds   : %d" % rounds)

    words = list(CANDIDATES)
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
            words += [l.rstrip("\r\n") for l in f if l.strip()]
    print("candidate: %d" % len(words))

    t0 = time.time()
    for i, w in enumerate(words, 1):
        if verify(w, target):
            print("\n*** TROVATA: %r (dopo %.1fs)" % (w, time.time() - t0))
            return 0
        if i % 25 == 0:
            print("   ...%d provate (%.1fs)" % (i, time.time() - t0))
    print("\nnessuna candidata corrisponde (%.1fs)" % (time.time() - t0))
    return 1


if __name__ == "__main__":
    sys.exit(main())
