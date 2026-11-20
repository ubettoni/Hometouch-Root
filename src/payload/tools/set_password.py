#!/usr/bin/env python3
"""set_password.py - cambia la password di root del payload v8 senza rigenerare gli zip.

Come funziona
-------------
`pwn.sh` legge, se esiste, `/home/bticino/cfg/extra/.pwn_hash` e usa quell'hash al posto di
quello compilato nel payload. Quindi per cambiare la password basta scrivere quel file e
riavviare (o aspettare il prossimo boot: pwn.sh ricrea comunque l'override di /etc/shadow).

Uso
---
    # 1) solo generazione: stampa l'hash e il comando da eseguire sulla shell root
    python payload/tools/set_password.py --password "NuovaPassword"

    # 2) scrittura diretta via SSH (serve la password attuale per collegersi)
    #    Sostituire <IP> e <PASSWORD_ATTUALE> con i valori del proprio device
    python payload/tools/set_password.py --password "NuovaPassword" \
        --ssh <IP> --old-password "<PASSWORD_ATTUALE>" --reboot

    # 3) torna all'hash compilato nel payload (rimuove l'override)
    python payload/tools/set_password.py --clear --ssh <IP> --old-password "<PASSWORD_ATTUALE>"

Richiede `paramiko` solo per `--ssh` (`python -m pip install paramiko`).
"""
from __future__ import print_function

import argparse
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from sha256crypt import sha256_crypt  # noqa: E402

SALT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
TARGET = "/home/bticino/cfg/extra/.pwn_hash"


def new_hash(password, salt=None):
    salt = salt or "".join(secrets.choice(SALT_CHARS) for _ in range(16))
    return sha256_crypt(password, salt, 5000)


def run_ssh(ip, old_password, commands, port=2222, timeout=25):
    try:
        import paramiko
    except ImportError:
        raise SystemExit("ERRORE: serve paramiko per --ssh (python -m pip install paramiko)")
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(ip, port=port, username="root", password=old_password,
                allow_agent=False, look_for_keys=False, timeout=timeout)
    try:
        for cmd in commands:
            _, out, err = cli.exec_command(cmd, timeout=timeout)
            data = (out.read() + err.read()).decode("utf-8", "replace").strip()
            print("  $ %s\n    %s" % (cmd, data if data else "(ok)"))
    finally:
        cli.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cambia la password di root del payload (v8).")
    ap.add_argument("--password", help="nuova password (in chiaro: resta solo qui sul PC)")
    ap.add_argument("--clear", action="store_true",
                    help="rimuove .pwn_hash: torna all'hash compilato nel payload")
    ap.add_argument("--ssh", help="IP del device: scrive il file via SSH")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--old-password", help="password attuale (serve per --ssh)")
    ap.add_argument("--reboot", action="store_true", help="inoltra *#13**43## alla fine")
    args = ap.parse_args(argv)

    if not args.clear and not args.password:
        ap.error("serve --password (oppure --clear)")

    if args.clear:
        print("Rimuovo l'override: la password torna quella compilata nel payload.")
        cmds = ["rm -f " + TARGET, "ls -l " + TARGET + " 2>&1"]
        if args.ssh:
            if not args.old_password:
                ap.error("--clear --ssh richiede --old-password")
            run_ssh(args.ssh, args.old_password, cmds, port=args.ssh_port)
        else:
            print("\nEsegui come root:")
            for c in cmds:
                print("  " + c)
        return 0

    h = new_hash(args.password)
    print("nuova password : %s" % args.password)
    print("hash $5$       : %s" % h)
    print("file           : %s" % TARGET)

    if args.ssh:
        if not args.old_password:
            ap.error("--ssh richiede --old-password (la password attuale)")
        # il file viene scritto con printf '%s\\n' e gli apici singoli: nessuna
        # espansione dei `$` da parte della shell.
        cmds = [
            "printf '%%s\\n' '%s' > %s" % (h, TARGET),
            "chmod 600 " + TARGET,
            "chown 0:0 " + TARGET,
            "cat " + TARGET,
        ]
        print("\ncomando che verrà eseguito:\n  " + cmds[0])
        print("\nscrivo sul device via SSH ...")
        run_ssh(args.ssh, args.old_password, cmds, port=args.ssh_port)
        print("\nFatto. La nuova password sarà attiva quando pwn.sh ricrea l'override\n"
              "di /etc/shadow, cioè al prossimo boot:")
        if args.reboot:
            print("\nriavvio ...")
            run_ssh(args.ssh, args.old_password, ["(sleep 1; reboot) >/dev/null 2>&1 &"],
                    port=args.ssh_port)
            print("reboot inviato: attendere ~1 minuto e usare la NUOVA password.")
        else:
            print("  python reboot_hometouch.py")
        return 0

    print("\nEsegui come root sul device (una riga):")
    print("  printf '%%s\\n' '%s' > %s && chmod 600 %s && chown 0:0 %s" %
          (h, TARGET, TARGET, TARGET))
    print("poi riavvia: python reboot_hometouch.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
