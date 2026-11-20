#!/usr/bin/env python3
"""check_root.py - verifica il payload root sulla porta 2222.

Rileva automaticamente il tipo di listener:

- **dropbear key-only** (payload v4): il server invia subito il banner
  `SSH-2.0-dropbear_...`; lo script esegue `ssh -p 2222 -i <chiave>` e verifica
  `uid=0(root)`.
- **netcat** (payload v3 / `--netcat`): nessun banner; lo script invia i comandi
  sulla shell raw.

Da usare DOPO il riavvio (reboot_hometouch.py). Non modifica nulla sul device.

    python payload/check_root.py
    python payload/check_root.py --ssh-key %USERPROFILE%\\.ssh\\id_hometouch
    python payload/check_root.py --ip 192.168.1.197 --port 2222
"""
from __future__ import print_function

import argparse
import os
import socket
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass

# IP del device target: sostituire con l'indirizzo reale della propria HomeTouch (es. 192.168.1.x)
# Può essere passato da riga di comando: --ip <indirizzo>
DEFAULT_IP = "<INDIRIZZO_IP_DEVICE>"
# Porta SSH del payload (solitamente 2222 dopo il boot; 22 è la riserva del dropbear di sistema)
DEFAULT_PORT = 2222
# Chiave privata per dropbear key-only (payload v4/v6)
DEFAULT_KEY = os.path.expanduser("~/.ssh/id_hometouch")


def key_is_encrypted(path):
    """True se la chiave privata richiede una passphrase (ssh-keygen -P '' fallisce)."""
    try:
        p = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", path],
                           capture_output=True, text=True, timeout=15)
        return p.returncode != 0 and "passphrase" in (p.stderr or "").lower()
    except Exception:
        return False

# comandi eseguiti sulla shell remota (netcat) o via ssh
REMOTE_CMD = (
    "id; "
    "uname -a; "
    "cat /home/bticino/cfg/extra/.license_ver 2>/dev/null; "
    "ls -l /home/bticino/cfg/extra/usbkey_dir/lib/ 2>/dev/null; "
    "awk '$2==\"/home/root\"{print}' /proc/mounts 2>/dev/null; "
    "tail -5 /var/tmp/ftp/ROOTED.txt 2>/dev/null"
)


def port_open(ip, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    finally:
        s.close()


def recv_banner(ip, port, timeout=2.5):
    """Legge l'eventuale banner iniziale. Ritorna b'' se il listener tace."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        try:
            return s.recv(256)
        except socket.timeout:
            return b""
    except OSError:
        return b""
    finally:
        s.close()


def run_netcat(ip, port, cmd, timeout=10):
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    data = b""
    try:
        s.sendall((cmd + "\n").encode())
        time.sleep(1.0)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
    finally:
        try:
            s.close()
        except Exception:
            pass
    return data.decode("latin-1", "replace")


def run_paramiko(ip, port, password, cmd, timeout=25):
    """Esegue `cmd` con autenticazione a password (paramiko, nessun binario esterno)."""
    try:
        import paramiko
    except ImportError:
        return 127, ("ERRORE: paramiko non installato.\n"
                     "  python -m pip install paramiko\n"
                     "  oppure: ssh -p %d root@%s" % (port, ip))
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(hostname=ip, port=port, username="root", password=password,
                    allow_agent=False, look_for_keys=False, timeout=timeout,
                    auth_timeout=timeout, banner_timeout=timeout)
        _, out, err = cli.exec_command(cmd, timeout=timeout)
        data = (out.read() + err.read()).decode("utf-8", "replace")
        return 0, data
    except Exception as exc:
        return 1, "ERRORE: %s: %s" % (type(exc).__name__, exc)
    finally:
        try:
            cli.close()
        except Exception:
            pass


def run_ssh(ip, port, key, cmd, timeout=20):
    known = "NUL" if os.name == "nt" else "/dev/null"
    argv = [
        "ssh", "-p", str(port), "-i", key,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=" + known,
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "root@" + ip, cmd,
    ]
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
    except FileNotFoundError:
        return 127, "ERRORE: client OpenSSH non trovato nel PATH"
    except subprocess.TimeoutExpired:
        return 124, "ERRORE: ssh in timeout"
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verifica root su 2222 (dropbear o netcat).")
    ap.add_argument("--ip", default=DEFAULT_IP)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--ssh-key", default=DEFAULT_KEY,
                    help="chiave privata per il payload dropbear (default %s)" % DEFAULT_KEY)
    ap.add_argument("--password", default=None,
                    help="usa il login con PASSWORD (payload v6, via paramiko)")
    args = ap.parse_args(argv)

    if not port_open(args.ip, args.port):
        print("porta %d CHIUSA su %s" % (args.port, args.ip), file=sys.stderr)
        print("  -> il payload non è attivo: verificare .license_ver e usbkey_dir (guida §19.7)")
        return 2

    banner = recv_banner(args.ip, args.port)
    if banner.startswith(b"SSH-"):
        print("porta %d APERTA: %s" % (args.port, banner.decode("latin-1").strip()))
        if args.password:
            print("modalità: dropbear con password (payload v6)", flush=True)
            print("\n$ " + REMOTE_CMD, flush=True)
            rc, out = run_paramiko(args.ip, args.port, args.password, REMOTE_CMD)
            print(("  " + out.strip().replace("\n", "\n  ")) if out.strip() else "  (nessun output)")
            if "uid=0(root)" in out:
                print("\n*** ROOT CONFERMATO (uid=0(root), autenticazione a password).", flush=True)
                return 0
            print("\n!!! login non riuscito o uid=0(root) non rilevato (rc=%d)." % rc,
                  file=sys.stderr)
            return 1
        if not os.path.exists(args.ssh_key):
            print("ERRORE: chiave privata non trovata: %s" % args.ssh_key, file=sys.stderr)
            return 2
        print("modalità: dropbear key-only (payload v5/v6)", flush=True)
        if key_is_encrypted(args.ssh_key):
            print("\n!!! la chiave privata è protetta da passphrase: ssh non può usarla in\n"
                  "    modalità non interattiva. Opzioni:\n"
                  "      1) ssh-add \"%s\"   (inserire la passphrase) e riprovare;\n"
                  "      2) ssh -p %d -i \"%s\" root@%s   (inserire la passphrase al prompt);\n"
                  "      3) usare una chiave senza passphrase e rigenerare il payload\n"
                  "         (build_payload.py --ssh-key ...)." %
                  (args.ssh_key, args.port, args.ssh_key, args.ip), file=sys.stderr)
            return 3
        print("\n$ " + REMOTE_CMD, flush=True)
        rc, out = run_ssh(args.ip, args.port, args.ssh_key, REMOTE_CMD)
        print(("  " + out.strip().replace("\n", "\n  ")) if out.strip() else "  (nessun output)")
        if "uid=0(root)" in out:
            print("\n*** ROOT CONFERMATO (uid=0(root), autenticazione a chiave).", flush=True)
            return 0
        print("\n!!! ssh connesso ma uid=0(root) non rilevato (rc=%d)." % rc, file=sys.stderr)
        return 1

    print("porta %d APERTA, nessun banner SSH: shell netcat (payload v3/--netcat)" % args.port,
          flush=True)
    ok_root = False
    for cmd in ("id", "uname -a",
                "cat /home/bticino/cfg/extra/.license_ver",
                "cat /var/tmp/ftp/ROOTED.txt",
                "ls -la /home/bticino/cfg/extra/usbkey_dir/lib/",
                "mount | grep -E ' / '"):
        print("\n$ %s" % cmd, flush=True)
        try:
            out = run_netcat(args.ip, args.port, cmd)
        except Exception as exc:
            print("  ERRORE: %s: %s" % (type(exc).__name__, exc), flush=True)
            continue
        out = out.strip()
        print(("  " + out.replace("\n", "\n  ")) if out else "  (nessun output)", flush=True)
        if cmd == "id" and "uid=0(root)" in out:
            ok_root = True

    if ok_root:
        print("\n*** ROOT CONFERMATO (uid=0(root)).", flush=True)
        print("Nota: questa è una shell netcat senza autenticazione.", flush=True)
        return 0
    print("\n!!! connessione riuscita ma uid=0(root) non rilevato.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
