#!/usr/bin/env python3
"""sha256crypt.py - implementazione pura di SHA-256 crypt (`$5$`), senza `crypt`.

Perche' serve
-------------
Il dropbear del firmware **non usa PAM**: autentica leggendo `/etc/passwd` +
`/etc/shadow` (`getspnam`). L'hash di root e' SHA-256 crypt:

    root:$5$EsWMqf.GghQWYTA3$U60XulBENunyfbHyi.UfykJkS4IWsq5Im7iraNuQxw/:15069:...

Da qui due usi possibili, entrambi offline:

1. **verifica** di password candidate contro l'hash esistente (`verify`), senza
   toccare il device;
2. **generazione** di un hash noto per il payload in modalita' password: pwn.sh
   riscrive `/etc/shadow` in `/var/tmp` e lo monta sopra l'originale, poi avvia
   dropbear **senza** `-s`, cosi' si entra con una password invece che con la chiave.

Confronto con le vettori ufficiali (Ulrich Drepper, "Unix crypt using SHA-256 and
SHA-512"): esegui `python payload/tools/sha256crypt.py --selftest`.
"""
from __future__ import print_function

import hashlib
import hmac  # noqa: F401  (solo per chiarezza d'uso: SHA-256 via hashlib)

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
DEFAULT_ROUNDS = 5000
MAX_SALT = 16


def _b64_from_24bit(b2, b1, b0, n):
    """Codifica `(b2<<16)|(b1<<8)|b0` in base64 crypt, `n` caratteri."""
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(ITOA64[w & 0x3F])
        w >>= 6
    return "".join(out)


def _repeat(b, n):
    """Ripete ciclicamente `b` fino a `n` byte (come `repeat_string`)."""
    if n <= 0:
        return b""
    if len(b) >= n:
        return b[:n]
    out = bytearray()
    while len(out) < n:
        out += b
    return bytes(out[:n])


def sha256_crypt(password, salt, rounds=None):
    """Ritorna la stringa completa `$5$[rounds=N$]salt$hash`.

    `password` e `salt` possono essere str o bytes; `rounds` None = default (5000).
    """
    if isinstance(password, str):
        password = password.encode()
    if isinstance(salt, str):
        salt = salt.encode()
    if len(salt) > MAX_SALT:
        salt = salt[:MAX_SALT]
    if rounds is None:
        rounds = DEFAULT_ROUNDS
    rounds = max(1000, min(999999999, int(rounds)))

    # digest B = SHA256(password + salt + password)
    b = hashlib.sha256(password + salt + password).digest()

    # digest A = SHA256(password + salt + B*pwd_len + bit-loop)
    a = hashlib.sha256()
    a.update(password)
    a.update(salt)
    a.update(_repeat(b, len(password)))
    cnt = len(password)
    while cnt > 0:
        a.update(b if (cnt & 1) else password)
        cnt >>= 1
    alt = a.digest()          # = digest A

    # sequenza P = SHA256(password * pwd_len) ripetuto a len(password) byte
    p = _repeat(hashlib.sha256(password * len(password)).digest(), len(password))
    # sequenza S = SHA256(salt * (16 + A[0])) troncata a len(salt) byte
    s = hashlib.sha256(salt * (16 + bytearray(alt)[0])).digest()[:len(salt)]

    # ciclo principale: digest C
    for i in range(rounds):
        ctx = hashlib.sha256()
        ctx.update(p if (i & 1) else alt)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        ctx.update(alt if (i & 1) else p)
        alt = ctx.digest()

    # codifica finale
    out = ""
    out += _b64_from_24bit(alt[0], alt[10], alt[20], 4)
    out += _b64_from_24bit(alt[21], alt[1], alt[11], 4)
    out += _b64_from_24bit(alt[12], alt[22], alt[2], 4)
    out += _b64_from_24bit(alt[3], alt[13], alt[23], 4)
    out += _b64_from_24bit(alt[24], alt[4], alt[14], 4)
    out += _b64_from_24bit(alt[15], alt[25], alt[5], 4)
    out += _b64_from_24bit(alt[6], alt[16], alt[26], 4)
    out += _b64_from_24bit(alt[27], alt[7], alt[17], 4)
    out += _b64_from_24bit(alt[18], alt[28], alt[8], 4)
    out += _b64_from_24bit(alt[9], alt[19], alt[29], 4)
    out += _b64_from_24bit(0, alt[31], alt[30], 3)

    prefix = "$5$"
    if rounds != DEFAULT_ROUNDS:
        prefix += "rounds=%d$" % rounds
    return "%s%s$%s" % (prefix, salt.decode("ascii", "replace"), out)


def parse(hashstr):
    """(rounds, salt, hash) da una stringa `$5$...` (o None se non e' SHA-256 crypt)."""
    if not hashstr.startswith("$5$"):
        return None
    rest = hashstr[3:]
    rounds = DEFAULT_ROUNDS
    if rest.startswith("rounds="):
        n, _, rest = rest.partition("$")
        try:
            rounds = int(n[len("rounds="):])
        except ValueError:
            return None
    salt, _, digest = rest.partition("$")
    if not digest:
        return None
    return rounds, salt, digest


def verify(password, shadow_field):
    """True se `password` corrisponde al campo hash di /etc/shadow.

    Riconosce anche gli account bloccati (`!`, `*`, campo vuoto).
    """
    if not shadow_field or shadow_field in ("*", "!", "!!") or shadow_field[0] in "!*":
        return False
    got = parse(shadow_field)
    if got is None:
        return False
    rounds, salt, digest = got
    return sha256_crypt(password, salt, rounds).split("$")[-1] == digest


def _selftest():
    """Vettori verificati con `openssl passwd -5` (OpenSSL 3.5.5) e con
    l'hash reale di `cfguser` nel firmware (`22K2mk7d`)."""
    cases = [
        ("Hello world!", "saltstring", None,
         "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        ("22K2mk7d", "W/Jv/wldgh8KXWKw", 5000,
         "$5$W/Jv/wldgh8KXWKw$h2ddXlz256F6ND.pYmRW6NlQWlYaD20575ELnwx03S5"),
    ]
    ok = True
    for pw, salt, rounds, expect in cases:
        got = sha256_crypt(pw, salt, rounds)
        mark = "OK  " if got == expect else "FAIL"
        if got != expect:
            ok = False
        print("%s %s" % (mark, got))
        if got != expect:
            print("     atteso: %s" % expect)
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    if len(sys.argv) >= 3 and sys.argv[1] == "--hash":
        print(sha256_crypt(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "hometouch",
                           5000))
        sys.exit(0)
    print(__doc__)
