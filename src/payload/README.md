# Payload root per HomeTouch BT-3488 (`BT-3488`, `<DEVICE_IP>`)

Artefatti per ottenere `root` da remoto sfruttando la primitiva di scrittura
dell'handler ESU di **apply** `#32`. La documentazione completa è in
`../guida_ssh_conf.xml.md`, sezioni **16.2–16.3**, **19.1**–**19.10**.

## Procedura definitiva (verificata il 13/11/2026)

> Il device `<DEVICE_IP>` ha oggi una build v8 **precedente** all'aggiunta di `.pwn_hash`:
> ha root funzionante, ma per la rotazione della password serve riapplicare questi artefatti.

```powershell
# 1. conf reale del device (serve come contenuto dello zip: l'apply applica ANCHE il conf.xml)
puma_ng.exe cd conf.xml -e <DEVICE_IP> <OPEN_PASSWORD>
python payload\build_payload.py --password "<ROOT_PASSWORD>"

# 2. apply (due stadi, con retry automatico; NON riavvia)
python payload\apply_2stage.py --max-retry 3        # attendersi 2 tentativi

# 3. riavvio e verifica (la 2222 compare ~10-15 s dopo il ritorno della 22)
python reboot_hometouch.py
python payload\check_root.py --password "<ROOT_PASSWORD>"
ssh -p 2222 root@<DEVICE_IP>        # oppure -p 22 (stessa password)
```

Esito: `uid=0(root)`, kernel `5.15.157-lts-next+…`, `.license_ver` = `3.2.5`.

| Accesso | Comando | Note |
|---|---|---|
| **password** (ufficiale) | `ssh -p 2222 root@<DEVICE_IP>` | nessuna chiave, nessuna passphrase |
| **password su 22** (riserva) | `ssh -p 22 root@<DEVICE_IP>` | il dropbear di sistema usa lo stesso `/etc/shadow` |
| chiave | `ssh -p 2222 -i <chiave> root@…` | serve una chiave **senza passphrase** e `chown 0:0` (§ sotto) |

> **La chiave installata non è utilizzabile** se la sua privata ha una passphrase che non si
> conosce. Per non dipendere da essa il payload definitivo si genera con `--no-key`
> (solo password). Per (ri)abilitare la chiave: generarla **senza passphrase**, accodicare la
> pubblica a `/home/bticino/cfg/extra/home/root/.ssh/authorized_keys` dalla shell root e
> `chown 0:0` file e directory.

### Cambiare la password (senza rigenerare il payload)

`pwn.sh` usa, se presente, l'hash in `/home/bticino/cfg/extra/.pwn_hash`:

```powershell
python payload\tools\set_password.py --password "<NEW_ROOT_PASSWORD>" `
    --ssh <DEVICE_IP> --old-password "<CURRENT_ROOT_PASSWORD>" --reboot
python payload\tools\set_password.py --clear --ssh <DEVICE_IP> --old-password "<CURRENT_ROOT_PASSWORD>"  # torna al compilato
```

## Punto chiave: servono DUE zip (deferred symlinks)

L'`unzip` del firmware è **Info-ZIP 6.00 con la patch Debian dei "deferred symlinks"**:
i symlink vengono creati **alla fine** dell'estrazione. Quindi un unico zip con
symlink `q` + entry `q/...` fallisce:

```
checkdir error:  /var/tmp/q exists but is not directory
                 unable to process q/...
exit code 2
```

Il symlink viene creato, ma **nessun file del payload viene scritto**: da qui la
necessità dei due archivi.

> **Correzione (13/11/2026).** Perché `#32` arrivi all'`unzip` serve il frame
> **con** `#` (`*#13**#32*<size>*0*<cksum>##`) e il **`cksum` POSIX** — non lo
> `zlib.crc32`. La forma **senza** `#` (`*#13**32*...##`) è una *query* e non scrive.
> Vedi guida **§16.2–§16.3**.

> **Conferma sul device (13/11/2026).** `*#13**#32*308*0*2442640499##` con un marker di 308 B
> ha scritto `PLAIN_OK.txt` owner `0` in `/var/tmp/ftp` in 0,05 s (guida §16.10). Il frame di
> risposta era **`*#*0##`**: ACK/NACK **non** è un oracolo. Attenzione: `#32` esegue anche
> `run_parse_xml`, quindi il `conf.xml` dello zip sostituisce la config **runtime** — il marker
> deve contenere il **conf.xml reale** (non uno minimo), altrimenti si perde `<pwd_open>` fino
> al riavvio. `apply_2stage.py` usa il `conf.xml` reale incluso da `build_payload.py`.

La soluzione:

| Archivio | Contenuto | Effetto |
|---|---|---|
| `stage1.zip` | `conf.xml` + **solo** symlink `q -> /home/bticino/cfg/extra` (e `m -> /var/tmp/ftp`) | crea i link |
| `stage2.zip` | `conf.xml` + file `q/.license_ver`, `q/pwn.sh`, `q/usbkey_dir/lib/*.so`, `q/usbkey_dir/common-licenses/.keep` (e `m/PAYLOAD_OK.txt`) | scrive **attraverso** i link |

Verificato offline con il binario ARM del firmware in qemu
(`payload/tools/selftest_symlink.py`): archivio unico → `exit=2`, file non
scritti; stage-1 + stage-2 → `exit=0`, file nel target con hash corretti.

## Generare il payload (nessun contatto col device)

```powershell
python payload\build_payload.py --password "<ROOT_PASSWORD>"
```

legge `payload/work/conf_now.zip` (la conf scaricata dal device) e produce in
`payload/work/payload/`:

- `stage1.zip` — symlink;
- `stage2.zip` — payload (`pwn.sh` con l'hash `$5$` della password sostituito);
- `manifest.json` — `size`, `cksum` POSIX (`#32`), `crc32`, `sha256`, elenco entry.

`--password` abilita il login con password (vedi sotto); senza, `pwn.sh` resta in modalità
sola-chiave.

Opzioni:

```powershell
python payload\build_payload.py --fw 3.2.5
python payload\build_payload.py --conf-xml mio_conf.xml --dest /home/bticino/cfg/extra
python payload\build_payload.py --no-marker
python payload\build_payload.py --password "<ROOT_PASSWORD>"       # login con password
python payload\build_payload.py --ssh-key a.pub --ssh-key b.pub  # piu' chiavi (ed25519+RSA)
```

Il builder **valida** struttura zip, CRC, modalità UNIX, ordine dei symlink e
contenuto di `.license_ver` prima di dichiarare l'esito.

## Autenticazione: password (verificata) o chiave

Il dropbear del firmware **non usa PAM**: legge `/etc/passwd` + `/etc/shadow` (`getspnam`);
la libc è `libxcrypt` (`$5$` e `$6$` supportati).

- **password** — `--password "…"`: il builder genera l'hash `$5$` (`tools/sha256crypt.py`,
  validato contro `openssl passwd -5` e contro l'hash reale di `cfguser`) e lo sostituisce al
  posto di `@@PWNHASH@@`; a runtime `pwn.sh` patcha la riga di `root` di `/etc/shadow`,
  la monta con `mount --bind` sopra l'originale e avvia dropbear **senza** `-s`.
  **Verificato il 13/11/2026**: `uid=0(root)` su `2222` e su `22`.
- **chiave** — `stage2` scrive `home/root/.ssh/authorized_keys`; `pwn.sh` monta
  `cfg/extra/home/root` sopra `/home/root` e fa `chown 0:0`.

> **Due bug trovati e corretti il 13/11/2026** (entrambi impedivano l'accesso):
> 1. `PWNHASH` era fra **doppi apici**: la shell espandeva i `$` del hash (`$5`, `$c4P2…`) e in
>    `/etc/shadow` finiva solo la coda della stringa. Serve l'**apice singolo** (`'$5$…'`).
> 2. i file estratti da `#32` appartengono a **`bticino` (uid 1000)**, non a root (l'`unzip`
>    gira dopo il drop dei privilegi di `bt_device`): dropbear pretende `authorized_keys`
>    di root o dell'utente, quindi la chiave era **sempre** rifiutata. Serve `chown 0:0`.

```powershell
# verifica dopo il boot (usa paramiko: pip install paramiko)
python payload\check_root.py --password "<ROOT_PASSWORD>"
python payload\check_root.py --password "<ROOT_PASSWORD>" --port 22
# oppure a mano
ssh -p 2222 root@<DEVICE_IP>
```

> L'override di `/etc/shadow` è **globale**: la stessa password vale anche per il dropbear
> di sistema sulla **22** (canale di riserva). Sparisce al reboot (tmpfs); `pwn.sh` lo ricrea
> a ogni boot. La `2222` è raggiungibile ~10-15 s dopo il ritorno della `22`.

## Inviare il payload (richiede il device)

```powershell
python payload\apply_2stage.py            # stage1 -> #32 -> stage2 -> #32 -> LIST
```

Lo script esegue `#48` → `#30` → `STOR stage1.zip` → `#32` (**con** `#`) →
`STOR stage2.zip` → `#32` (**con** `#`) → `LIST` e verifica `PAYLOAD_OK.txt`.
**Non** riavvia il device: stampa il comando da lanciare dopo la conferma.
Procedura manuale in guida §19.5.

> **Eseguito con esito positivo il 13/11/2026**: `PAYLOAD_OK.txt` (owner `0`) scritto
> attraverso il symlink di verifica; dopo il reboot la `2222` si apre e
> `ssh -p 2222 root@<DEVICE_IP>` dà **`uid=0(root)`** (password), anche sulla `22`.
>
> **Servono più tentativi**: il **primo** `#32` dello stage 2 applica il `conf.xml` e fa
> morire `bt_device` prima/durante l'`unzip` (scrittura parziale → `.license_ver` vuoto →
> `check_version` cancella `usbkey_dir`). `--max-retry` (default 3) ripete l'intero ciclo;
> negli ultimi test sono serviti **2 tentativi**. Verificare sempre il marker.
>
> **Il `#32` riavvia `bt_device`**: la sessione OWN e la connessione FTP **cadono** dopo ogni
> apply; `apply_2stage.py` si riconnette da solo. La verifica del marker avviene **senza**
> mandare `#30`, che azzera la chroot FTP. I symlink dello stage 1 sopravvivono al riavvio del
> demone (vivono in tmpfs); li cancella solo un *reboot*.
>
> La chiave privata usata da `check_root.py --ssh-key` **non deve avere passphrase**; con
> `--password` non serve alcuna chiave.

## Contenuto

| File | Ruolo |
|---|---|
| `build_payload.py` | **genera stage1/stage2 + manifest** (offline) |
| `apply_2stage.py` | invia i due zip, verifica il marker, non riavvia |
| `tools/cksum.py` | **checksum dell'handler di apply `#32`** (`cksum` POSIX, non `zlib.crc32`): `device_cksum`, `frame_cmd` |
| `tools/selftest_symlink.py` | zip minimi per riprodurre il comportamento di `unzip` |
| `check_root.py` | (post-reboot) verifica `uid=0(root)` sulla porta `2222` |
| `pwn.sh` | payload v5: **dropbear con sola chiave** su `2222` (`-s`), con log diagnostico su `/var/tmp/ftp/ROOTED.txt` |
| `pwn_netcat.sh` | payload v3 legacy: shell **netcat** root su `2222` (usato con `build_payload.py --netcat`) |
| `lib/libpwn.so` | costruttore ELF ARM: `fork → setsid → sh pwn.sh` |
| `lib/libutils.so.1` | `libutils` patchata: `DT_NEEDED libpwn.so` |
| `tools/zipbuild.py` | builder zip (ZipCrypto `bticino`, symlink, mode UNIX) |
| `tools/zipcrypto.py` | ZipCrypto usato da `zipbuild`/`conf_apply_test` |
| `tools/own_session.py` | client OWN Python 3 (handshake HMAC-SHA256) |
| `tools/conf_apply_test.py` | helper FTP attivo (`Ftp`, `wait_port`, `port_open`) |
| `apply_payload_crc32.py` | **DEPRECATO**: zip unico, non scrive il payload (§19.1) |
| `verify_write.py`, `probe_*.py`, `drain32.py` | diagnostica **storica** dei frame (`#32` senza `#` = query); utili solo come riferimento |
| `work/` | conf scaricate e zip generati |

## Catena di esecuzione (boot)

`S96-firewall` → `S98-bt_daemon-apps` → `check_version` (`.license_ver` deve
valere **esattamente** il firmware, `3.2.5`, altrimenti `rm -rf usbkey_dir`) →
`setup_usbkey` (`/dev/loop2` vfat) → `bt_daemon` con `LD_LIBRARY_PATH` →
carica la nostra `libutils.so.1` → `DT_NEEDED` carica `libpwn.so` → costruttore
root → `pwn.sh` → `mount --bind /home/root` + regola `iptables` +
**dropbear key-only sulla `2222`**.

## Cosa fa (e cosa non fa) il payload

- Avvia un **dropbear con sola chiave** su `2222` (`dropbear -p 2222 -r <hostkey> -s`):
  autenticazione **solo pubblica** (`authorized_keys` in `cfg/extra/home/root/.ssh/`),
  nessuna password. Se `authorized_keys` manca **non apre nulla**.
- Genera la **host key** RSA 2048 al primo boot in `cfg/extra/ssh/dropbear_host_key`
  e la riusa; fa `mount --bind cfg/extra/home/root /home/root` (la home di `root` in
  `/etc/passwd` è `/home/root`, non `/root`).
- Si riarma a ogni boot tramite `libpwn.so` (costruttore di `libutils.so.1`); è
  idempotente (lock sullo stato del socket + mutex `mkdir /var/tmp/pwn.start`).
- Con `build_payload.py --netcat` si genera invece il payload **v3** (`pwn_netcat.sh`):
  shell **netcat** root su `2222`, in chiaro e **senza autenticazione** (sconsigliato).

## Connettersi

```powershell
ssh -p 2222 -i $HOME\.ssh\id_hometouch root@<DEVICE_IP>
```

```sh
# Linux/macOS
ssh -p 2222 -i ~/.ssh/id_hometouch root@<DEVICE_IP>
```

La chiave privata deve corrispondere alla pubblica finita in `authorized_keys`
(default `~/.ssh/id_hometouch.pub`, `build_payload.py --ssh-key`).

> **Sicurezza.** Con `--netcat` la `2222` è una shell **in chiaro senza password**:
> chiunque la raggiunga è root. Il payload dropbear (default) è preferibile.

## Hash degli artefatti

| File | SHA-256 |
|---|---|
| `lib/libpwn.so` | `9B1C276B6641C46182C3BA7C51743FC51DA009627EE81383282CDDE8542CD9FA` |
| `lib/libutils.so.1` | `9BAC5C3140F68CB2F5C7E82C83376A83F4E7DFABAE94F514A0C1787125EDDC3D` |
| `pwn.sh` (v5, dropbear) | `682FFECB721C74F44C33C099488F1888F034F9F6CFD04FD1892FFFFF9860B977` |
| `pwn_netcat.sh` (v3, legacy) | `D755E444A1E0A4D1A52EC24221044C33032A330832BD1ADAEB124819BEC780A5` |

Il **checksum del frame `#32`** è il `cksum` POSIX del file, calcolato da
`tools/cksum.py` (vedi guida §16.2); `build_payload.py` lo scrive nel
`manifest.json` nel campo `cksum` di `stage1`/`stage2`.

## Riferimenti

- Forma del frame e algoritmo del checksum: guida §16.2
- Perché servono due zip: guida §19.1 (e §16.8)
- Stato accertato sul device (12/11/2026): guida §16.9
- Vincolo `.license_ver = 3.2.5`: guida §19.2
- Catena di payload: guida §19.3
- Procedura completa: guida §19.5
- Persistenza e quando si perde: guida §19.7
- Riavvio controllato: guida §19.10

> **Sicurezza.** Il payload dropbear non apre nulla senza la chiave corrispondente.
> Con `--netcat` invece la `2222` è una shell in chiaro: usare solo su apparecchi propri,
> chiudere la porta quando non serve e non esporre il device su reti non fidate.
