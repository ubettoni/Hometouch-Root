# HomeTouch BT-3488 - Root via ESU Apply

> **Attenzione**: Questo repository è stato creato per scopi di ricerca e sicurezza.
> **Non sono incluse password, hash o credenziali reali**. Tutti i segreti devono essere
> forniti al momento dell'esecuzione tramite argomenti o variabili d'ambiente.

## Sommario rapido

Questo progetto fornisce gli strumenti e la procedura per ottenere `root` su un
HomeTouch BT-3488 sfruttando la primitiva di scrittura dell'handler ESU `conf.zip`
mediante il frame `#32`.

## Flusso di lavoro

1. **Scaricare conf.xml** dal device con `puma_ng.exe`
2. **Costruire lo zip payload** con `build_payload.py --password <ROOT_PASSWORD> --no-key`
3. **Applicare** con `apply_2stage.py --max-retry 3`
4. **Riavviare** con `reboot_hometouch.py`
5. **Verificare** l'accesso root via SSH (`uid=0`)

## Strumenti inclusi

| Strumento | Descrizione |
|---|---|
| `build_payload.py` | Costruzione payload zip. Opzioni: `--password`, `--no-key`, `--ssh-key` |
| `apply_2stage.py` | Apply a due stadi con retry automatico ericonnessione |
| `check_root.py` | Verifica `uid=0(root)` via SSH/paramiko |
| `sha256crypt.py` | Hash `$5$` in Python (validato vs `openssl`) |
| `set_password.py` | Rotazione password via `cfg/extra/.pwn_hash` |
| `crack_shadow.py` | Attacco/verifica offline hash `$5$` |
| `pwn.sh` | Payload v8: dropbear su 2222, diagnostica, log |

## Documentazione

- `docs/procedure/GETTING_STARTED.md` - Guida rapida (3 passaggi)
- `docs/procedure/PROCEDURE.md` - Procedura dettagliata (8 sezioni)

## Sicurezza & Privacy

- **Mai** hardcodare password o hash reali nei file commitati
- Passare i segreti come argomenti da riga di comando
- L'override password vive in `tmpfs` e non è persistente su riavvio forte
- Chiave SSH deve essere **senza passphrase**; altrimenti usare `--no-key`
- L'hash `$5$` va scritto con **apici singoli** (`printf '%s\n' '$5$...'`) per evitare espansione shell

## Licenza

Questo progetto è rilasciato a scopo di ricerca e difesa delle infrastrutture
critiche. Non utilizzare per scopi illeciti su dispositivi non autorizzati.
