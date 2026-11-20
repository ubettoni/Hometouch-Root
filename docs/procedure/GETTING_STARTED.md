# HomeTouch BT-3488 - Root via ESU Apply

## Quick Summary

This repository contains the tools and procedure to obtain `root` access on a HomeTouch BT-3488 device
through the ESU (Equipment Service Unit) `conf.zip` apply handler using frame `#32`.

**Important**: No passwords, hashes, or device-specific secrets are hardcoded. All secrets must be
provided at runtime.

## Prerequisites

- A HomeTouch BT-3488 device (use `<DEVICE_IP>` as a placeholder for its address)
- The `puma_ng.exe` tool to download the real `conf.xml` from the device
- Python 3 with `zipfile` support
- Network access to the device on ports 22 and 2222

## Step-by-Step Procedure

### Step 1: Download the real configuration

```bash
# Use puma_ng.exe to download the device configuration
# Replace <DEVICE_IP> and <OPEN_PASSWORD> with your device values
puma_ng.exe cd conf.xml -e <DEVICE_IP> <OPEN_PASSWORD>
```

The expected output confirms a successful handshake: `@@@ ok 200 4 3.2.5 @@@`

### Step 2: Generate the payload

```bash
# Build the payload zip with password-only access (recommended)
# Replace <ROOT_PASSWORD> with your chosen password
python build_payload.py --password <ROOT_PASSWORD> --no-key
```

Options:
- `--password <senha>`: enables password login on dropbear (port 2222)
- `--no-key`: disables SSH key authentication (use if key has unknown passphrase)
- `--ssh-key <key>`: includes a SSH public key (must be without passphrase)
- `--out-dir <dir>`: specifies output directory

The script produces:
- `stage1.zip`: contains symlink setup and marker for deferred creation
- `stage2.zip`: contains the actual payload files (pwn.sh, libs, conf.xml, license)

### Step 3: Apply the payload (two-stage with retry)

```bash
# Apply the payload; the script retries automatically until the marker appears
python apply_2stage.py --max-retry 3
```

Key points:
- The first `#32` apply may cause `bt_device` to die mid-unzip (partial write)
- `apply_2stage.py` handles retries, reconnection, and marker verification
- `--max-retry 3` is the recommended number (2-3 attempts typical)

### Step 4: Reboot and verify access

```bash
# Reboot the device
python reboot_hometouch.py
```

After reboot, wait ~10-15 seconds for port 2222 to become reachable, then:

```bash
# Verify root access
python check_root.py --password <ROOT_PASSWORD>

# SSH access (port 2222 or 22, same password)
ssh -p 2222 root@<DEVICE_IP>
# or
ssh -p 22 root@<DEVICE_IP>
```

Verify: `uid=0(root)` should appear in the output.

## Password Rotation (without regenerating the payload)

To change the root password without rebuilding the whole payload:

```bash
# Write new hash to cfg/extra/.pwn_hash on the device
# Replace the placeholders with your device values
python set_password.py --password <NEW_ROOT_PASSWORD> --ssh <DEVICE_IP> --old-password "<CURRENT_ROOT_PASSWORD>" --reboot
```

This writes the `$5$` hash to `/home/bticino/cfg/extra/.pwn_hash`, which `pwn.sh`
prefers over the compiled hash. The `--clear` flag removes the override to restore the
original compiled hash.

## SSH Key (optional, requires no passphrase)

If you want SSH key access instead of (or in addition to) password:

1. Generate a key without passphrase: `ssh-keygen -t ed25519 -f $HOME/.ssh/id_hometouch`
2. Include it in the payload: `python build_payload.py --password <ROOT_PASSWORD> --ssh-key ~/.ssh/id_hometouch.pub`
3. Ensure `chown 0:0` on the `.ssh` directory and `authorized_keys` (done automatically by `pwn.sh`)

> **Nota**: La chiave SSH dei primi test aveva una passphrase sconosciuta e non era utilizzabile.
> Per renderla utilizzabile serve una chiave senza passphrase + `chown 0:0`.

## Risultato atteso

- `uid=0(root)` su porte 22 e 2222
- `.license_ver` = `3.2.5`
- Accesso via SSH con la password specificata
- Eventuale accesso chiave SSH (se generata senza passphrase)

## Struttura dei file in questo repo

```
src/payload/
  build_payload.py      -- costruzione payload
  apply_2stage.py       -- apply a due stadi
  check_root.py         -- verifica accesso root
  sha256crypt.py        -- hash $5$ in Python
  set_password.py       -- rotazione password
  crack_shadow.py       -- attacco offline hash
  pwn.sh                -- payload v8
  apply_payload_crc32.py--
  verify_write.py       -- verifica scrittura

docs/procedure/
  GETTING_STARTED.md    -- questo documento

.gitignore
README.md
```

## Sicurezza & Privacy

- **Mai** pubblicare password o hash reali su repo pubblici
- Passare i segreti come argomenti di riga di comando o variabili d'ambiente
- L'override `.pwn_hash` vive in `tmpfs` e svanisce dopo un riavvio forte senza il payload
- Le chiave SSH devono essere **senza passphrase**; altrimenti usare la via password-only
