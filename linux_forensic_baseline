#!/usr/bin/env bash
# Linux/Ubuntu forensic baseline collector (best-effort, mostly read-only)
# Usage: sudo bash linux_forensic_baseline.sh "2026-11-01 00:00:00" "2026-11-03 23:59:59" /mnt/evidence
set -u
umask 077
START="${1:-}"; END="${2:-}"; OUTDIR="${3:-/mnt/evidence}"
if [[ $EUID -ne 0 ]]; then echo "Run with sudo/root."; exit 1; fi
if [[ -z "$START" || -z "$END" ]] || ! date -d "$START" >/dev/null 2>&1 || ! date -d "$END" >/dev/null 2>&1; then
  echo "Usage: sudo bash $0 \"YYYY-MM-DD HH:MM:SS\" \"YYYY-MM-DD HH:MM:SS\" [OUTPUT_DIR]"; exit 1
fi
mkdir -p "$OUTDIR" || exit 1
HOST=$(hostname -s 2>/dev/null || echo unknown); STAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$OUTDIR/${HOST}_baseline_${STAMP}.txt"
CHANGED="$OUTDIR/${HOST}_changed_files_${STAMP}.txt"
HASHES="$OUTDIR/${HOST}_changed_sha256_${STAMP}.txt"
exec > >(tee -a "$REPORT") 2>&1
section(){ echo; echo "================================================================================"; echo "[$1]"; echo "================================================================================"; }
cmd(){ echo; echo "\$ $*"; "$@" 2>&1 || echo "[Command unavailable or returned non-zero]"; }

echo "LINUX FORENSIC BASELINE"; echo "Host: $HOST"; echo "Operator: ${SUDO_USER:-root}"
echo "Collected: $(date '+%F %T %Z (%z)')"; echo "Incident window: $START -> $END"
echo "Report: $REPORT"; echo "NOTE: Prefer OUTPUT_DIR on an external evidence drive."

section "1. SYSTEM IDENTITY AND TIME"
cmd hostnamectl; cmd uname -a; cmd cat /etc/os-release
cmd date; cmd date -u; cmd timedatectl; cmd uptime; cmd who -a; cmd last -Faiwx

section "2. STORAGE AND MOUNTS"
cmd lsblk -f; cmd df -hT; cmd findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS

section "3. USERS AND AUTHENTICATION"
cmd getent passwd; cmd getent group; cmd lastlog; cmd last -Fai
for f in /var/log/auth.log /var/log/secure; do
  if [[ -r "$f" ]]; then echo "--- $f ---"; grep -Ei 'accepted|failed|invalid user|sudo|session opened|session closed|authentication failure' "$f" | tail -n 500; fi
done
for d in /root/.ssh /home/*/.ssh; do [[ -e "$d" ]] && ls -lad "$d" "$d"/* 2>/dev/null; done

section "4. PROCESSES, SERVICES AND NETWORK CONNECTIONS"
cmd ps auxwwf; cmd ps -eo pid,ppid,user,lstart,etime,cmd --sort=lstart
cmd systemctl --no-pager --type=service --state=running
cmd systemctl --no-pager list-unit-files; cmd systemctl list-timers --all --no-pager
cmd ss -plantue; cmd pstree -ap
if command -v lsof >/dev/null 2>&1; then cmd lsof -nP -i; fi

section "5. NETWORK CONFIGURATION"
cmd ip address show; cmd ip route show table all; cmd ip neigh show
cmd cat /etc/hosts; cmd cat /etc/resolv.conf; cmd cat /etc/hostname
cmd iptables-save; cmd nft list ruleset

section "6. PERSISTENCE AND SCHEDULED TASKS"
cmd crontab -l
cmd ls -lah /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron /var/spool/cron/crontabs
cmd systemctl list-unit-files --state=enabled --no-pager
cmd find /etc/systemd /usr/lib/systemd /lib/systemd /etc/init.d /etc/profile.d -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS | %m | %u:%g | %p\n'

section "7. FILES MODIFIED IN INCIDENT WINDOW"
echo "Window: $START -> $END"
echo "Find lists regular files currently present with mtime in the window. ctime is metadata-change time."
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path "$OUTDIR" \) -prune -o \
  -type f -newermt "$START" ! -newermt "$END" \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS | ctime=%CY-%Cm-%Cd %CH:%CM:%CS | size=%s | mode=%m | owner=%u:%g | %p\n' \
  2>/dev/null | sort > "$CHANGED"
cat "$CHANGED"
echo "Changed-file inventory saved: $CHANGED"

section "8. HIGH-RISK PATHS – RECENT FILE CHANGES"
for d in /tmp /var/tmp /dev/shm /var/www /etc /usr/local/bin /usr/local/sbin /opt /root /home; do
  if [[ -d "$d" ]]; then echo "--- $d ---"; find "$d" -type f -newermt "$START" ! -newermt "$END" \
    -printf '%TY-%Tm-%Td %TH:%TM:%TS | size=%s | mode=%m | owner=%u:%g | %p\n' 2>/dev/null | sort; fi
done

section "9. WEB SERVER AND APPLICATION LOGS"
for f in /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log /var/log/nginx/error.log \
         /var/log/httpd/access_log /var/log/httpd/error_log /var/log/auth.log /var/log/syslog /var/log/messages; do
  if [[ -r "$f" ]]; then echo "--- $f (last 1000 lines) ---"; tail -n 1000 "$f"; fi
done
echo "--- Related log file inventory ---"
find /var/log -maxdepth 4 -type f \( -iname '*apache*' -o -iname '*nginx*' -o -iname '*php*' -o -iname '*moodle*' \) \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS | size=%s | %p\n' 2>/dev/null | sort

section "10. SYSTEM JOURNAL IN INCIDENT WINDOW"
if command -v journalctl >/dev/null 2>&1; then journalctl --since "$START" --until "$END" --no-pager -o short-iso 2>&1; else echo "journalctl unavailable"; fi

section "11. PACKAGE AND SECURITY AGENT STATUS"
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' 2>/dev/null
elif command -v rpm >/dev/null 2>&1; then rpm -qa; fi
ps auxww | grep -Ei 'defender|mdatp|sentinel|crowdstrike|falcon|elastic|filebeat|auditd|osquery|wazuh|qualys|nessus' | grep -v grep || true

section "12. AUDITD STATUS AND EVENTS"
if command -v auditctl >/dev/null 2>&1; then auditctl -s 2>&1; auditctl -l 2>&1; else echo "auditctl unavailable"; fi
if command -v ausearch >/dev/null 2>&1; then ausearch -ts "$START" -te "$END" -i 2>&1 | tail -n 2000; else echo "ausearch unavailable"; fi

section "13. SHA256 OF CHANGED FILES"
: > "$HASHES"
while IFS= read -r line; do
  file="${line##* | }"
  if [[ -f "$file" && ! -L "$file" ]]; then sha256sum -- "$file" >> "$HASHES" 2>/dev/null || echo "HASH_FAILED $file" >> "$HASHES"; fi
done < "$CHANGED"
cat "$HASHES"

section "14. SUMMARY AND LIMITATIONS"
echo "Report: $REPORT"; echo "Changed files: $CHANGED"; echo "SHA256 list: $HASHES"
echo "Changed-file count: $(wc -l < "$CHANGED")"
echo "Output SHA256:"; sha256sum "$REPORT" "$CHANGED" "$HASHES" 2>/dev/null
echo "LIMITATIONS:"
echo "- find only identifies files that still exist and whose mtime falls in the selected window."
echo "- Deleted files require auditd/EDR, snapshots, backups, filesystem journal or forensic recovery."
echo "- mtime/ctime do not identify the user/process and timestamps can be manipulated."
echo "- Rotated/compressed logs and remote SIEM records require separate review."
echo "- This is not a forensic disk image; preserve volatile evidence and follow organizational chain-of-custody procedures."
echo "- Writing output to the suspect host changes it; use external evidence media where possible."
echo "Collection completed: $(date '+%F %T %Z (%z)')"
