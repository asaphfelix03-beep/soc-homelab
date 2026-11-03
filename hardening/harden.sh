#!/usr/bin/env bash
# Durcissement du poste endpoint-ubuntu selon le benchmark CIS Ubuntu 24.04 v1.0.0.
# Chaque bloc indique le contrôle CIS visé. À exécuter en root DANS le poste :
#   docker exec -i soc-homelab-endpoint-ubuntu-1 bash < hardening/harden.sh
#
# Hors périmètre dans un conteneur (à faire sur une vraie VM) : partitions séparées
# (1.1.2.x), AppArmor (1.3), sysctl réseau (3.3.x), pare-feu ufw/nftables (4.x),
# auditd (6.2.x), AIDE (6.3).
set -euo pipefail

echo "== SSH (CIS 5.1.x)"
chmod 600 /etc/ssh/sshd_config                                   # 5.1.1
cat > /etc/ssh/sshd_config.d/50-cis.conf <<'EOF'
# Durcissement CIS 5.1.x
AllowGroups sudo
Banner /etc/issue.net
ClientAliveInterval 300
ClientAliveCountMax 3
DisableForwarding yes
LoginGraceTime 60
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
MaxAuthTries 4
MaxStartups 10:30:60
MaxSessions 10
PermitRootLogin no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
LogLevel VERBOSE
EOF
chmod 600 /etc/ssh/sshd_config.d/50-cis.conf
# Le fichier principal ne doit pas réactiver ce que l'on désactive
sed -i 's/^PermitRootLogin .*/#&/; s/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
# CIS 5.1.20 vérifie aussi le fichier principal
grep -q '^PermitRootLogin no' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
/usr/sbin/sshd -t && echo "   sshd_config valide"
[ -f /run/sshd.pid ] && kill -HUP "$(cat /run/sshd.pid)" || true

echo "== Bannières de connexion (CIS 1.6.2, 1.6.3)"
MSG="Accès réservé aux utilisateurs autorisés. Toute activité est journalisée."
echo "$MSG" > /etc/issue
echo "$MSG" > /etc/issue.net
chmod 644 /etc/issue /etc/issue.net

echo "== Cron & at (CIS 2.4.1.2 - 2.4.2.1)"
chown root:root /etc/crontab && chmod 600 /etc/crontab
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  mkdir -p "$d"; chown root:root "$d"; chmod 700 "$d"
done
rm -f /etc/cron.deny /etc/at.deny
echo root > /etc/cron.allow && chown root:root /etc/cron.allow && chmod 640 /etc/cron.allow
# 2.4.2.1 exige aussi que le paquet "at" soit installé : sans lui, le contrôle reste en échec
echo root > /etc/at.allow && chown root:root /etc/at.allow && chmod 640 /etc/at.allow

echo "== Core dumps (CIS 1.5.3)"
echo '* hard core 0' > /etc/security/limits.d/60-cis-coredump.conf
echo 'fs.suid_dumpable = 0' > /etc/sysctl.d/60-cis-coredump.conf
sysctl -w fs.suid_dumpable=0 2>/dev/null || echo "   (sysctl non modifiable dans un conteneur : à appliquer sur l'hôte/VM)"
mkdir -p /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/60-cis.conf

echo "== sudo (CIS 5.2.3)"
echo 'Defaults logfile=/var/log/sudo.log' > /etc/sudoers.d/60-cis-logfile
chmod 440 /etc/sudoers.d/60-cis-logfile
visudo -c >/dev/null && echo "   sudoers valide"

echo "== Restreindre su (CIS 5.2.7)"
getent group sugroup >/dev/null || groupadd sugroup
grep -q 'pam_wheel.so use_uid group=sugroup' /etc/pam.d/su || \
  sed -i '1a auth required pam_wheel.so use_uid group=sugroup' /etc/pam.d/su

echo "== PAM : pas de mot de passe vide (CIS 5.3.3.4.1)"
sed -i '/pam_unix.so/ s/ nullok//' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null || true

echo "== Politique des mots de passe (CIS 5.4.1.1, 5.4.1.2, 5.4.1.5)"
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
useradd -D -f 45
for u in $(awk -F: '$2 ~ /^\$/ {print $1}' /etc/shadow); do
  chage --maxdays 365 --mindays 1 --warndays 7 --inactive 45 "$u"
done

echo "== umask root & délai d'inactivité du shell (CIS 5.4.2.6, 5.4.3.2)"
for f in /root/.bashrc /root/.bash_profile; do
  touch "$f"; grep -q '^umask 0027' "$f" || echo 'umask 0027' >> "$f"
done
cat > /etc/profile.d/60-cis-timeout.sh <<'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF

echo "== Journaux (CIS 6.1.3.4, 6.1.4.1, 7.1.10)"
for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
  [ -f "$f" ] || continue
  grep -q '^\$FileCreateMode 0640' "$f" || sed -i '1i $FileCreateMode 0640' "$f"
done
find /var/log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
for f in /etc/security/opasswd /etc/security/opasswd.old; do
  touch "$f" && chown root:root "$f" && chmod 600 "$f"
done
pkill -HUP rsyslogd || true

echo "Durcissement terminé."
