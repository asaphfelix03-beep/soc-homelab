#!/bin/bash
# Démarre les services du poste puis l'agent Wazuh.
set -e
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER:-wazuh.manager}</address>|" /var/ossec/etc/ossec.conf
sed -i "s|<agent_name>.*</agent_name>|<agent_name>${WAZUH_AGENT_NAME:-endpoint-ubuntu}</agent_name>|" /var/ossec/etc/ossec.conf

# rsyslog : écrit /var/log/auth.log et /var/log/syslog (sans module noyau dans un conteneur)
sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
rm -f /run/rsyslogd.pid
rsyslogd
cron
mkdir -p /run/sshd && /usr/sbin/sshd

# Attend que le manager accepte les enrôlements
for i in $(seq 1 60); do
  (echo > /dev/tcp/${WAZUH_MANAGER:-wazuh.manager}/1515) 2>/dev/null && break
  sleep 5
done

/var/ossec/bin/wazuh-control start
logger -t soc-homelab "endpoint démarré, agent Wazuh lancé"
exec tail -F /var/ossec/logs/ossec.log
