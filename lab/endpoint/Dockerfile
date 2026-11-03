# Poste Ubuntu 24.04 surveillé par l'agent Wazuh 4.14.9
FROM ubuntu:24.04

ARG WAZUH_VERSION=4.14.9-1
# APT_HTTPS=1 et le secret "extra_ca" sont optionnels : utiles seulement derrière
# un proxy d'entreprise qui n'autorise que le HTTPS. Laisse-les vides chez toi.
ARG APT_HTTPS=0
ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then \
      mkdir -p /usr/local/share/ca-certificates /etc/ssl/certs && \
      cp /run/secrets/extra_ca /usr/local/share/ca-certificates/extra.crt && \
      cp /run/secrets/extra_ca /etc/ssl/certs/ca-certificates.crt && \
      chmod 644 /etc/ssl/certs/ca-certificates.crt /usr/local/share/ca-certificates/extra.crt; fi && \
    if [ "$APT_HTTPS" = "1" ]; then \
      sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources; fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release \
        rsyslog cron sudo passwd procps iproute2 openssh-server && \
    update-ca-certificates && \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=wazuh.manager apt-get install -y wazuh-agent=${WAZUH_VERSION} && \
    rm -rf /var/lib/apt/lists/* /usr/local/share/ca-certificates/extra.crt && update-ca-certificates --fresh >/dev/null

# Un utilisateur "normal" pour simuler l'activité quotidienne
RUN useradd -m -s /bin/bash -G sudo analyste && echo 'analyste:Analyste2026!' | chpasswd && \
    install -d -m 700 -o analyste -g analyste /home/analyste/.ssh

COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown root:wazuh /var/ossec/etc/ossec.conf

ENTRYPOINT ["/entrypoint.sh"]
