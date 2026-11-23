#!/usr/bin/env bash
# instalar-siem.sh - instala AKRAM-SIEM en SRV01
# Autor: Akram El Mazzoudi Zarrouk
set -e
AQUI="$(cd "$(dirname "$0")" && pwd)"
install -d /opt/akram-siem /var/lib/akram-siem /etc/akram-siem
install -m 0755 "$AQUI/akram-siem.py" /opt/akram-siem/akram-siem.py
install -m 0644 "$AQUI/panel.html"    /opt/akram-siem/panel.html
[ -s /etc/akram-siem/token ] || head -c 24 /dev/urandom | base64 | tr -d '/+=' > /etc/akram-siem/token
chmod 600 /etc/akram-siem/token
install -m 0644 "$AQUI/akram-siem.service" /etc/systemd/system/akram-siem.service
# El auditor de Docker deja su informe donde el SIEM lo recoge (cada hora)
cat > /etc/cron.d/akram-dockaudit <<CRON
0 * * * * root /usr/bin/python3 /home/akram/lab/proyecto09/akram-dockaudit.py --json /var/lib/akram-siem/dockaudit.json >/dev/null 2>&1
CRON
# Cortafuegos: syslog e ingesta desde el laboratorio, panel desde la red de administracion
for r in "-s 10.66.0.0/24 -p udp --dport 514" "-s 10.66.0.0/24 -p tcp --dport 8443" "-s 10.0.2.0/24 -p tcp --dport 8443"; do
  iptables -C INPUT $r -j ACCEPT 2>/dev/null || iptables -I INPUT $r -j ACCEPT
done
iptables-save > /etc/iptables/rules.v4
systemctl daemon-reload
systemctl enable --now akram-siem
echo "AKRAM-SIEM instalado. Token de ingesta: /etc/akram-siem/token"
