#!/usr/bin/env bash
# Aplica el cortafuegos final con red de seguridad · Akram El Mazzoudi Zarrouk
# Si en 120 s no se confirma (sudo rm /root/fw-pendiente), se restaura el anterior.
# El temporizador va desligado de la sesión (setsid + sin heredar la salida) para
# que la conexión SSH termine y se pueda comprobar el acceso con otra nueva.
set -euo pipefail
D=/home/akram/lab/proyecto04
iptables-save  > /root/fw-anterior.v4
ip6tables-save > /root/fw-anterior.v6
iptables-restore --test  < $D/akram-firewall.rules
ip6tables-restore --test < $D/akram-firewall6.rules
touch /root/fw-pendiente
setsid bash -c 'sleep 120; if [ -f /root/fw-pendiente ]; then iptables-restore < /root/fw-anterior.v4; ip6tables-restore < /root/fw-anterior.v6; logger -t akram-firewall "sin confirmar: restaurado el cortafuegos anterior"; fi' > /dev/null 2>&1 < /dev/null &
iptables-restore  < $D/akram-firewall.rules
ip6tables-restore < $D/akram-firewall6.rules
logger -t akram-firewall "aplicado akram-firewall.rules (pendiente de confirmar)"
# Redis vuelve a escuchar solo en localhost y con modo protegido
sed -i 's/^bind .*/bind 127.0.0.1 ::1/; s/^protected-mode .*/protected-mode yes/' /etc/redis/redis.conf
systemctl restart redis-server
echo "Aplicado. Comprueba el acceso con otra conexión y confirma con: sudo rm /root/fw-pendiente"
