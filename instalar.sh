#!/usr/bin/env bash
# instalar.sh - instala el DNS Sinkhole akram-dnshield como servicio
# Autor: Akram El Mazzoudi Zarrouk
set -e
AQUI="$(cd "$(dirname "$0")" && pwd)"
echo "[*] Copiando el servidor a /usr/local/sbin ..."
sudo install -m 0755 "$AQUI/akram-dnshield.py" /usr/local/sbin/akram-dnshield.py
echo "[*] Creando el directorio de datos y cargando la lista negra ..."
sudo mkdir -p /var/lib/akram-dnshield
sudo /usr/local/sbin/akram-dnshield.py --cargar "$AQUI/akram-bloqueo.txt"
echo "[*] Instalando el servicio systemd ..."
sudo install -m 0644 "$AQUI/akram-dnshield.service" /etc/systemd/system/akram-dnshield.service
sudo systemctl daemon-reload
sudo systemctl enable --now akram-dnshield.service
echo "[*] Abriendo el puerto 53 en el cortafuegos para la red del laboratorio ..."
sudo iptables -C INPUT -i enp0s8 -s 10.66.0.0/24 -p udp --dport 53 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -i enp0s8 -s 10.66.0.0/24 -p udp --dport 53 -j ACCEPT
sudo iptables -C INPUT -i enp0s8 -s 10.66.0.0/24 -p tcp --dport 53 -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -i enp0s8 -s 10.66.0.0/24 -p tcp --dport 53 -j ACCEPT
echo "[+] Listo. Estado:"
sudo systemctl --no-pager status akram-dnshield.service | head -5
