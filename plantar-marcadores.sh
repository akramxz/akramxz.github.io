#!/usr/bin/env bash
# =============================================================================
#  plantar-marcadores.sh · Marcadores de persistencia INERTES para probar el detector
#  Autor: Akram El Mazzoudi Zarrouk · Proyecto 06 · Persistence Scanner
#
#  IMPORTANTE: ninguno de estos marcadores hace nada dañino. No hay shells
#  inversas, ni puertas traseras, ni descargas, ni acceso remoto. Cada uno es
#  solo una señal que un atacante dejaría en ese mismo sitio, pero aquí su
#  "carga" se limita a escribir una línea en el log del sistema (logger) o a
#  dormir. Sirven para comprobar que el detector mira en los sitios correctos.
#  Todos llevan la etiqueta AKRAM-LAB-TEST para poder limpiarlos después.
# =============================================================================
set -euo pipefail
MARCA="AKRAM-LAB-TEST"
log() { logger -t akram-persist-test "marcador inerte: $1"; }

# 1) cron (T1053.003): tarea que solo escribe en el log, no ejecuta nada externo
cat > /etc/cron.d/akram-test <<EOF
# ${MARCA}: marcador inerte, solo registra una línea
*/10 * * * * root /usr/bin/logger -t ${MARCA} "cron inerte en marcha"
EOF

# 2) servicio systemd (T1543.002): una unidad que únicamente duerme
cat > /etc/systemd/system/akram-test-persist.service <<EOF
[Unit]
Description=${MARCA} servicio inerte de prueba
[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/bin/logger -t ${MARCA} "servicio inerte"; /bin/sleep 1'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable akram-test-persist.service >/dev/null 2>&1

# 3) perfil de shell (T1546.004): referencia INERTE a /tmp para activar el motor de
#    patrones. Es solo una variable de entorno; no ejecuta ni descarga nada.
cat > /etc/profile.d/akram-test.sh <<EOF
# ${MARCA}: referencia inerte a /tmp para activar el motor de patrones
export AKRAM_TEST_DIR=/tmp/akram-test-dir  # solo una variable, no ejecuta nada
EOF

# 4) clave SSH de prueba (T1098.004): clave generada para la ocasión y etiquetada
mkdir -p /root/.ssh && chmod 700 /root/.ssh
GEN=$(ssh-keygen -q -t ed25519 -N '' -C "${MARCA}-clave-inerte" -f /tmp/akram_test_key <<<y 2>/dev/null; cat /tmp/akram_test_key.pub)
echo "$GEN" >> /root/.ssh/authorized_keys
rm -f /tmp/akram_test_key /tmp/akram_test_key.pub

# 5) ld.so.preload (T1574.006): apunta a una biblioteca que no existe/vacía.
#    No se precarga nada real; es solo la señal en el fichero, que es lo que busca el detector.
echo "/opt/${MARCA}/inerte.so" > /etc/ld.so.preload

# 6) modprobe install hook (T1547.006): un módulo inventado cuyo hook solo registra
echo "install akram_test_mod /usr/bin/logger -t ${MARCA} modulo-inerte" > /etc/modprobe.d/akram-test.conf

# 7) rc.local / init (T1037.004): rc.local que solo escribe en el log
cat > /etc/rc.local <<EOF
#!/bin/sh
# ${MARCA}: rc.local inerte
/usr/bin/logger -t ${MARCA} "rc.local inerte"
exit 0
EOF
chmod +x /etc/rc.local

# 8) update-motd.d (T1546): script de login que solo registra
cat > /etc/update-motd.d/99-akram-test <<EOF
#!/bin/sh
# ${MARCA}: motd inerte
/usr/bin/logger -t ${MARCA} "motd inerte"
EOF
chmod +x /etc/update-motd.d/99-akram-test

# 9) regla udev (T1546): RUN+= que solo registra (no se dispara solo)
echo "ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"/usr/bin/logger -t ${MARCA} udev-inerte\"  # ${MARCA}" > /etc/udev/rules.d/99-akram-test.rules

echo "Plantados 9 marcadores inertes etiquetados ${MARCA}."
