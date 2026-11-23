#!/usr/bin/env bash
# limpiar-marcadores.sh · Elimina los marcadores inertes del proyecto 06 · Akram El Mazzoudi Zarrouk
set -u
rm -rf /opt/AKRAM-LAB-TEST
rm -f /etc/cron.d/akram-test /etc/profile.d/akram-test.sh /etc/modprobe.d/akram-test.conf \
      /etc/update-motd.d/99-akram-test /etc/udev/rules.d/99-akram-test.rules /etc/ld.so.preload /etc/rc.local
systemctl disable akram-test-persist.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/akram-test-persist.service
systemctl daemon-reload
sed -i '/AKRAM-LAB-TEST-clave-inerte/d' /root/.ssh/authorized_keys 2>/dev/null || true
echo "Marcadores inertes eliminados."
