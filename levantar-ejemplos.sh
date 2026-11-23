#!/usr/bin/env bash
# levantar-ejemplos.sh - crea dos contenedores de ejemplo para la auditoria:
#   uno mal configurado (inerte, solo duerme) y otro endurecido.
# Autor: Akram El Mazzoudi Zarrouk
set -e
docker rm -f akram-inseguro akram-seguro 2>/dev/null || true

# Contenedor INSEGURO: reune los errores tipicos. No hace nada (sleep),
# solo existe para que el auditor tenga algo que marcar.
docker run -d --name akram-inseguro \
  --privileged --network host --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/anfitrion-etc:ro \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  alpine:3.19 sleep infinity

# Contenedor ENDURECIDO: las buenas practicas aplicadas.
docker run -d --name akram-seguro \
  --read-only --tmpfs /tmp --user 1000:1000 \
  --memory 128m --cpus 0.5 --pids-limit 100 \
  --cap-drop ALL --security-opt no-new-privileges=true \
  --health-cmd "true" --health-interval 30s --restart on-failure \
  alpine:3.19 sleep infinity

echo "Listos. Audita con: sudo ./akram-dockaudit.py"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
