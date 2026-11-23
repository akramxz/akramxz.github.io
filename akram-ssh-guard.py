#!/usr/bin/env python3
# =============================================================================
#  akram-ssh-guard.py
#  Detector de ataques de fuerza bruta contra SSH con respuesta escalonada
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: SSH Brute Force Detector · Laboratorio AKRAM-LAB
#
#  Lee /var/log/auth.log en tiempo real, cuenta los fallos de autenticación
#  de cada IP dentro de una ventana deslizante y responde por escalones:
#
#    1. AVISO      fallos >= UMBRAL_AVISO    -> se registra la alerta
#    2. LIMITAR    fallos >= UMBRAL_LIMITAR  -> nftables limita las conexiones
#                                               nuevas a SSH de esa IP
#    3. BLOQUEAR   fallos >= UMBRAL_BLOQUEO  -> nftables descarta todo el
#                                               tráfico de esa IP un tiempo
#
#  Usa su propia tabla nftables (inet akram_guard) con conjuntos con caducidad,
#  así no toca las reglas del cortafuegos principal del servidor.
#
#  Uso:  sudo akram-ssh-guard.py               (modo servicio)
#        sudo akram-ssh-guard.py --estado      (IPs limitadas y bloqueadas)
#        sudo akram-ssh-guard.py --desbloquear 1.2.3.4
# =============================================================================
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

# ---------------------------------------------------------------- configuración
AUTH_LOG = "/var/log/auth.log"
LOG_EVENTOS = "/var/log/akram-ssh-guard.log"      # legible por personas
LOG_JSON = "/var/log/akram-ssh-guard.json"         # una línea JSON por evento (para un SIEM)

VENTANA_SEG = 300          # ventana deslizante de 5 minutos
UMBRAL_AVISO = 3
UMBRAL_LIMITAR = 6
UMBRAL_BLOQUEO = 10
DURACION_LIMITE = "15m"
DURACION_BLOQUEO = "1h"

LISTA_BLANCA = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.2.0/24"),   # red NAT de VirtualBox: por aquí administro yo
]

TABLA = "akram_guard"

# Líneas de sshd que indican un intento fallido. Cada patrón captura la IP.
# Solo se cuentan las líneas "Failed ...": sshd escribe una por cada contraseña probada,
# también para usuarios inexistentes o no permitidos. Las líneas "Invalid user" o
# "not allowed" acompañan a esas mismas pruebas y contarlas duplicaría los fallos.
PATRONES = [
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
]
PATRON_PAM_FAILLOCK = re.compile(r"pam_faillock\(sshd:auth\): Consecutive login failures for user (?P<user>\S+) account temporarily locked")

AZUL, VERDE, AMARILLO, NARANJA, ROJO, NC = "\033[1;34m", "\033[1;32m", "\033[1;33m", "\033[38;5;208m", "\033[1;31m", "\033[0m"


# ---------------------------------------------------------------- utilidades
def ahora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def registrar(nivel, ip, mensaje, **extra):
    color = {"INFO": AZUL, "AVISO": AMARILLO, "LIMITAR": NARANJA, "BLOQUEAR": ROJO, "OK": VERDE}.get(nivel, NC)
    linea = f"{ahora()} [{nivel:<8}] {ip:<15} {mensaje}"
    print(f"{color}{linea}{NC}", flush=True)
    with open(LOG_EVENTOS, "a") as f:
        f.write(linea + "\n")
    evento = {"ts": datetime.now().isoformat(timespec="seconds"), "host": os.uname().nodename,
              "herramienta": "akram-ssh-guard", "nivel": nivel, "ip": ip, "mensaje": mensaje, **extra}
    with open(LOG_JSON, "a") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")


def nft(*args, entrada=None):
    return subprocess.run(["nft", *args], input=entrada, text=True, capture_output=True)


def en_lista_blanca(ip):
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(direccion in red for red in LISTA_BLANCA)


# ---------------------------------------------------------------- nftables
def preparar_nftables():
    """Crea la tabla propia con dos conjuntos con caducidad automática."""
    reglas = f"""
table inet {TABLA} {{
    set limitadas {{ type ipv4_addr; flags timeout; }}
    set bloqueadas {{ type ipv4_addr; flags timeout; }}
    chain entrada {{
        type filter hook input priority -10; policy accept;
        ip saddr @bloqueadas counter drop comment "akram-ssh-guard: bloqueo"
        ip saddr @limitadas tcp dport 22 ct state new meter limite_ssh {{ ip saddr limit rate over 2/minute }} counter drop comment "akram-ssh-guard: limite"
    }}
}}
"""
    if nft("list", "table", "inet", TABLA).returncode != 0:
        r = nft("-f", "-", entrada=reglas)
        if r.returncode != 0:
            sys.exit(f"No se pudo crear la tabla nftables: {r.stderr.strip()}")
    registrar("INFO", "-", f"Tabla nftables inet {TABLA} preparada")


def anadir(conjunto, ip, duracion):
    r = nft("add", "element", "inet", TABLA, conjunto, f"{{ {ip} timeout {duracion} }}")
    return r.returncode == 0


# ---------------------------------------------------------------- lectura del log
def seguir(ruta):
    """Lee el fichero como tail -F: desde el final y sobreviviendo a la rotación."""
    while not os.path.exists(ruta):
        time.sleep(1)
    f = open(ruta)
    f.seek(0, os.SEEK_END)
    inodo = os.fstat(f.fileno()).st_ino
    while True:
        linea = f.readline()
        if linea:
            yield linea
            continue
        time.sleep(0.3)
        try:
            if os.stat(ruta).st_ino != inodo:       # logrotate ha creado un fichero nuevo
                f.close()
                f = open(ruta)
                inodo = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------- motor
def vigilar():
    preparar_nftables()
    fallos = defaultdict(deque)          # ip -> instantes de los fallos
    usuarios = defaultdict(set)          # ip -> usuarios probados
    escalon = defaultdict(int)           # ip -> 0 nada, 1 aviso, 2 limitada, 3 bloqueada
    registrar("INFO", "-", f"Vigilando {AUTH_LOG} · ventana {VENTANA_SEG}s · "
                           f"umbrales {UMBRAL_AVISO}/{UMBRAL_LIMITAR}/{UMBRAL_BLOQUEO}")

    for linea in seguir(AUTH_LOG):
        if "sshd" not in linea:
            continue
        m_lock = PATRON_PAM_FAILLOCK.search(linea)
        if m_lock:
            registrar("AVISO", "-", f"pam_faillock ha bloqueado la cuenta '{m_lock['user']}'", usuario=m_lock["user"])
            continue
        for patron in PATRONES:
            m = patron.search(linea)
            if not m:
                continue
            ip, usuario = m["ip"], m["user"] or "?"
            if en_lista_blanca(ip):
                break
            t = time.time()
            cola = fallos[ip]
            cola.append(t)
            usuarios[ip].add(usuario)
            while cola and t - cola[0] > VENTANA_SEG:
                cola.popleft()
            n = len(cola)
            if n == 1:                       # empieza una ventana nueva: el escalón vuelve a cero
                escalon[ip] = 0
            datos = {"fallos": n, "usuarios": sorted(usuarios[ip])[:20]}

            if n >= UMBRAL_BLOQUEO and escalon[ip] < 3:
                if anadir("bloqueadas", ip, DURACION_BLOQUEO):
                    escalon[ip] = 3
                    registrar("BLOQUEAR", ip, f"{n} fallos en {VENTANA_SEG}s · bloqueada {DURACION_BLOQUEO} "
                                              f"· usuarios probados: {len(usuarios[ip])}", **datos)
            elif n >= UMBRAL_LIMITAR and escalon[ip] < 2:
                if anadir("limitadas", ip, DURACION_LIMITE):
                    escalon[ip] = 2
                    registrar("LIMITAR", ip, f"{n} fallos · SSH limitado a 2 conexiones/min durante {DURACION_LIMITE}", **datos)
            elif n >= UMBRAL_AVISO and escalon[ip] < 1:
                escalon[ip] = 1
                registrar("AVISO", ip, f"{n} fallos de autenticación · último usuario: {usuario}", **datos)
            break


# ---------------------------------------------------------------- comandos
def estado():
    r = nft("-j", "list", "table", "inet", TABLA)
    if r.returncode != 0:
        print("La tabla no existe: el servicio no se ha iniciado.")
        return
    datos = json.loads(r.stdout)["nftables"]
    for obj in datos:
        if "set" in obj:
            s = obj["set"]
            elems = s.get("elem", [])
            print(f"{AZUL}{s['name']}{NC} ({len(elems)})")
            for e in elems:
                e = e.get("elem", e)
                ip = e["val"] if isinstance(e, dict) else e
                expira = e.get("expires", "?") if isinstance(e, dict) else "?"
                print(f"   {ip:<15}  caduca en {expira}s")
        if "rule" in obj and "comment" in obj["rule"]:
            for expr in obj["rule"]["expr"]:
                if "counter" in expr:
                    c = expr["counter"]
                    print(f"   {obj['rule']['comment']}: {c['packets']} paquetes descartados")


def desbloquear(ip):
    for conjunto in ("bloqueadas", "limitadas"):
        nft("delete", "element", "inet", TABLA, conjunto, f"{{ {ip} }}")
    registrar("OK", ip, "Desbloqueada manualmente")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Ejecuta este programa como root.")
    if "--estado" in sys.argv:
        estado()
    elif "--desbloquear" in sys.argv:
        desbloquear(sys.argv[sys.argv.index("--desbloquear") + 1])
    else:
        try:
            vigilar()
        except KeyboardInterrupt:
            registrar("INFO", "-", "Detenido")
