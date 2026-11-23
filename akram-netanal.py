#!/usr/bin/env python3
# =============================================================================
#  akram-netanal.py · Analizador de tráfico de red
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: Network Traffic Analyzer · Laboratorio AKRAM-LAB
#
#  Captura tramas en una interfaz con un socket RAW AF_PACKET (sin dependencias
#  externas: parsea Ethernet, IPv4, TCP, UDP e ICMP a mano) y muestra en vivo:
#     - reparto por protocolo
#     - equipos que más tráfico generan (top talkers), por paquetes y bytes
#     - puertos de destino más vistos
#     - una alerta sencilla si una IP abre muchas conexiones TCP nuevas (SYN)
#       al mismo puerto en poco tiempo (patrón de fuerza bruta o escaneo)
#
#  Uso:  sudo akram-netanal.py -i enp0s8
#        sudo akram-netanal.py -i enp0s8 -s 20 --json captura.json
#  Necesita root para abrir el socket RAW. Se detiene con Ctrl-C.
# =============================================================================
import argparse
import collections
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime

AZUL, VERDE, ROJO, GRIS, AMARILLO, NC = "\033[1;36m", "\033[1;32m", "\033[1;31m", "\033[0;90m", "\033[1;33m", "\033[0m"
PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


class Analizador:
    def __init__(self, ventana):
        self.inicio = time.time()
        self.paquetes = 0
        self.bytes = 0
        self.por_proto = collections.Counter()
        self.bytes_ip = collections.Counter()
        self.paq_ip = collections.Counter()
        self.por_puerto = collections.Counter()
        # Para la alerta de fuerza bruta: (ip_origen, puerto_destino) -> [instantes de SYN]
        self.syns = collections.defaultdict(collections.deque)
        self.alertas = {}
        self.ventana = ventana

    def procesar(self, datos):
        self.paquetes += 1
        self.bytes += len(datos)
        if len(datos) < 14:
            return
        ethertype = struct.unpack("!H", datos[12:14])[0]
        if ethertype != 0x0800:          # solo IPv4 en este análisis
            self.por_proto["no-IPv4"] += 1
            return
        ihl = (datos[14] & 0x0F) * 4
        proto = datos[23]
        src = socket.inet_ntoa(datos[26:30])
        dst = socket.inet_ntoa(datos[30:34])
        self.por_proto[PROTOS.get(proto, f"proto-{proto}")] += 1
        self.bytes_ip[src] += len(datos)
        self.paq_ip[src] += 1

        l4 = 14 + ihl
        if proto == 6 and len(datos) >= l4 + 14:      # TCP
            sport, dport = struct.unpack("!HH", datos[l4:l4 + 4])
            flags = datos[l4 + 13]
            self.por_puerto[dport] += 1
            syn = flags & 0x02
            ack = flags & 0x10
            if syn and not ack:                        # SYN de conexión nueva
                t = time.time()
                clave = (src, dport)
                cola = self.syns[clave]
                cola.append(t)
                while cola and t - cola[0] > self.ventana:
                    cola.popleft()
                if len(cola) >= 10:
                    self.alertas[clave] = len(cola)
        elif proto == 17 and len(datos) >= l4 + 4:     # UDP
            _, dport = struct.unpack("!HH", datos[l4:l4 + 4])
            self.por_puerto[dport] += 1

    def pintar(self, interfaz, host):
        dur = max(time.time() - self.inicio, 0.001)
        os.system("clear")
        print(f"{AZUL}akram-netanal · [Akram El Mazzoudi] · {host} · interfaz {interfaz}{NC}")
        print(f"{GRIS}  {self.paquetes} paquetes · {self.bytes/1024:.1f} KiB · {dur:.0f} s · "
              f"{self.paquetes/dur:.0f} paq/s · {self.bytes*8/dur/1000:.1f} kbit/s{NC}\n")

        print(f"  {AZUL}Protocolos:{NC}  " + "   ".join(
            f"{p} {c} ({c*100//max(self.paquetes,1)}%)" for p, c in self.por_proto.most_common()))

        print(f"\n  {AZUL}Equipos que más tráfico generan:{NC}")
        for ip, by in self.bytes_ip.most_common(6):
            print(f"    {ip:<16} {self.paq_ip[ip]:>6} paq   {by/1024:>8.1f} KiB")

        print(f"\n  {AZUL}Puertos de destino más vistos:{NC}")
        linea = "   ".join(f"{pt}:{c}" for pt, c in self.por_puerto.most_common(8))
        print(f"    {linea}")

        if self.alertas:
            print(f"\n  {ROJO}ALERTAS (muchas conexiones nuevas desde un mismo origen):{NC}")
            for (ip, puerto), n in sorted(self.alertas.items(), key=lambda x: -x[1]):
                print(f"    {ROJO}{ip} -> puerto {puerto}: {n} SYN en {self.ventana}s "
                      f"(posible fuerza bruta o escaneo){NC}")
        print(f"\n{GRIS}  Ctrl-C para parar y ver el resumen final.{NC}")

    def resumen_json(self, interfaz, host):
        dur = max(time.time() - self.inicio, 0.001)
        return {
            "autor": "Akram El Mazzoudi Zarrouk", "herramienta": "akram-netanal",
            "host": host, "interfaz": interfaz, "fecha": datetime.now().isoformat(timespec="seconds"),
            "duracion_s": round(dur, 1), "paquetes": self.paquetes, "bytes": self.bytes,
            "protocolos": dict(self.por_proto),
            "top_talkers": [{"ip": ip, "paquetes": self.paq_ip[ip], "bytes": by}
                            for ip, by in self.bytes_ip.most_common(10)],
            "puertos": dict(self.por_puerto.most_common(15)),
            "alertas": [{"origen": ip, "puerto": pt, "syn": n} for (ip, pt), n in self.alertas.items()],
        }


def main():
    ap = argparse.ArgumentParser(description="Analizador de tráfico de red · Akram El Mazzoudi Zarrouk")
    ap.add_argument("-i", "--interfaz", required=True, help="interfaz a escuchar (ej. enp0s8)")
    ap.add_argument("-s", "--segundos", type=int, default=0, help="parar tras N segundos (0 = hasta Ctrl-C)")
    ap.add_argument("-w", "--ventana", type=int, default=10, help="ventana de la alerta de fuerza bruta (s)")
    ap.add_argument("--refresco", type=float, default=1.0, help="cada cuánto repinta la pantalla (s)")
    ap.add_argument("--json", metavar="FICHERO", help="guardar el resumen final en JSON")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Hace falta root para abrir el socket RAW (sudo).")

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((a.interfaz, 0))
    except OSError as e:
        sys.exit(f"No se pudo escuchar en {a.interfaz}: {e}")
    s.settimeout(a.refresco)

    host = socket.gethostname()
    an = Analizador(a.ventana)
    ultimo = 0.0
    fin = (time.time() + a.segundos) if a.segundos else None
    try:
        while True:
            try:
                datos = s.recv(65535)
                an.procesar(datos)
            except socket.timeout:
                pass
            ahora = time.time()
            if ahora - ultimo >= a.refresco:
                an.pintar(a.interfaz, host)
                ultimo = ahora
            if fin and ahora >= fin:
                break
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

    an.pintar(a.interfaz, host)
    print(f"\n{VERDE}  Captura terminada: {an.paquetes} paquetes en {time.time()-an.inicio:.0f} s.{NC}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(an.resumen_json(a.interfaz, host), f, ensure_ascii=False, indent=2)
        print(f"{GRIS}  Resumen guardado en {a.json}{NC}")


if __name__ == "__main__":
    main()
