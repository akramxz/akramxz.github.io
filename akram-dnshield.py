#!/usr/bin/env python3
# =============================================================================
#  akram-dnshield.py - DNS Sinkhole (agujero negro de DNS)
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: DNS Sinkhole - Laboratorio AKRAM-LAB
#
#  Un servidor DNS sencillo, sin dependencias externas (solo biblioteca
#  estandar). Para cada consulta:
#     - si el dominio (o uno de sus dominios padre) esta en la lista negra,
#       responde A 0.0.0.0 / AAAA :: (lo "sumerge") y lo registra como BLOQUEADO
#     - si no, reenvia la consulta tal cual a un resolutor de verdad y
#       devuelve su respuesta (RESUELTO)
#  Todo queda guardado en una base de datos SQLite: la lista negra y el
#  registro de consultas, para poder sacar estadisticas despues.
#
#  Uso:
#     sudo akram-dnshield.py -i 10.66.0.10            # arrancar el servidor
#     akram-dnshield.py --cargar lista.txt            # importar dominios
#     akram-dnshield.py --stats                       # ver estadisticas
#     akram-dnshield.py --listar                       # ver la lista negra
#  Necesita root para escuchar en el puerto 53. Se para con Ctrl-C.
# =============================================================================
import argparse
import os
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
from datetime import datetime

AZUL = "\033[1;36m"; VERDE = "\033[1;32m"; ROJO = "\033[1;31m"
GRIS = "\033[0;90m"; AMARILLO = "\033[1;33m"; NC = "\033[0m"
DB_POR_DEFECTO = "/var/lib/akram-dnshield/dnshield.db"
TIPOS = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 12: "PTR", 6: "SOA"}


# --------------------------------------------------------------------------- #
#  Base de datos
# --------------------------------------------------------------------------- #
class BaseDatos:
    def __init__(self, ruta):
        os.makedirs(os.path.dirname(ruta), exist_ok=True) if os.path.dirname(ruta) else None
        self.con = sqlite3.connect(ruta, check_same_thread=False)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("CREATE TABLE IF NOT EXISTS bloqueo("
                         "dominio TEXT PRIMARY KEY, fuente TEXT, agregado TEXT)")
        self.con.execute("CREATE TABLE IF NOT EXISTS registro("
                         "ts TEXT, cliente TEXT, dominio TEXT, tipo TEXT, accion TEXT, detalle TEXT)")
        self.con.commit()
        self.lock = threading.Lock()
        self.negra = set()
        self.recargar()

    def recargar(self):
        with self.lock:
            self.negra = {r[0] for r in self.con.execute("SELECT dominio FROM bloqueo")}
        return len(self.negra)

    def importar(self, lineas, fuente):
        nuevos = 0
        with self.lock:
            for ln in lineas:
                d = normalizar(ln)
                if not d:
                    continue
                try:
                    cur = self.con.execute("INSERT OR IGNORE INTO bloqueo VALUES(?,?,?)",
                                           (d, fuente, datetime.now().isoformat(timespec="seconds")))
                    nuevos += cur.rowcount if cur.rowcount > 0 else 0
                except sqlite3.Error:
                    pass
            self.con.commit()
        self.recargar()
        return nuevos

    def apunta(self, cliente, dominio, tipo, accion, detalle=""):
        with self.lock:
            self.con.execute("INSERT INTO registro VALUES(?,?,?,?,?,?)",
                             (datetime.now().isoformat(timespec="seconds"), cliente, dominio, tipo, accion, detalle))
            self.con.commit()


def normalizar(linea):
    """Admite 'dominio', '0.0.0.0 dominio' y '127.0.0.1 dominio'; ignora comentarios."""
    linea = linea.split("#", 1)[0].strip()
    if not linea:
        return None
    partes = linea.split()
    dom = partes[-1].lower().rstrip(".")
    if dom in ("localhost", "0.0.0.0", "127.0.0.1", "::1") or "." not in dom:
        return None
    if not re.match(r"^[a-z0-9_.-]+$", dom):
        return None
    return dom


# --------------------------------------------------------------------------- #
#  DNS: lectura del nombre y construccion de la respuesta de bloqueo
# --------------------------------------------------------------------------- #
def leer_nombre(datos, offset):
    partes = []
    salto = None
    i = offset
    while True:
        if i >= len(datos):
            break
        long = datos[i]
        if long == 0:
            i += 1
            break
        if long & 0xC0 == 0xC0:                       # puntero de compresion
            puntero = ((long & 0x3F) << 8) | datos[i + 1]
            if salto is None:
                salto = i + 2
            i = puntero
            continue
        partes.append(datos[i + 1:i + 1 + long].decode("latin1"))
        i += long + 1
    nombre = ".".join(partes).lower()
    return nombre, (salto if salto is not None else i)


def respuesta_bloqueo(peticion, fin_pregunta, qtype, sink4, sink6):
    """Devuelve la peticion convertida en respuesta que sumerge el dominio."""
    tid = peticion[0:2]
    rd = peticion[2] & 0x01                             # conservar el bit RD
    cab = tid + bytes([0x80 | rd, 0x80])               # QR=1, RA=1, rcode=0
    pregunta = peticion[12:fin_pregunta]
    puntero = b"\xc0\x0c"                               # apunta al nombre de la pregunta
    if qtype == 1:                                      # A -> 0.0.0.0
        ans = puntero + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(sink4)
        nans = 1
    elif qtype == 28:                                   # AAAA -> ::
        ans = puntero + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, sink6)
        nans = 1
    else:                                               # otros tipos: respuesta vacia
        ans = b""
        nans = 0
    cab += peticion[4:6] + struct.pack("!HHH", nans, 0, 0)
    return cab + pregunta + ans


# --------------------------------------------------------------------------- #
#  Servidor
# --------------------------------------------------------------------------- #
class Sinkhole:
    def __init__(self, bd, upstreams, sink4, sink6):
        self.bd = bd
        self.upstreams = upstreams
        self.sink4 = sink4
        self.sink6 = sink6
        self.n_total = 0
        self.n_bloq = 0
        self.n_reenv = 0
        self.n_error = 0

    def coincide(self, dominio):
        """Bloquea el dominio y cualquier subdominio suyo."""
        etiquetas = dominio.split(".")
        for i in range(len(etiquetas) - 1):
            if ".".join(etiquetas[i:]) in self.bd.negra:
                return ".".join(etiquetas[i:])
        return None

    def reenviar(self, peticion):
        for up in self.upstreams:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(peticion, (up, 53))
                resp, _ = s.recvfrom(4096)
                s.close()
                return resp, up
            except OSError:
                continue
        return None, None

    def atender(self, datos, cliente, sock):
        self.n_total += 1
        ip = cliente[0]
        try:
            qname, fin = leer_nombre(datos, 12)
            qtype = struct.unpack("!H", datos[fin:fin + 2])[0]
        except Exception:
            self.n_error += 1
            return
        tnom = TIPOS.get(qtype, f"T{qtype}")

        regla = self.coincide(qname)
        if regla:
            self.n_bloq += 1
            resp = respuesta_bloqueo(datos, fin + 4, qtype, self.sink4, self.sink6)
            sock.sendto(resp, cliente)
            self.bd.apunta(ip, qname, tnom, "BLOQUEADO", f"regla={regla}")
            print(f"{GRIS}{hora()}{NC} {ip:<13} {ROJO}BLOQUEADO{NC} {qname} ({tnom})  {GRIS}<- {regla}{NC}")
            return

        resp, up = self.reenviar(datos)
        if resp is None:
            self.n_error += 1
            self.bd.apunta(ip, qname, tnom, "ERROR", "sin respuesta del resolutor")
            print(f"{GRIS}{hora()}{NC} {ip:<13} {AMARILLO}ERROR{NC}     {qname} ({tnom})")
            return
        self.n_reenv += 1
        sock.sendto(resp, cliente)
        nans = struct.unpack("!H", resp[6:8])[0]
        self.bd.apunta(ip, qname, tnom, "RESUELTO", f"respuestas={nans} via {up}")
        print(f"{GRIS}{hora()}{NC} {ip:<13} {VERDE}RESUELTO{NC}  {qname} ({tnom})  {GRIS}{nans} resp{NC}")

    def servir(self, ip, puerto):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, puerto))
        print(f"{AZUL}akram-dnshield - [Akram El Mazzoudi] - escuchando en {ip}:{puerto}/udp{NC}")
        print(f"{GRIS}  Lista negra: {len(self.bd.negra)} dominios   Resolutores: {', '.join(self.upstreams)}{NC}")
        print(f"{GRIS}  Sumidero: A -> {self.sink4} / AAAA -> {self.sink6}   Ctrl-C para parar{NC}\n")
        try:
            while True:
                datos, cliente = sock.recvfrom(2048)
                threading.Thread(target=self.atender, args=(datos, cliente, sock), daemon=True).start()
        except KeyboardInterrupt:
            print(f"\n{AZUL}Resumen:{NC} {self.n_total} consultas - "
                  f"{ROJO}{self.n_bloq} bloqueadas{NC}, {VERDE}{self.n_reenv} resueltas{NC}, {self.n_error} errores")
        finally:
            sock.close()


def hora():
    return datetime.now().strftime("%H:%M:%S")


def upstreams_del_sistema():
    """Lee los resolutores de verdad que usa el sistema (los del DHCP del laboratorio)."""
    for ruta in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            ips = []
            for ln in open(ruta):
                m = re.match(r"\s*nameserver\s+([0-9.]+)", ln)
                if m and not m.group(1).startswith("127."):
                    ips.append(m.group(1))
            if ips:
                return ips
        except OSError:
            continue
    return []


# --------------------------------------------------------------------------- #
#  Estadisticas
# --------------------------------------------------------------------------- #
def mostrar_stats(bd):
    c = bd.con
    tot = c.execute("SELECT COUNT(*) FROM registro").fetchone()[0]
    bloq = c.execute("SELECT COUNT(*) FROM registro WHERE accion='BLOQUEADO'").fetchone()[0]
    res = c.execute("SELECT COUNT(*) FROM registro WHERE accion='RESUELTO'").fetchone()[0]
    pct = (bloq * 100 // tot) if tot else 0
    print(f"{AZUL}Estadisticas de akram-dnshield - Akram El Mazzoudi{NC}")
    print(f"  Lista negra:      {len(bd.negra)} dominios")
    print(f"  Consultas totales:{tot:>6}")
    print(f"  {ROJO}Bloqueadas:{NC}       {bloq:>6}  ({pct} %)")
    print(f"  {VERDE}Resueltas:{NC}        {res:>6}")
    print(f"\n  {ROJO}Dominios mas bloqueados:{NC}")
    for d, n in c.execute("SELECT dominio,COUNT(*) FROM registro WHERE accion='BLOQUEADO' "
                          "GROUP BY dominio ORDER BY 2 DESC LIMIT 10"):
        print(f"    {n:>4}  {d}")
    print(f"\n  {AZUL}Clientes:{NC}")
    for ip, n in c.execute("SELECT cliente,COUNT(*) FROM registro GROUP BY cliente ORDER BY 2 DESC LIMIT 6"):
        print(f"    {n:>4}  {ip}")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="DNS Sinkhole - Akram El Mazzoudi Zarrouk")
    ap.add_argument("-i", "--ip", default="0.0.0.0", help="direccion donde escuchar (ej. 10.66.0.10)")
    ap.add_argument("-p", "--puerto", type=int, default=53)
    ap.add_argument("--upstream", help="resolutores separados por comas (por defecto, los del sistema)")
    ap.add_argument("--sink4", default="0.0.0.0", help="IPv4 con la que se responde a lo bloqueado")
    ap.add_argument("--sink6", default="::", help="IPv6 con la que se responde a lo bloqueado")
    ap.add_argument("--db", default=DB_POR_DEFECTO, help="base de datos SQLite")
    ap.add_argument("--cargar", metavar="FICHERO", help="importar dominios a la lista negra y salir")
    ap.add_argument("--stats", action="store_true", help="mostrar estadisticas y salir")
    ap.add_argument("--listar", action="store_true", help="listar la lista negra y salir")
    a = ap.parse_args()

    bd = BaseDatos(a.db)

    if a.cargar:
        n = bd.importar(open(a.cargar, encoding="utf-8", errors="ignore"), os.path.basename(a.cargar))
        print(f"Importados {n} dominios nuevos. La lista negra tiene ahora {len(bd.negra)}.")
        return
    if a.listar:
        for d in sorted(bd.negra):
            print(d)
        print(f"\n{len(bd.negra)} dominios en la lista negra.")
        return
    if a.stats:
        mostrar_stats(bd)
        return

    if os.geteuid() != 0:
        sys.exit("Hace falta root para escuchar en el puerto 53 (sudo).")

    ups = a.upstream.split(",") if a.upstream else upstreams_del_sistema()
    if not ups:
        sys.exit("No se encontro ningun resolutor. Indica uno con --upstream.")
    Sinkhole(bd, ups, a.sink4, a.sink6).servir(a.ip, a.puerto)


if __name__ == "__main__":
    main()
