#!/usr/bin/env python3
# =============================================================================
#  akram-siem.py - SIEM del laboratorio AKRAM-LAB
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: SIEM final - Laboratorio AKRAM-LAB
#
#  Centraliza los registros de todas las maquinas del laboratorio, los
#  normaliza a un formato comun, los guarda en SQLite y los pasa por un motor
#  de reglas de correlacion que genera alertas (con su tecnica MITRE ATT&CK).
#  Incluye un panel web propio. Solo biblioteca estandar: sin dependencias.
#
#  Fuentes que recoge:
#     - syslog por UDP 514 (Kali y cualquier equipo Linux)
#     - HTTP POST /api/ingest con token (agente PowerShell del Windows Server)
#     - /var/log/auth.log de SRV01 (sshd, sudo)
#     - /var/log/akram-ssh-guard.json (proyecto 03)
#     - base de datos de akram-dnshield (proyecto 08)
#     - informe JSON de akram-dockaudit (proyecto 09)
#
#  Uso:  sudo akram-siem.py                    (servicio)
#        akram-siem.py --resumen               (estado por consola)
# =============================================================================
import argparse
import collections
import json
import os
import re
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = "/var/lib/akram-siem/siem.db"
PANEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.html")
CONF = "/etc/akram-siem/token"
SEV = {"INFO": 0, "BAJA": 1, "MEDIA": 2, "ALTA": 3, "CRITICA": 4}
AZUL = "\033[1;36m"; ROJO = "\033[1;31m"; AMAR = "\033[1;33m"; VERDE = "\033[1;32m"
GRIS = "\033[0;90m"; MAG = "\033[1;35m"; NC = "\033[0m"
COL = {"CRITICA": MAG, "ALTA": ROJO, "MEDIA": AMAR, "BAJA": AZUL, "INFO": GRIS}


def ahora():
    return datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
#  Almacen
# --------------------------------------------------------------------------- #
class Almacen:
    def __init__(self, ruta):
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        self.con = sqlite3.connect(ruta, check_same_thread=False)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.executescript("""
        CREATE TABLE IF NOT EXISTS eventos(
            id INTEGER PRIMARY KEY, ts TEXT, host TEXT, fuente TEXT, tipo TEXT,
            severidad TEXT, ip TEXT, usuario TEXT, mensaje TEXT);
        CREATE TABLE IF NOT EXISTS alertas(
            id INTEGER PRIMARY KEY, ts TEXT, regla TEXT, severidad TEXT, mitre TEXT,
            ip TEXT, usuario TEXT, host TEXT, descripcion TEXT, eventos INTEGER);
        CREATE TABLE IF NOT EXISTS cursores(nombre TEXT PRIMARY KEY, valor TEXT);
        CREATE INDEX IF NOT EXISTS ix_ev_ts ON eventos(ts);
        CREATE INDEX IF NOT EXISTS ix_al_ts ON alertas(ts);
        """)
        self.lock = threading.Lock()

    def evento(self, e):
        with self.lock:
            cur = self.con.execute(
                "INSERT INTO eventos(ts,host,fuente,tipo,severidad,ip,usuario,mensaje) VALUES(?,?,?,?,?,?,?,?)",
                (e["ts"], e["host"], e["fuente"], e["tipo"], e["severidad"], e.get("ip", ""),
                 e.get("usuario", ""), e.get("mensaje", "")[:500]))
            self.con.commit()
            return cur.lastrowid

    def alerta(self, a):
        with self.lock:
            self.con.execute(
                "INSERT INTO alertas(ts,regla,severidad,mitre,ip,usuario,host,descripcion,eventos) VALUES(?,?,?,?,?,?,?,?,?)",
                (a["ts"], a["regla"], a["severidad"], a["mitre"], a.get("ip", ""), a.get("usuario", ""),
                 a.get("host", ""), a["descripcion"], a.get("eventos", 1)))
            self.con.commit()

    def cursor(self, nombre, valor=None):
        with self.lock:
            if valor is None:
                r = self.con.execute("SELECT valor FROM cursores WHERE nombre=?", (nombre,)).fetchone()
                return r[0] if r else None
            self.con.execute("INSERT OR REPLACE INTO cursores VALUES(?,?)", (nombre, str(valor)))
            self.con.commit()

    def consulta(self, sql, args=()):
        with self.lock:
            return self.con.execute(sql, args).fetchall()


# --------------------------------------------------------------------------- #
#  Motor de correlacion
# --------------------------------------------------------------------------- #
class Motor:
    """Reglas con ventanas deslizantes. Cada alerta se silencia un rato para no repetirla."""

    def __init__(self, almacen):
        self.a = almacen
        self.ventanas = collections.defaultdict(collections.deque)
        self.silencio = {}
        self.reglas_ip = collections.defaultdict(dict)   # ip -> {regla: instante}
        self.lock = threading.Lock()

    def _cuenta(self, clave, segundos):
        t = time.time()
        d = self.ventanas[clave]
        d.append(t)
        while d and t - d[0] > segundos:
            d.popleft()
        return len(d)

    def _disparar(self, regla, sev, mitre, desc, e, n=1, silencio=300):
        # Una alerta por regla y origen: si hay IP, la IP; si no, el usuario y el equipo
        clave = (regla, e.get("ip")) if e.get("ip") else (regla, e.get("usuario"), e.get("host"))
        t = time.time()
        if t - self.silencio.get(clave, 0) < silencio:
            return
        self.silencio[clave] = t
        a = {"ts": ahora(), "regla": regla, "severidad": sev, "mitre": mitre, "ip": e.get("ip", ""),
             "usuario": e.get("usuario", ""), "host": e.get("host", ""), "descripcion": desc, "eventos": n}
        self.a.alerta(a)
        print(f"{COL[sev]}[ALERTA {sev}]{NC} {regla} · {desc} {GRIS}({mitre}){NC}", flush=True)
        if e.get("ip") and regla != "Incidente multi-fuente":
            self._correlar_ip(regla, e)

    def _correlar_ip(self, regla, e):
        """Si una misma IP dispara dos reglas distintas en 15 minutos, es un incidente."""
        ip = e["ip"]
        t = time.time()
        vistas = self.reglas_ip[ip]
        vistas[regla] = t
        recientes = [r for r, ti in vistas.items() if t - ti < 900]
        if len(recientes) >= 2:
            self._disparar("Incidente multi-fuente", "CRITICA", "TA0001→TA0011",
                           f"{ip} encadena {len(recientes)} tipos de actividad maliciosa: "
                           + ", ".join(sorted(recientes)), {"ip": ip, "host": e.get("host", "")},
                           n=len(recientes), silencio=900)

    def evaluar(self, e):
        with self.lock:
            f, tipo, ip, us = e["fuente"], e["tipo"], e.get("ip", ""), e.get("usuario", "")
            # SSH: contrasenas fallidas
            if tipo == "ssh_fallo":
                n = self._cuenta(("ssh", ip), 60)
                if n >= 5:
                    self._disparar("Fuerza bruta SSH", "ALTA", "T1110.001",
                                   f"{n} contrasenas fallidas desde {ip} en 60 s", e, n)
            elif tipo == "ssh_usuario_invalido":
                n = self._cuenta(("sshinv", ip), 120)
                if n >= 3:
                    self._disparar("Enumeracion de usuarios SSH", "MEDIA", "T1087",
                                   f"{ip} prueba {n} usuarios que no existen", e, n)
            elif tipo == "ssh_login_ok" and ip and self.ventanas.get(("ssh", ip)):
                self._disparar("Acceso tras fuerza bruta", "CRITICA", "T1110 → T1078",
                               f"Login correcto de {us} desde {ip} despues de varios fallos", e)
            elif tipo == "ipsguard_bloqueo":
                self._disparar("Respuesta automatica: IP bloqueada", "MEDIA", "M1036",
                               f"akram-ssh-guard bloqueo {ip} en el cortafuegos", e)
            # DNS
            elif tipo == "dns_bloqueado":
                dom = e.get("mensaje", "")
                if re.search(r"malware|phishing|c2-|maligno|falso", dom):
                    self._disparar("Consulta a dominio malicioso", "ALTA", "T1071.004",
                                   f"{ip} intento resolver {dom.split()[0]}", e, silencio=120)
                else:
                    n = self._cuenta(("dnsads", ip), 300)
                    if n >= 10:
                        self._disparar("Rastreo/publicidad bloqueada", "BAJA", "-",
                                       f"{ip}: {n} dominios de publicidad bloqueados en 5 min", e, n)
            # Docker
            elif tipo == "docker_hallazgo" and e["severidad"] == "ALTA":
                self._disparar("Contenedor inseguro", "MEDIA", "T1611",
                               e.get("mensaje", ""), e, silencio=3600)
            # Windows / Active Directory
            elif tipo == "win_4625":
                n = self._cuenta(("w4625", us or ip), 120)
                if n >= 5:
                    self._disparar("Fuerza bruta contra el dominio", "ALTA", "T1110.001",
                                   f"{n} inicios de sesion fallidos para {us} en 2 min", e, n)
                n2 = len({u for u in self._usuarios_ip(ip, us)})
                if ip and n2 >= 4:
                    self._disparar("Password spraying", "ALTA", "T1110.003",
                                   f"{ip} prueba contrasenas contra {n2} cuentas distintas", e, n2)
            elif tipo == "win_4740":
                self._disparar("Cuenta bloqueada", "MEDIA", "T1110",
                               f"La cuenta {us} del dominio se ha bloqueado", e, silencio=60)
            elif tipo in ("win_4728", "win_4732", "win_4756"):
                if re.search(r"admin|domain|dominio|empresa|esquema|schema", e.get("mensaje", ""), re.I):
                    self._disparar("Alta en grupo privilegiado", "ALTA", "T1098",
                                   e.get("mensaje", ""), e, silencio=30)
            elif tipo == "win_4720":
                self._disparar("Cuenta de usuario creada", "BAJA", "T1136.002",
                               e.get("mensaje", ""), e, silencio=5)
            elif tipo == "win_1102":
                self._disparar("Registro de seguridad borrado", "CRITICA", "T1070.001",
                               f"Alguien ha borrado el log de seguridad en {e['host']}", e)
            elif tipo == "sudo_fallo":
                n = self._cuenta(("sudo", us), 300)
                if n >= 3:
                    self._disparar("Intentos de sudo fallidos", "MEDIA", "T1548.003",
                                   f"{us} ha fallado sudo {n} veces", e, n)

    def _usuarios_ip(self, ip, us):
        d = self.ventanas[("spray", ip)]
        t = time.time()
        d.append((t, us))
        while d and t - d[0][0] > 300:
            d.popleft()
        return [u for _, u in d]


# --------------------------------------------------------------------------- #
#  Normalizacion de cada fuente
# --------------------------------------------------------------------------- #
RE_FAIL = re.compile(r"Failed password for (invalid user )?(\S+) from ([\d.]+)")
RE_OK = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
RE_INV = re.compile(r"Invalid user (\S+) from ([\d.]+)")
RE_SUDO = re.compile(r"sudo: +(\S+) : .*(incorrect password attempts|authentication failure)")
WIN_TIPOS = {4624: ("Inicio de sesion correcto", "INFO"), 4625: ("Inicio de sesion fallido", "BAJA"),
             4720: ("Usuario creado", "BAJA"), 4726: ("Usuario eliminado", "BAJA"),
             4728: ("Miembro anadido a grupo global de seguridad", "MEDIA"),
             4732: ("Miembro anadido a grupo local de seguridad", "MEDIA"),
             4756: ("Miembro anadido a grupo universal", "MEDIA"),
             4740: ("Cuenta bloqueada", "MEDIA"), 1102: ("Log de seguridad borrado", "ALTA")}


def ev(host, fuente, tipo, sev, mensaje, ip="", usuario="", ts=None):
    return {"ts": ts or ahora(), "host": host, "fuente": fuente, "tipo": tipo,
            "severidad": sev, "ip": ip, "usuario": usuario, "mensaje": mensaje}


def norm_auth(linea, host):
    m = RE_FAIL.search(linea)
    if m:
        return ev(host, "sshd", "ssh_fallo", "BAJA", f"Contrasena fallida para {m.group(2)}", m.group(3), m.group(2))
    m = RE_INV.search(linea)
    if m:
        return ev(host, "sshd", "ssh_usuario_invalido", "BAJA", f"Usuario inexistente {m.group(1)}", m.group(2), m.group(1))
    m = RE_OK.search(linea)
    if m:
        return ev(host, "sshd", "ssh_login_ok", "INFO", f"Login correcto de {m.group(1)}", m.group(2), m.group(1))
    m = RE_SUDO.search(linea)
    if m:
        return ev(host, "sudo", "sudo_fallo", "BAJA", "sudo con contrasena incorrecta", "", m.group(1))
    return None


def norm_syslog(datos, ip_origen):
    txt = datos.decode("utf-8", "replace").strip()
    txt = re.sub(r"^<\d+>", "", txt)
    partes = txt.split()
    host = ip_origen
    if len(partes) > 4 and re.match(r"\w{3}$", partes[0]):
        host = partes[3]
    e = norm_auth(txt, host)
    if e:
        e["fuente"] = "syslog/" + e["fuente"]
        return e
    sev = "MEDIA" if re.search(r"nmap|scan|hydra|ataque|attack", txt, re.I) else "INFO"
    tipo = "syslog_actividad_ofensiva" if sev == "MEDIA" else "syslog"
    return ev(host, "syslog", tipo, sev, txt[-300:], ip_origen)


def norm_windows(d):
    eid = int(d.get("Id", 0))
    nombre, sev = WIN_TIPOS.get(eid, (f"Evento {eid}", "INFO"))
    us = d.get("Usuario") or ""
    msg = nombre
    if d.get("Grupo"):
        msg = f"{d.get('Miembro') or us} anadido al grupo {d['Grupo']} por {d.get('Autor', '?')}"
    elif eid == 4720:
        msg = f"Usuario {us} creado por {d.get('Autor', '?')}"
    elif eid in (4624, 4625):
        msg = f"{nombre}: {us} (tipo {d.get('TipoLogon', '?')})"
    return ev(d.get("Equipo", "windows"), "windows", f"win_{eid}", sev, msg,
              d.get("Ip", "") if d.get("Ip") not in ("-", "::1", "127.0.0.1") else "", us, d.get("Hora"))


# --------------------------------------------------------------------------- #
#  Colectores
# --------------------------------------------------------------------------- #
class Siem:
    def __init__(self, db, token):
        self.al = Almacen(db)
        self.motor = Motor(self.al)
        self.token = token
        self.host = socket.gethostname()
        self.n = 0

    def ingerir(self, e):
        if not e:
            return
        self.al.evento(e)
        self.n += 1
        self.motor.evaluar(e)

    def seguir(self, ruta, fn, nombre):
        """tail -F de un fichero, recordando por donde iba."""
        # La primera vez empieza por el final: el historico antiguo no es un ataque en curso
        c = self.al.cursor(nombre)
        pos = int(c) if c is not None else (os.path.getsize(ruta) if os.path.exists(ruta) else 0)
        while True:
            try:
                tam = os.path.getsize(ruta)
                if tam < pos:
                    pos = 0
                if tam > pos:
                    with open(ruta, "r", errors="replace") as f:
                        f.seek(pos)
                        for linea in f:
                            self.ingerir(fn(linea))
                        pos = f.tell()
                    self.al.cursor(nombre, pos)
            except OSError:
                pass
            time.sleep(1)

    def guard(self, linea):
        try:
            d = json.loads(linea)
        except ValueError:
            return None
        acc = (d.get("accion") or d.get("nivel") or "").upper()
        ip = d.get("ip", "")
        if "BLOQ" in acc:
            return ev(self.host, "ssh-guard", "ipsguard_bloqueo", "MEDIA", f"Bloqueo de {ip}", ip)
        return ev(self.host, "ssh-guard", "ipsguard_" + (acc.lower() or "evento"), "BAJA",
                  f"{acc} {ip}".strip(), ip)

    def dns(self, ruta="/var/lib/akram-dnshield/dnshield.db"):
        c = self.al.cursor("dns")
        if c is None:                      # primera vez: solo lo nuevo
            try:
                c = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True).execute("SELECT MAX(rowid) FROM registro").fetchone()[0] or 0
            except sqlite3.Error:
                c = 0
        ultimo = int(c)
        while True:
            try:
                c = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True)
                filas = c.execute("SELECT rowid,ts,cliente,dominio,tipo,accion FROM registro WHERE rowid>? "
                                  "ORDER BY rowid", (ultimo,)).fetchall()
                c.close()
                for rid, ts, cli, dom, tipo, acc in filas:
                    if acc == "BLOQUEADO":
                        self.ingerir(ev(self.host, "dnshield", "dns_bloqueado", "BAJA", f"{dom} ({tipo})", cli, ts=ts))
                    else:
                        self.ingerir(ev(self.host, "dnshield", "dns_consulta", "INFO", f"{dom} ({tipo})", cli, ts=ts))
                    ultimo = rid
                if filas:
                    self.al.cursor("dns", ultimo)
            except sqlite3.Error:
                pass
            time.sleep(2)

    def docker(self, ruta="/var/lib/akram-siem/dockaudit.json"):
        visto = self.al.cursor("docker") or ""
        while True:
            try:
                m = str(os.path.getmtime(ruta))
                if m != visto:
                    d = json.load(open(ruta))
                    for h in d.get("hallazgos", []):
                        self.ingerir(ev(self.host, "dockaudit", "docker_hallazgo", h["gravedad"],
                                        f"{h['ambito']} {h['control']} (CIS {h['cis']})"))
                    visto = m
                    self.al.cursor("docker", m)
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(15)

    def syslog(self, puerto=514):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", puerto))
        while True:
            datos, (ip, _) = s.recvfrom(8192)
            self.ingerir(norm_syslog(datos, ip))

    # ---- API web y panel ---------------------------------------------------
    def resumen(self):
        q = self.al.consulta
        desde = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
        linea = (datetime.now() - timedelta(minutes=60)).isoformat(timespec="seconds")
        por_min = collections.Counter(r[0][11:16] for r in q("SELECT ts FROM eventos WHERE ts>=?", (linea,)))
        al_min = collections.Counter(r[0][11:16] for r in q("SELECT ts FROM alertas WHERE ts>=?", (linea,)))
        minutos = [(datetime.now() - timedelta(minutes=i)).strftime("%H:%M") for i in range(59, -1, -1)]
        return {
            "generado": ahora(), "host": self.host,
            "totales": {"eventos": q("SELECT COUNT(*) FROM eventos")[0][0],
                        "alertas": q("SELECT COUNT(*) FROM alertas")[0][0],
                        "eventos24": q("SELECT COUNT(*) FROM eventos WHERE ts>=?", (desde,))[0][0],
                        "fuentes": q("SELECT COUNT(DISTINCT fuente) FROM eventos")[0][0],
                        "equipos": q("SELECT COUNT(DISTINCT host) FROM eventos")[0][0]},
            "severidad": dict(q("SELECT severidad,COUNT(*) FROM alertas GROUP BY severidad")),
            "fuentes": q("SELECT fuente,COUNT(*) FROM eventos GROUP BY fuente ORDER BY 2 DESC"),
            "equipos": q("SELECT host,COUNT(*) FROM eventos GROUP BY host ORDER BY 2 DESC"),
            "ips": q("SELECT ip,COUNT(*) FROM alertas WHERE ip!='' GROUP BY ip ORDER BY 2 DESC LIMIT 6"),
            "mitre": q("SELECT mitre,regla,COUNT(*) FROM alertas GROUP BY mitre,regla ORDER BY 3 DESC LIMIT 10"),
            "linea": [[m, por_min.get(m, 0), al_min.get(m, 0)] for m in minutos],
            "alertas": q("SELECT ts,severidad,regla,mitre,ip,usuario,host,descripcion FROM alertas "
                         "ORDER BY id DESC LIMIT 40"),
            "eventos": q("SELECT ts,host,fuente,severidad,ip,usuario,mensaje FROM eventos "
                         "ORDER BY id DESC LIMIT 40"),
        }

    def web(self, puerto):
        siem = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _env(self, codigo, cuerpo, tipo="application/json"):
                b = cuerpo if isinstance(cuerpo, bytes) else cuerpo.encode()
                self.send_response(codigo)
                self.send_header("Content-Type", tipo + "; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    try:
                        self._env(200, open(PANEL, "rb").read(), "text/html")
                    except OSError:
                        self._env(500, "falta panel.html", "text/plain")
                elif self.path == "/api/resumen":
                    self._env(200, json.dumps(siem.resumen(), ensure_ascii=False))
                else:
                    self._env(404, '{"error":"no existe"}')

            def do_POST(self):
                if self.path != "/api/ingest":
                    return self._env(404, '{"error":"no existe"}')
                if self.headers.get("X-Akram-Token") != siem.token:
                    return self._env(401, '{"error":"token incorrecto"}')
                try:
                    largo = min(int(self.headers.get("Content-Length", 0)), 2_000_000)
                    datos = json.loads(self.rfile.read(largo) or b"[]")
                    if isinstance(datos, dict):
                        datos = [datos]
                    for d in datos:
                        siem.ingerir(norm_windows(d))
                    self._env(200, json.dumps({"recibidos": len(datos)}))
                except (ValueError, TypeError) as ex:
                    self._env(400, json.dumps({"error": str(ex)}))

        ThreadingHTTPServer(("0.0.0.0", puerto), H).serve_forever()


def resumen_consola(db):
    s = Siem.__new__(Siem)
    s.al = Almacen(db)
    s.host = socket.gethostname()
    r = s.resumen()
    t = r["totales"]
    print(f"{AZUL}AKRAM-SIEM · [Akram El Mazzoudi] · {r['host']} · {r['generado']}{NC}")
    print(f"  {t['eventos']} eventos de {t['equipos']} equipos y {t['fuentes']} fuentes · {t['alertas']} alertas")
    print("  " + "  ".join(f"{COL[k]}{k} {r['severidad'].get(k, 0)}{NC}" for k in ("CRITICA", "ALTA", "MEDIA", "BAJA")))
    print(f"\n  {AZUL}Eventos por fuente:{NC}  " + "  ".join(f"{f} {n}" for f, n in r["fuentes"]))
    print(f"\n  {AZUL}Ultimas alertas:{NC}")
    for ts, sev, regla, mitre, ip, us, host, desc in r["alertas"][:14]:
        print(f"   {GRIS}{ts[11:]}{NC} {COL[sev]}{sev:<7}{NC} {regla:<32.32} {GRIS}{mitre:<10.10}{NC} {desc[:58]}")


def main():
    ap = argparse.ArgumentParser(description="AKRAM-SIEM - Akram El Mazzoudi Zarrouk")
    ap.add_argument("--db", default=DB)
    ap.add_argument("--web", type=int, default=8443, help="puerto del panel y la API")
    ap.add_argument("--syslog", type=int, default=514)
    ap.add_argument("--resumen", action="store_true", help="mostrar el estado y salir")
    a = ap.parse_args()
    if a.resumen:
        return resumen_consola(a.db)
    token = open(CONF).read().strip()
    s = Siem(a.db, token)
    print(f"{AZUL}AKRAM-SIEM · [Akram El Mazzoudi] · panel en :{a.web} · syslog en :{a.syslog}/udp{NC}", flush=True)
    hilos = [
        (s.seguir, ("/var/log/auth.log", lambda l: norm_auth(l, s.host), "auth")),
        (s.seguir, ("/var/log/akram-ssh-guard.json", s.guard, "guard")),
        (s.dns, ()), (s.docker, ()), (s.syslog, (a.syslog,)),
    ]
    for fn, args in hilos:
        threading.Thread(target=fn, args=args, daemon=True).start()
    s.web(a.web)


if __name__ == "__main__":
    main()
