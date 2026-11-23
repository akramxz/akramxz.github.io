#!/usr/bin/env python3
# =============================================================================
#  akram-dockaudit.py - Auditoria de seguridad de Docker
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: Docker Security Audit - Laboratorio AKRAM-LAB
#
#  Revisa la configuracion de seguridad de Docker sin dependencias externas:
#  consulta el demonio y cada contenedor con el propio cliente de Docker
#  (docker info / inspect en JSON) y comprueba una lista de controles
#  inspirados en el CIS Docker Benchmark. Cada hallazgo lleva su gravedad
#  (ALTA / MEDIA / BAJA), una explicacion y la referencia del CIS.
#
#  Uso:
#     sudo akram-dockaudit.py              # informe en pantalla
#     sudo akram-dockaudit.py --json a.json  # ademas, informe en JSON
#  Necesita permiso para hablar con el demonio de Docker (grupo docker o sudo).
# =============================================================================
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime

AZUL = "\033[1;36m"; VERDE = "\033[1;32m"; ROJO = "\033[1;31m"
GRIS = "\033[0;90m"; AMARILLO = "\033[1;33m"; NARANJA = "\033[1;33m"; NC = "\033[0m"
COLOR = {"ALTA": ROJO, "MEDIA": AMARILLO, "BAJA": AZUL}
ORDEN = {"ALTA": 0, "MEDIA": 1, "BAJA": 2}


def docker(*args):
    """Ejecuta el cliente de Docker y devuelve la salida (o None si falla)."""
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def djson(*args):
    salida = docker(*args)
    if salida is None:
        return None
    try:
        return json.loads(salida)
    except json.JSONDecodeError:
        return None


class Auditor:
    def __init__(self):
        self.hallazgos = []

    def apunta(self, ambito, gravedad, control, cis, detalle):
        self.hallazgos.append({"ambito": ambito, "gravedad": gravedad,
                               "control": control, "cis": cis, "detalle": detalle})

    # --- Demonio -----------------------------------------------------------
    def auditar_demonio(self):
        info = djson("info", "--format", "{{json .}}")
        if info is None:
            return
        if not info.get("LiveRestore"):
            self.apunta("demonio", "BAJA", "live-restore desactivado", "2.14",
                        "Sin live-restore, reiniciar el demonio para todos los contenedores.")
        segopts = " ".join(info.get("SecurityOptions") or [])
        if "name=seccomp" not in segopts and "seccomp" not in segopts:
            self.apunta("demonio", "MEDIA", "perfil seccomp por defecto no visible", "2.x",
                        "El demonio no reporta un perfil seccomp por defecto.")
        if "name=apparmor" not in segopts and "name=selinux" not in segopts:
            self.apunta("demonio", "MEDIA", "sin AppArmor/SELinux en el demonio", "2.x",
                        "No se detecta modulo de control de acceso obligatorio (AppArmor/SELinux).")
        if "name=userns" not in segopts:
            self.apunta("demonio", "MEDIA", "user namespace no activado", "2.8",
                        "Sin remapeo de usuarios: root dentro del contenedor es root en el host.")
        # Permisos del socket Unix
        sock = "/var/run/docker.sock"
        try:
            st = os.stat(sock)
            if st.st_mode & stat.S_IROTH or st.st_mode & stat.S_IWOTH:
                self.apunta("demonio", "ALTA", "docker.sock accesible por 'otros'", "3.15",
                            f"{sock} tiene permisos para otros; da control total del host.")
        except OSError:
            pass

    # --- Contenedores ------------------------------------------------------
    def auditar_contenedor(self, c):
        nombre = c.get("Name", "?").lstrip("/")
        hc = c.get("HostConfig", {}) or {}
        cfg = c.get("Config", {}) or {}
        et = f"[{nombre}]"

        if hc.get("Privileged"):
            self.apunta(et, "ALTA", "contenedor privilegiado", "5.4",
                        "--privileged da al contenedor casi todas las capacidades del host.")
        montados = [m.get("Source", "") for m in (c.get("Mounts") or [])]
        if any(s.endswith("docker.sock") for s in montados):
            self.apunta(et, "ALTA", "docker.sock montado dentro", "5.31",
                        "Con el socket dentro, el contenedor controla todo Docker (y el host).")
        sensibles = ("/", "/etc", "/boot", "/proc", "/sys", "/var/run", "/run")
        for m in (c.get("Mounts") or []):
            if m.get("Type") == "bind" and m.get("Source") in sensibles:
                self.apunta(et, "ALTA", f"montaje sensible del host: {m.get('Source')}", "5.x",
                            "Montar directorios del sistema del host rompe el aislamiento.")
        segopt = " ".join(hc.get("SecurityOpt") or [])
        if "seccomp=unconfined" in segopt:
            self.apunta(et, "ALTA", "seccomp desactivado (unconfined)", "5.21",
                        "Sin seccomp, el contenedor puede usar cualquier llamada al sistema.")
        if "apparmor=unconfined" in segopt or "apparmor:unconfined" in segopt:
            self.apunta(et, "ALTA", "AppArmor desactivado (unconfined)", "5.1",
                        "Sin perfil AppArmor, no hay control de acceso obligatorio.")
        if hc.get("NetworkMode") == "host":
            self.apunta(et, "MEDIA", "red del host (--net=host)", "5.9",
                        "Comparte la pila de red del host: sin aislamiento de red.")
        if hc.get("PidMode") == "host":
            self.apunta(et, "MEDIA", "espacio de PID del host (--pid=host)", "5.15",
                        "Ve y puede senalizar los procesos del host.")
        caps = hc.get("CapAdd")
        if caps:
            self.apunta(et, "MEDIA", f"capacidades anadidas: {', '.join(caps)}", "5.3",
                        "Anadir capacidades amplia lo que puede hacer el contenedor.")
        usuario = (cfg.get("User") or "").strip()
        if usuario in ("", "0", "root"):
            self.apunta(et, "MEDIA", "se ejecuta como root", "4.1",
                        "Sin USER, el proceso corre como root dentro del contenedor.")
        if "no-new-privileges=true" not in segopt and "no-new-privileges:true" not in segopt:
            self.apunta(et, "MEDIA", "falta no-new-privileges", "5.25",
                        "Sin no-new-privileges, un binario setuid puede escalar privilegios.")
        if not hc.get("ReadonlyRootfs"):
            self.apunta(et, "BAJA", "sistema de ficheros raiz escribible", "5.12",
                        "Con el rootfs escribible, un atacante puede modificar el contenedor.")
        if not hc.get("Memory"):
            self.apunta(et, "BAJA", "sin limite de memoria", "5.10",
                        "Sin limite, un contenedor puede agotar la memoria del host.")
        if not hc.get("CpuShares") and not hc.get("NanoCpus") and not hc.get("CpuQuota"):
            self.apunta(et, "BAJA", "sin limite de CPU", "5.11",
                        "Sin limite, un contenedor puede acaparar la CPU del host.")
        if cfg.get("Healthcheck") is None and not c.get("State", {}).get("Health"):
            self.apunta(et, "BAJA", "sin healthcheck", "5.26",
                        "Sin healthcheck, Docker no sabe si la aplicacion esta sana.")

    # --- Imagenes ----------------------------------------------------------
    def auditar_imagenes(self):
        salida = docker("ps", "--format", "{{.Image}}")
        if not salida:
            return
        for img in {x for x in salida.split() if x}:
            if ":" not in img or img.endswith(":latest"):
                self.apunta("imagenes", "BAJA", f"imagen sin version fijada: {img}", "4.x",
                            "Usar 'latest' hace que no sepas que version corre realmente.")

    # --- Ejecutar ----------------------------------------------------------
    def ejecutar(self):
        self.auditar_demonio()
        ids = (docker("ps", "-q") or "").split()
        contenedores = []
        for cid in ids:
            info = djson("inspect", cid)
            if info:
                contenedores.append(info[0])
                self.auditar_contenedor(info[0])
        self.auditar_imagenes()
        return len(ids)


def informe(aud, n_cont):
    h = sorted(aud.hallazgos, key=lambda x: (0 if x["ambito"].startswith("[") else 1, x["ambito"], ORDEN[x["gravedad"]]))
    cuenta = {g: sum(1 for x in h if x["gravedad"] == g) for g in ("ALTA", "MEDIA", "BAJA")}
    print(f"{AZUL}Auditoria de seguridad de Docker - [Akram El Mazzoudi] - {datetime.now():%d/%m/%Y %H:%M}{NC}")
    print(f"{GRIS}  {n_cont} contenedores en marcha   "
          f"{ROJO}{cuenta['ALTA']} altas{NC}  {AMARILLO}{cuenta['MEDIA']} medias{NC}  "
          f"{AZUL}{cuenta['BAJA']} bajas{NC}\n")
    ambito_actual = None
    for x in h:
        if x["ambito"] != ambito_actual:
            ambito_actual = x["ambito"]
            print(f"\n  {AZUL}{ambito_actual}{NC}")
        c = COLOR[x["gravedad"]]
        print(f"    {c}{x['gravedad']:<5}{NC} {x['control']:<42} "
              f"{GRIS}CIS {x['cis']}{NC}")
        print(f"          {GRIS}{x['detalle']}{NC}")
    if not h:
        print(f"  {VERDE}Sin hallazgos. Buen trabajo.{NC}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Auditoria de seguridad de Docker - Akram El Mazzoudi Zarrouk")
    ap.add_argument("--json", metavar="FICHERO", help="guardar el informe en JSON")
    a = ap.parse_args()

    if shutil.which("docker") is None:
        sys.exit("Docker no esta instalado o no esta en el PATH.")
    if docker("info") is None:
        sys.exit("No puedo hablar con el demonio de Docker (prueba con sudo o en el grupo docker).")

    aud = Auditor()
    n = aud.ejecutar()
    informe(aud, n)
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"autor": "Akram El Mazzoudi Zarrouk", "herramienta": "akram-dockaudit",
                       "fecha": datetime.now().isoformat(timespec="seconds"),
                       "contenedores": n, "hallazgos": aud.hallazgos}, f, ensure_ascii=False, indent=2)
        print(f"{GRIS}  Informe JSON guardado en {a.json}{NC}")


if __name__ == "__main__":
    main()
