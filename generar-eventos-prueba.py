#!/usr/bin/env python3
# =============================================================================
#  generar-eventos-prueba.py - Banco de pruebas de AKRAM-SIEM
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: SIEM final - Laboratorio AKRAM-LAB
#
#  Alimenta el SIEM con eventos de PRUEBA (no es ningun ataque real: son
#  registros sinteticos, etiquetados como laboratorio, enviados por las mismas
#  vias que usarian las maquinas de verdad). Sirve para comprobar que el motor
#  de correlacion detecta y encadena, sin lanzar herramientas ofensivas.
#
#  Reproduce un incidente de ejemplo visto desde los logs:
#     1. Rafaga de "Failed password" de SSH (sshd de SRV01)      T1110.001
#     2. Consulta DNS a un dominio de malware de ejemplo          T1071.004
#     3. Varios eventos 4625 del dominio con la misma clave       T1110.003
#        contra cuentas distintas (password spraying)
#     4. Rafaga de 4625 contra una cuenta -> 4740 (bloqueo)       T1110 / 4740
#  La misma IP origen encadena varias reglas, asi que el SIEM debe elevarlo a
#  un incidente CRITICO multi-fuente.
#
#  Uso:  python3 generar-eventos-prueba.py --siem 10.66.0.10 --token <TOKEN>
# =============================================================================
import argparse
import json
import socket
import time
import urllib.request
from datetime import datetime

ORIGEN = "10.66.0.50"       # Kali, el equipo "atacante" del laboratorio
DC = "DC01-AKRAM"


def syslog(host, puerto, texto):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(f"<38>{datetime.now():%b %d %H:%M:%S} {ORIGEN} {texto}".encode(), (host, puerto))
    s.close()


def ingest(url, token, eventos):
    datos = json.dumps(eventos).encode()
    pet = urllib.request.Request(url, data=datos,
                                 headers={"X-Akram-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(pet, timeout=10) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser(description="Banco de pruebas de AKRAM-SIEM - Akram El Mazzoudi Zarrouk")
    ap.add_argument("--siem", default="10.66.0.10")
    ap.add_argument("--token", required=True)
    ap.add_argument("--syslog", type=int, default=514)
    ap.add_argument("--web", type=int, default=8443)
    a = ap.parse_args()
    url = f"http://{a.siem}:{a.web}/api/ingest"
    print(f"AKRAM-SIEM · banco de pruebas · [Akram El Mazzoudi] · objetivo {a.siem}")

    print("  Fase 1/4 · rafaga de fallos SSH (syslog)")
    for i in range(8):
        syslog(a.siem, a.syslog, f"sshd[2001]: Failed password for root from {ORIGEN} port {40000+i} ssh2")
        time.sleep(0.05)
    for u in ("admin", "test", "oracle", "git"):
        syslog(a.siem, a.syslog, f"sshd[2001]: Invalid user {u} from {ORIGEN}")

    time.sleep(1)
    print("  Fase 2/4 · consulta a dominio de malware de ejemplo")
    # Lo registra el propio DNS; aqui lo mandamos como evento ya normalizado por syslog
    syslog(a.siem, a.syslog, f"dnshield: BLOQUEADO malware-ejemplo-akramlab.com desde {ORIGEN}")

    time.sleep(1)
    print("  Fase 3/4 · password spraying contra el dominio (eventos 4625)")
    cuentas = ["laura.martinez", "javier.ortega", "sergio.ruiz", "ana.garcia", "carla.fernandez", "elena.torres"]
    lote = [{"Id": 4625, "Hora": datetime.now().isoformat(timespec="seconds"),
             "Equipo": DC, "Usuario": u, "Ip": ORIGEN, "TipoLogon": 3} for u in cuentas]
    print("   ", ingest(url, a.token, lote))

    time.sleep(1)
    print("  Fase 4/4 · fuerza bruta contra pablo.serrano -> bloqueo de cuenta")
    lote = [{"Id": 4625, "Hora": datetime.now().isoformat(timespec="seconds"),
             "Equipo": DC, "Usuario": "pablo.serrano", "Ip": ORIGEN, "TipoLogon": 3} for _ in range(6)]
    lote.append({"Id": 4740, "Hora": datetime.now().isoformat(timespec="seconds"),
                 "Equipo": DC, "Usuario": "pablo.serrano", "Autor": DC})
    print("   ", ingest(url, a.token, lote))

    print("\n  Hecho. La misma IP ha encadenado SSH + DNS + dominio: el SIEM debe marcar un incidente CRITICO.")


if __name__ == "__main__":
    main()
