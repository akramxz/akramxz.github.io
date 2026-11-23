#!/usr/bin/env python3
# =============================================================================
#  akram-portscan.py · Escáner de puertos TCP asíncrono
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: Simple Port Scanner · Laboratorio AKRAM-LAB
#
#  Escaneo por conexión completa (TCP connect) con asyncio: no necesita root
#  y lanza miles de conexiones a la vez, limitadas por un semáforo.
#  Clasifica cada puerto como:
#     abierto   -> la conexión se completa (SYN, SYN-ACK, ACK)
#     cerrado   -> el equipo responde con RST (ConnectionRefusedError)
#     filtrado  -> no hay respuesta antes del timeout (un cortafuegos descarta)
#  En los puertos abiertos intenta leer el banner del servicio.
#
#  Uso:  akram-portscan.py 10.66.0.10                 (puertos 1-1024)
#        akram-portscan.py 10.66.0.10 -p 1-65535 -c 300 -t 1.5
#        akram-portscan.py 10.66.0.10 -p 22,80,443 --json resultado.json
# =============================================================================
import argparse
import asyncio
import ipaddress
import json
import resource
import socket
import sys
import time
from datetime import datetime

AZUL, VERDE, ROJO, GRIS, AMARILLO, NC = "\033[1;36m", "\033[1;32m", "\033[1;31m", "\033[0;90m", "\033[1;33m", "\033[0m"

# Algunos servicios solo hablan si se les pregunta primero.
SONDAS = {
    80: b"HEAD / HTTP/1.0\r\n\r\n", 8080: b"HEAD / HTTP/1.0\r\n\r\n", 8000: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"PING\r\n",
}


def parsear_puertos(texto):
    puertos = set()
    for trozo in texto.split(","):
        trozo = trozo.strip()
        if "-" in trozo:
            a, b = trozo.split("-", 1)
            puertos.update(range(int(a), int(b) + 1))
        elif trozo:
            puertos.add(int(trozo))
    validos = sorted(p for p in puertos if 1 <= p <= 65535)
    if not validos:
        raise argparse.ArgumentTypeError("no hay puertos válidos")
    return validos


def servicio(puerto):
    try:
        return socket.getservbyport(puerto, "tcp")
    except OSError:
        return "?"


async def leer_banner(lector, escritor, puerto, espera):
    try:
        if puerto in SONDAS:
            escritor.write(SONDAS[puerto])
            await escritor.drain()
        datos = await asyncio.wait_for(lector.read(120), timeout=espera)
        linea = datos.decode(errors="replace").strip().splitlines()
        return linea[0][:60] if linea else ""
    except (asyncio.TimeoutError, OSError):
        return ""


async def probar(host, puerto, timeout, semaforo, banner):
    async with semaforo:
        inicio = time.perf_counter()
        try:
            lector, escritor = await asyncio.wait_for(asyncio.open_connection(host, puerto), timeout=timeout)
        except asyncio.TimeoutError:
            return puerto, "filtrado", "", None
        except ConnectionRefusedError:
            return puerto, "cerrado", "", round((time.perf_counter() - inicio) * 1000, 1)
        except OSError as e:
            if e.errno == 24:          # EMFILE: problema local, no del objetivo
                raise
            return puerto, "filtrado", str(e.strerror or e), None
        rtt = round((time.perf_counter() - inicio) * 1000, 1)
        sock = escritor.get_extra_info("socket")
        if sock is not None and sock.getsockname() == sock.getpeername():
            # Autoconexión TCP: al escanear localhost, el puerto de origen que elige el
            # sistema puede coincidir con el de destino y el socket se conecta consigo mismo.
            escritor.close()
            return puerto, "cerrado", "autoconexión", rtt
        texto = await leer_banner(lector, escritor, puerto, 1.5) if banner else ""
        escritor.close()
        try:
            await escritor.wait_closed()
        except OSError:
            pass
        return puerto, "abierto", texto, rtt


async def vigilar_bucle(estado):
    """Mide cuánto se retrasa el bucle de eventos. Si se retrasa más que el timeout,
    un puerto abierto puede acabar marcado como filtrado por culpa de mi propia carga."""
    bucle = asyncio.get_running_loop()
    while True:
        t = bucle.time()
        await asyncio.sleep(0.1)
        estado["retardo_max"] = max(estado["retardo_max"], bucle.time() - t - 0.1)


async def escanear(host, puertos, concurrencia, timeout, banner, progreso, estado):
    vigia = asyncio.create_task(vigilar_bucle(estado))
    semaforo = asyncio.Semaphore(concurrencia)
    tareas = [asyncio.create_task(probar(host, p, timeout, semaforo, banner)) for p in puertos]
    resultados = []
    hechas = 0
    for futura in asyncio.as_completed(tareas):
        resultados.append(await futura)
        hechas += 1
        if progreso and (hechas % 500 == 0 or hechas == len(tareas)):
            print(f"\r{GRIS}  progreso: {hechas}/{len(tareas)} puertos{NC}", end="", file=sys.stderr, flush=True)
    if progreso:
        print(file=sys.stderr)
    # Segunda pasada: si hay pocos filtrados, los vuelvo a probar con calma.
    # (Con miles de filtrados es un cortafuegos con DROP y repetirlos solo cuesta tiempo.)
    filtrados = [r[0] for r in resultados if r[1] == "filtrado"]
    if 0 < len(filtrados) <= 2000:
        sem2 = asyncio.Semaphore(min(100, concurrencia))
        segunda = await asyncio.gather(*(probar(host, p, timeout * 2, sem2, banner) for p in filtrados))
        nuevos = {r[0]: r for r in segunda}
        estado["recuperados"] = sum(1 for r in segunda if r[1] != "filtrado")
        resultados = [nuevos.get(r[0], r) for r in resultados]
    vigia.cancel()
    return sorted(resultados)


def main():
    ap = argparse.ArgumentParser(description="Escáner TCP asíncrono · Akram El Mazzoudi Zarrouk")
    ap.add_argument("objetivo", help="IP o nombre del equipo")
    ap.add_argument("-p", "--puertos", type=parsear_puertos, default=parsear_puertos("1-1024"))
    ap.add_argument("-c", "--concurrencia", type=int, default=300, help="conexiones simultáneas (300)")
    ap.add_argument("-t", "--timeout", type=float, default=1.5, help="segundos antes de dar un puerto por filtrado (1.5)")
    ap.add_argument("--sin-banner", action="store_true", help="no leer banners")
    ap.add_argument("--todos", action="store_true", help="mostrar también cerrados y filtrados")
    ap.add_argument("--json", metavar="FICHERO", help="guardar el resultado en JSON")
    a = ap.parse_args()

    # Cada conexión abierta consume un descriptor de fichero. Si se agotan, el error
    # (EMFILE) se confundiría con un puerto filtrado, así que subo el límite y ajusto.
    blando, duro = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (duro, duro))
        blando = duro
    except (ValueError, OSError):
        pass
    if a.concurrencia > blando - 64:
        a.concurrencia = max(16, blando - 64)
        print(f"{GRIS}  concurrencia ajustada a {a.concurrencia} por el límite de descriptores{NC}")

    try:
        ip = str(ipaddress.ip_address(a.objetivo))
    except ValueError:
        ip = socket.gethostbyname(a.objetivo)

    print(f"{AZUL}akram-portscan · [Akram El Mazzoudi] · {socket.gethostname()} -> {ip}{NC}")
    print(f"{GRIS}  {len(a.puertos)} puertos · concurrencia {a.concurrencia} · timeout {a.timeout}s · "
          f"{datetime.now():%d/%m/%Y %H:%M:%S}{NC}")
    t0 = time.perf_counter()
    estado = {"retardo_max": 0.0, "recuperados": 0}
    res = asyncio.run(escanear(ip, a.puertos, a.concurrencia, a.timeout, not a.sin_banner, sys.stderr.isatty(), estado))
    dur = time.perf_counter() - t0

    cuenta = {"abierto": 0, "cerrado": 0, "filtrado": 0}
    for _, est, _, _ in res:
        cuenta[est] += 1
    print(f"\n  {'PUERTO':<10}{'ESTADO':<10}{'SERVICIO':<14}{'RTT ms':<8}BANNER")
    for p, est, ban, rtt in res:
        if est != "abierto" and not a.todos:
            continue
        color = {"abierto": VERDE, "cerrado": ROJO, "filtrado": AMARILLO}[est]
        print(f"  {str(p)+'/tcp':<10}{color}{est:<10}{NC}{servicio(p):<14}{str(rtt or '-'):<8}{ban}")
    print(f"\n  {VERDE}{cuenta['abierto']} abiertos{NC} · {ROJO}{cuenta['cerrado']} cerrados{NC} · "
          f"{AMARILLO}{cuenta['filtrado']} filtrados{NC} · {len(res)} puertos en {dur:.1f} s "
          f"({len(res)/dur:,.0f} puertos/s)".replace(",", "."))
    lag = estado["retardo_max"]
    aviso = f" {AMARILLO}<- por encima del timeout: baja la concurrencia{NC}" if lag > a.timeout else ""
    print(f"  {GRIS}retardo máximo del bucle: {lag*1000:.0f} ms · recuperados en 2.ª pasada: {estado['recuperados']}{NC}{aviso}")

    if a.json:
        with open(a.json, "w") as f:
            json.dump({"autor": "Akram El Mazzoudi Zarrouk", "herramienta": "akram-portscan",
                       "origen": socket.gethostname(), "objetivo": ip, "fecha": datetime.now().isoformat(timespec="seconds"),
                       "duracion_s": round(dur, 2), "resumen": cuenta,
                       "retardo_max_bucle_ms": round(estado["retardo_max"] * 1000), "recuperados_2a_pasada": estado["recuperados"],
                       "puertos": [{"puerto": p, "estado": e, "servicio": servicio(p), "banner": b, "rtt_ms": r}
                                   for p, e, b, r in res if e == "abierto" or a.todos]},
                      f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
