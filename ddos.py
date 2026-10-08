#!/usr/bin/env python3
"""
================================================================================
DDoS / HTTP & TCP Load Testing Script for Fail2Ban Protected Environments
================================================================================
Este script permite simular ataques de denegación de servicio (DoS / DDoS)
controlados contra servicios HTTP/HTTPS y puertos TCP (como LDAP TLS en el puerto 636).

Permite parametrizar el host, puerto, ruta, concurrencia, tasa de peticiones y duración
mediante argumentos de línea de comandos o variables de entorno.
================================================================================
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

REQUEST_TIMEOUT_SECONDS = 2
REPORT_INTERVAL_SECONDS = 3
MAX_DURATION_SECONDS = 600
MAX_CONCURRENCY = 1000
MAX_REQUESTS_PER_SECOND = 2000


class RateLimiter:
    """Controla la tasa máxima de peticiones por segundo en todos los hilos."""

    def __init__(self, requests_per_second: int) -> None:
        self.interval = 1.0 / max(1, requests_per_second)
        self.next_request_at = 0.0
        self.lock = threading.Lock()

    def wait_for_turn(self, stop_event: threading.Event) -> bool:
        with self.lock:
            now = time.monotonic()
            scheduled_at = max(now, self.next_request_at)
            self.next_request_at = scheduled_at + self.interval
        delay = max(0.0, scheduled_at - now)
        return not stop_event.wait(delay)


def http_request_status(
    opener: urllib.request.OpenerDirector,
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict | None = None,
) -> tuple[str, float]:
    """
    Ejecuta una petición HTTP/HTTPS y retorna su código de estado y latencia.
    Retorna '000' en caso de error de conexión / timeout / bloqueo por Fail2Ban (iptables).
    """
    req_headers = {"User-Agent": "DDoS-Stress-Tester/2.0"}
    if headers:
        req_headers.update(headers)
    
    if data and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    start_time = time.monotonic()

    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            latency = time.monotonic() - start_time
            return str(response.status), latency
    except urllib.error.HTTPError as error:
        latency = time.monotonic() - start_time
        return str(error.code), latency
    except (urllib.error.URLError, TimeoutError, OSError, ConnectionResetError):
        latency = time.monotonic() - start_time
        return "000", latency


def tcp_probe_status(host: str, port: int, use_tls: bool = False) -> tuple[str, float]:
    """
    Realiza una conexión socket TCP/TLS directa para probar puertos como 636 (LDAPS/TLS).
    Retorna '200' si la conexión fue exitosa, o '000' si fue rechazada/bloqueada.
    """
    start_time = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(REQUEST_TIMEOUT_SECONDS)
        
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=host) as s:
                s.connect((host, port))
                latency = time.monotonic() - start_time
                return "200", latency
        else:
            sock.connect((host, port))
            sock.close()
            latency = time.monotonic() - start_time
            return "200", latency
    except Exception:
        latency = time.monotonic() - start_time
        return "000", latency


def worker(
    target_url: str,
    host: str,
    port: int,
    mode: str,
    method: str,
    data: bytes | None,
    deadline: float,
    stop_event: threading.Event,
    rate_limiter: RateLimiter,
    counts: Counter[str],
    latencies: list[float],
    stats_lock: threading.Lock,
) -> None:
    """Hilo trabajador que envía peticiones continuamente hasta el tiempo límite."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    
    while not stop_event.is_set() and time.monotonic() < deadline:
        if not rate_limiter.wait_for_turn(stop_event):
            break
        if time.monotonic() >= deadline:
            break

        if mode == "tcp":
            code, lat = tcp_probe_status(host, port, use_tls=False)
        elif mode == "tls":
            code, lat = tcp_probe_status(host, port, use_tls=True)
        else:
            code, lat = http_request_status(opener, target_url, method=method, data=data)

        with stats_lock:
            counts[code] += 1
            latencies.append(lat)


def print_report(
    target_display: str,
    counts: Counter[str],
    latencies: list[float],
    elapsed: float,
    final: bool = False,
) -> None:
    """Imprime resumen de estadísticas de carga en tiempo real o reporte final."""
    total = sum(counts.values())
    ok = counts["200"] + counts["201"]
    unauth = counts["401"] + counts["403"]
    server_err = sum(v for k, v in counts.items() if k.startswith("5"))
    blocked_dropped = counts["000"]
    other = total - ok - unauth - server_err - blocked_dropped

    avg_lat = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0
    actual_rps = total / max(0.001, elapsed)

    if final:
        print("\n" + "=" * 70)
        print(f"📊 REPORTE FINAL DE PRUEBA DE CARGA: {target_display}")
        print("=" * 70)
        print(f"  • Tiempo transcurrido:    {elapsed:.2f} s")
        print(f"  • Peticiones totales:     {total}")
        print(f"  • Tasa real alcanzada:    {actual_rps:.2f} req/s")
        print(f"  • Latencia promedio:      {avg_lat:.2f} ms")
        print("-" * 70)
        print("  DESGLOSE DE RESPUESTAS:")
        print(f"    [200/201 OK / Conectado]        : {ok} ({ok * 100 // max(1, total)}%)")
        if unauth > 0:
            print(f"    [401/403 Autenticación/Permiso] : {unauth} ({unauth * 100 // max(1, total)}%)")
        if server_err > 0:
            print(f"    [5xx Error de Servidor]         : {server_err} ({server_err * 100 // max(1, total)}%)")
        if blocked_dropped > 0:
            print(f"    [000 Bloqueado / Conexión Caída]: {blocked_dropped} ({blocked_dropped * 100 // max(1, total)}%)")
            print(f"    ⚠️  El bloqueo '000' indica que Fail2Ban / Firewall ha intervenido activamente.")
        if other > 0:
            print(f"    [Otros códigos HTTP]           : {other}")
        print("=" * 70)

        # Diagnóstico de seguridad
        if blocked_dropped > 0 and ok > 0:
            print("🛡️  ESTADO DE PROTECCIÓN: [ACTIVO] Fail2Ban detectó el flood y bloqueó al atacante con iptables.")
        elif blocked_dropped == total:
            print("🚫 ESTADO: Host inaccesible o IP previamente baneada.")
        elif server_err > (total * 0.3):
            print("🔥 ESTADO: [SERVICIO SATURADO] El servicio sufrió sobrecarga sin defensa activa.")
        else:
            print("✅ ESTADO: [ESTABLE] El servicio toleró la carga dentro de los parámetros probados.")
        print()
    else:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"  [{timestamp}] Total={total:<5} | 200_OK={ok:<5} | 000_Drop/Ban={blocked_dropped:<5} | "
            f"RPS={actual_rps:5.1f} | Lat={avg_lat:5.1f}ms",
            flush=True,
        )


def run_test(
    host: str,
    port: int,
    path: str,
    duration: int,
    concurrency: int,
    requests_per_second: int,
    mode: str,
    method: str,
    data: bytes | None,
) -> bool:
    """Ejecuta la prueba de carga con los parámetros configurados."""
    schema = "https" if mode == "https" else "http"
    target_url = f"{schema}://{host}:{port}{path}"
    target_display = f"{target_url} (Modo: {mode.upper()})"

    print(f"\n🚀 Iniciando prueba de carga contra: {target_display}")
    print(f"   Configuración: {concurrency} hilos concurrentes | Límite {requests_per_second} req/s | Duración: {duration}s")
    print("-" * 70)

    counts: Counter[str] = Counter()
    latencies: list[float] = []
    stats_lock = threading.Lock()
    stop_event = threading.Event()
    rate_limiter = RateLimiter(requests_per_second)

    start_time = time.monotonic()
    deadline = start_time + duration
    interrupted = False

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                worker,
                target_url,
                host,
                port,
                mode,
                method,
                data,
                deadline,
                stop_event,
                rate_limiter,
                counts,
                latencies,
                stats_lock,
            )
            for _ in range(concurrency)
        ]

        try:
            while time.monotonic() < deadline:
                time.sleep(min(REPORT_INTERVAL_SECONDS, max(0.1, deadline - time.monotonic())))
                with stats_lock:
                    snap_counts = counts.copy()
                    snap_lats = list(latencies)
                print_report(target_display, snap_counts, snap_lats, time.monotonic() - start_time, final=False)
        except KeyboardInterrupt:
            interrupted = True
            stop_event.set()
            print("\n⚠️ Interrupción manual detectada (Ctrl+C). Deteniendo trabajadores...", flush=True)
        finally:
            stop_event.set()

        for future in futures:
            future.result()

    elapsed = time.monotonic() - start_time
    with stats_lock:
        print_report(target_display, counts, latencies, elapsed, final=True)

    return not interrupted


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="DDoS & Load Tester con soporte para Fail2Ban, HTTP, HTTPS y puertos TCP/TLS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python ddos.py -H localhost -p 80 -c 50 -r 100 -d 15
  python ddos.py -H 127.0.0.1 -p 8000 -t /login -c 60 -r 80 -d 20
  python ddos.py -H 127.0.0.1 -p 5000 -t /api/pokemons -c 40 -r 60 -d 15
  python ddos.py -H 127.0.0.1 -p 636 --tls -c 30 -r 40 -d 10
        """,
    )
    parser.add_argument(
        "-H", "--host",
        type=str,
        default=os.getenv("TARGET_HOST", "127.0.0.1"),
        help="Host o IP objetivo a probar (default: 127.0.0.1 o $TARGET_HOST)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=int(os.getenv("TARGET_PORT", "80")),
        help="Puerto objetivo (default: 80 o $TARGET_PORT)",
    )
    parser.add_argument(
        "-t", "--path",
        type=str,
        default=os.getenv("TARGET_PATH", "/"),
        help="Ruta HTTP/URL path (default: / o $TARGET_PATH)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=int(os.getenv("CONCURRENCY", "40")),
        help="Cantidad de hilos concurrentes (default: 40, máx: 1000)",
    )
    parser.add_argument(
        "-r", "--rps", "--requests-per-second",
        dest="rps",
        type=int,
        default=int(os.getenv("REQUESTS_PER_SECOND", "50")),
        help="Tasa máxima de peticiones por segundo (default: 50, máx: 2000)",
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=int(os.getenv("DURATION", "20")),
        help="Duración de la prueba en segundos (default: 20, máx: 600)",
    )
    parser.add_argument(
        "-m", "--method",
        type=str,
        default="GET",
        choices=["GET", "POST", "HEAD", "PUT", "DELETE"],
        help="Método HTTP a utilizar (default: GET)",
    )
    parser.add_argument(
        "--data",
        type=str,
        default=None,
        help="Payload JSON para enviar en peticiones POST/PUT",
    )
    parser.add_argument(
        "--https",
        action="store_true",
        help="Utilizar HTTPS en lugar de HTTP",
    )
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Realizar prueba de socket TCP raw (para puertos no HTTP)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Realizar prueba de socket TLS/SSL directo (ej. puerto 636 LDAPS)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Validaciones
    concurrency = min(max(1, args.concurrency), MAX_CONCURRENCY)
    rps = min(max(1, args.rps), MAX_REQUESTS_PER_SECOND)
    duration = min(max(1, args.duration), MAX_DURATION_SECONDS)
    path = args.path if args.path.startswith("/") else f"/{args.path}"

    mode = "http"
    if args.tls or (args.port == 636 and not args.https):
        mode = "tls"
    elif args.tcp:
        mode = "tcp"
    elif args.https or args.port == 443:
        mode = "https"

    payload = args.data.encode("utf-8") if args.data else None

    run_test(
        host=args.host,
        port=args.port,
        path=path,
        duration=duration,
        concurrency=concurrency,
        requests_per_second=rps,
        mode=mode,
        method=args.method.upper(),
        data=payload,
    )


if __name__ == "__main__":
    main()
