#!/usr/bin/env python3
"""
================================================================================
DDoS / HTTP & TCP Load Testing Script for Fail2Ban Protected Environments
================================================================================
This script allows simulating controlled Denial of Service (DoS / DDoS) attacks
against HTTP/HTTPS services and raw TCP ports (such as LDAP TLS on port 636).

It supports customizing the host, port, path, concurrency, request rate, and duration
via command line arguments or environment variables.
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
    """Controls aggregate maximum requests per second across all worker threads."""

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
    Executes an HTTP/HTTPS request and returns its status code and latency.
    Returns '000' in case of connection failure / timeout / Fail2Ban iptables ban.
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
    Performs a direct TCP/TLS socket connection to test ports like 636 (LDAPS/TLS).
    Returns '200' if connection succeeded, or '000' if rejected/blocked.
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
    """Worker thread sending requests continuously until the deadline."""
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
    """Prints real-time or final load test summary report."""
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
        print(f"📊 FINAL LOAD TEST REPORT: {target_display}")
        print("=" * 70)
        print(f"  • Elapsed time:           {elapsed:.2f} s")
        print(f"  • Total requests:         {total}")
        print(f"  • Actual rate achieved:   {actual_rps:.2f} req/s")
        print(f"  • Average latency:        {avg_lat:.2f} ms")
        print("-" * 70)
        print("  RESPONSE BREAKDOWN:")
        print(f"    [200/201 OK / Connected]       : {ok} ({ok * 100 // max(1, total)}%)")
        if unauth > 0:
            print(f"    [401/403 Auth / Forbidden]     : {unauth} ({unauth * 100 // max(1, total)}%)")
        if server_err > 0:
            print(f"    [5xx Server Error]             : {server_err} ({server_err * 100 // max(1, total)}%)")
        if blocked_dropped > 0:
            print(f"    [000 Blocked / Dropped / Ban]  : {blocked_dropped} ({blocked_dropped * 100 // max(1, total)}%)")
            print(f"    ⚠️  Status '000' indicates Fail2Ban / Firewall active intervention.")
        if other > 0:
            print(f"    [Other HTTP codes]             : {other}")
        print("=" * 70)

        # Security evaluation
        if blocked_dropped > 0 and ok > 0:
            print("🛡️  PROTECTION STATUS: [ACTIVE] Fail2Ban detected the flood and banned the attacker via iptables.")
        elif blocked_dropped == total:
            print("🚫 STATUS: Host unreachable or IP was previously banned.")
        elif server_err > (total * 0.3):
            print("🔥 STATUS: [OVERLOADED] Service experienced high failure rate without active mitigation.")
        else:
            print("✅ STATUS: [HEALTHY] Service tolerated load within tested boundaries.")
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
    schema = "https" if mode == "https" else "http"
    target_url = f"{schema}://{host}:{port}{path}"
    target_display = f"{target_url} (Mode: {mode.upper()})"

    print(f"\n🚀 Starting load test against: {target_display}")
    print(f"   Config: {concurrency} workers | Limit {requests_per_second} req/s | Duration: {duration}s")
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
            print("\n⚠️ Interrupted by user (Ctrl+C). Terminating workers...", flush=True)
        finally:
            stop_event.set()

        for future in futures:
            future.result()

    elapsed = time.monotonic() - start_time
    with stats_lock:
        print_report(target_display, counts, latencies, elapsed, final=True)

    return not interrupted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DDoS & Load Tester with support for Fail2Ban, HTTP, HTTPS, and TCP/TLS ports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
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
        help="Target host or IP address (default: 127.0.0.1 or $TARGET_HOST)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=int(os.getenv("TARGET_PORT", "80")),
        help="Target port (default: 80 or $TARGET_PORT)",
    )
    parser.add_argument(
        "-t", "--path",
        type=str,
        default=os.getenv("TARGET_PATH", "/"),
        help="HTTP route / URL path (default: / or $TARGET_PATH)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=int(os.getenv("CONCURRENCY", "40")),
        help="Number of concurrent worker threads (default: 40, max: 1000)",
    )
    parser.add_argument(
        "-r", "--rps", "--requests-per-second",
        dest="rps",
        type=int,
        default=int(os.getenv("REQUESTS_PER_SECOND", "50")),
        help="Maximum aggregate requests per second (default: 50, max: 2000)",
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=int(os.getenv("DURATION", "20")),
        help="Test duration in seconds (default: 20, max: 600)",
    )
    parser.add_argument(
        "-m", "--method",
        type=str,
        default="GET",
        choices=["GET", "POST", "HEAD", "PUT", "DELETE"],
        help="HTTP method to use (default: GET)",
    )
    parser.add_argument(
        "--data",
        type=str,
        default=None,
        help="JSON payload string to send in POST/PUT requests",
    )
    parser.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS instead of HTTP",
    )
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Perform raw TCP socket probe (for non-HTTP ports)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Perform direct TLS/SSL socket probe (e.g. port 636 LDAPS)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

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
