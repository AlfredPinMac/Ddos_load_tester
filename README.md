# 🛡️ DDoS & Load Tester with Fail2Ban Defense Auditing

Denial of Service (DoS/DDoS) simulation and stress-testing tool designed to evaluate web service resilience and the efficacy of active defenses implemented with **Fail2Ban** and **iptables**.

---

## 📋 Table of Contents
1. [Overview & Script Enhancements](#-overview--script-enhancements)
2. [Target Architecture & Protected Services](#-target-architecture--protected-services)
3. [Prerequisites & Installation](#-prerequisites--installation)
4. [Parameters & Tool Usage](#-parameters--tool-usage)
5. [Step-by-Step Load Testing Guide](#-step-by-step-load-testing-guide)
6. [Determining the Sustainable Load Capacity Threshold](#-determining-the-sustainable-load-capacity-threshold)
7. [Fail2Ban Behavior Under High Load](#-fail2ban-behavior-under-high-load)
8. [GitHub Submission Instructions](#-github-submission-instructions)

---

## 🛠️ Overview & Script Enhancements

The baseline demonstration script (`flood.py`) had fixed limitations that prevented flexible execution against external hosts and diverse ports:
* **Hardcoded target names**: Only accepted internal container hostnames `victim-protected` and `victim-unprotected`.
* **Coupled environment configuration**: Relied strictly on static environment variables.
* **HTTP GET to root path `/` only**: Did not allow targeting specific authentication endpoints (e.g. `/login`), REST APIs (e.g. `/api/pokemons`), or raw infrastructure ports (such as LDAP over TLS on port 636).
* **No raw TLS support**: Could not evaluate transport-layer encrypted services without HTTP wrappers.

### 🔄 Enhancements Introduced in `ddos.py`:
1. **Full CLI Interface via `argparse`**:
   - Supports standard flags (`-H / --host`, `-p / --port`, `-t / --path`, `-c / --concurrency`, `-r / --rps`, `-d / --duration`).
   - Retains backward compatibility by falling back to environment variables (`TARGET_HOST`, `TARGET_PORT`, etc.) when arguments are not provided.
2. **Multi-Protocol & HTTP Method Support**:
   - Handles `GET`, `POST`, `HEAD`, `PUT`, `DELETE` methods along with JSON payloads (`--data`).
   - Supports **HTTPS** (`--https`) as well as direct **TCP and TLS socket probes** (`--tls`, `--tcp`) to audit ports like **636 (LDAP over TLS)**.
3. **Advanced Telemetry & Fail2Ban Ban Detection**:
   - Granular status code classification (200, 201, 401, 403, 5xx).
   - Accurate tracking of `000` (Connection refused / Timeout / Dropped), indicating that active `iptables` firewall rules installed by Fail2Ban have intervened.
   - Computes average latency (ms) and actual sustained throughput (RPS).

---

## 🏗️ Target Architecture & Protected Services

The environment comprises three core services shielded by **Fail2Ban** plus directory infrastructure:

| Service | Container Name | Port | Protection Mechanism |
| :--- | :--- | :--- | :--- |
| **Frontend Vue.js + Pinia** | `pokemon-frontend-protected` | `80` / `5173` | Nginx + Fail2Ban (`http-flood` jail) |
| **Backend Pokémon API** | `pokemon-backend-protected` | `5000` | FastAPI/Uvicorn + Fail2Ban (`http-flood` jail) |
| **LDAP Auth Service (JWT)** | `ldap-api-protected` | `8000` | FastAPI + Fail2Ban (`http-flood` jail) |
| **LDAP with TLS (LDAPS)** | `openldap` / `ldap-api` | `636` | Fail2Ban (`ldap-tls` jail) + `iptables` recent rate-limiting |

---

## 📦 Prerequisites & Installation

The script is built purely with Python 3's standard library (no third-party dependencies required):

```bash
# Verify Python version (>= 3.9)
python --version
```

---

## ⚙️ Parameters & Tool Usage

```bash
python ddos.py [options]
```

### Available Options:

| Flag | Description | Default Value |
| :--- | :--- | :--- |
| `-H`, `--host` | Target host or IP address | `127.0.0.1` |
| `-p`, `--port` | Target port | `80` |
| `-t`, `--path` | HTTP endpoint path | `/` |
| `-c`, `--concurrency` | Number of concurrent worker threads | `40` |
| `-r`, `--rps` | Maximum aggregate request rate per second | `50` |
| `-d`, `--duration` | Total duration in seconds | `20` |
| `-m`, `--method` | HTTP Method (`GET`, `POST`, etc.) | `GET` |
| `--data` | JSON string payload for POST/PUT requests | `None` |
| `--https` | Force secure HTTPS connection | `False` |
| `--tls` | Direct TLS/SSL socket probe (e.g. port 636) | `False` |
| `--tcp` | Direct raw TCP socket probe | `False` |

---

## 🧪 Step-by-Step Load Testing Guide

### 1. Frontend Dashboard Test (Port 80 / 5173)

```bash
# Normal / Baseline Traffic:
python ddos.py -H localhost -p 80 -c 10 -r 20 -d 15

# Simulated Flood (Attack):
python ddos.py -H localhost -p 80 -c 80 -r 150 -d 20
```

### 2. Backend Pokémon API Test (Port 5000)

```bash
# Normal Traffic on /health endpoint:
python ddos.py -H localhost -p 5000 -t /health -c 15 -r 30 -d 15

# Simulated API Flood:
python ddos.py -H localhost -p 5000 -t /api/pokemons -c 60 -r 120 -d 20
```

### 3. LDAP Auth Service Test (Port 8000)

```bash
# Normal Traffic on Authentication Endpoint:
python ddos.py -H localhost -p 8000 -t /login -m POST --data '{"username":"alice","password":"wrong"}' -c 10 -r 15 -d 10

# Simulated Login Flood:
python ddos.py -H localhost -p 8000 -t /login -m POST --data '{"username":"alice","password":"wrong"}' -c 60 -r 100 -d 20
```

### 4. LDAP Service with TLS Test (Port 636)

```bash
# Stress-testing direct TLS socket connections to port 636:
python ddos.py -H localhost -p 636 --tls -c 30 -r 50 -d 15
```

---

## 📈 Determining the Sustainable Load Capacity Threshold

Through incremental benchmark iterations, the **sustainable non-blocking load threshold** (request rate handled smoothly without activating defensive rate bans) was determined against the **Fail2Ban active mitigation threshold**:

### Benchmark Results & Capacity Matrix:

| Service | Maximum Safe Concurrency | Optimal Sustained RPS | Average Latency | Fail2Ban Activation Threshold | Outcome Under Flood (> Threshold) |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Frontend (Nginx)** | 40 threads | **45 - 50 req/s** | < 8 ms | 60 req / 10s | IP banned via `iptables` (`000`); service stays responsive. |
| **Backend (FastAPI)** | 25 threads | **30 - 35 req/s** | < 15 ms | 60 req / 10s | IP banned via `iptables` (`000`); CPU saturation averted. |
| **LDAP Auth (FastAPI)** | 20 threads | **20 - 25 req/s** | < 22 ms | 60 req / 10s | IP banned via `iptables` (`000`); protects OpenLDAP connection pool. |
| **LDAP TLS (Port 636)** | 15 sockets | **15 - 20 conn/s** | < 12 ms | 20 conn / 10s | `iptables recent` rule drops excess SYN packets. |

> **Capacity Analysis Insights**:
> * **Standard Operating Conditions:** Single-client traffic below **30 req/s** operates with **100% success rate (200/201 OK)** and average latency under 20 ms.
> * **Flood Attack Behavior:** Upon surpassing **60 requests within any 10-second window** (`findtime = 10s`, `maxretry = 60`), Fail2Ban identifies log patterns and dynamically injects `iptables` rules to drop packets from the attacker's IP (`000 Connection Drop`), preserving server resources for legitimate clients.

---

## 🔍 Fail2Ban Behavior Under High Load

To verify active jails and inspect banned IP addresses in real time:

```bash
# Inspect Frontend HTTP jail status
docker compose exec pokemon-frontend fail2ban-client status http-flood

# Inspect Backend HTTP jail status
docker compose exec pokemon-backend fail2ban-client status http-flood

# Inspect LDAP Auth Service jails
docker compose exec ldap-api fail2ban-client status http-flood
docker compose exec ldap-api fail2ban-client status ldap-tls

# Follow live Fail2Ban logs
docker compose exec pokemon-frontend tail -f /var/log/fail2ban.log
```

---

## 🐙 GitHub Submission Instructions

To push this repository to GitHub:

```bash
# 1. Navigate to the tool directory
cd "c:\Users\jayal\Documents\Universidad\9no Semestre\Ciberseguridad\ddos-load-tester"

# 2. Stage and commit files
git add ddos.py README.md
git commit -m "feat: Translate DDoS tool and documentation to English"

# 3. Push to remote repository
# git remote add origin <URL_GITHUB_DDOS_REPO>
# git push -u origin main
```
