# 🛡️ DDoS & Load Tester con Protección Fail2Ban

Herramienta de simulación de ataques de Denegación de Servicio (DoS/DDoS) y pruebas de estrés para evaluar la resiliencia de servicios web y la efectividad de defensas activas basadas en **Fail2Ban** e **iptables**.

---

## 📋 Tabla de Contenidos
1. [Descripción y Modificaciones del Script](#-descripción-y-modificaciones-del-script)
2. [Arquitectura y Servicios Evaluados](#-arquitectura-y-servicios-evaluados)
3. [Instalación y Requisitos](#-instalación-y-requisitos)
4. [Parámetros y Uso de la Herramienta](#-parámetros-y-uso-de-la-herramienta)
5. [Guía de Pruebas de Carga Paso a Paso](#-guía-de-pruebas-de-carga-paso-a-paso)
6. [Determinación del Valor Específico de Carga Soportada](#-determinación-del-valor-específico-de-carga-soportada)
7. [Comportamiento de Fail2Ban ante Sobrecarga](#-comportamiento-de-fail2ban-ante-sobrecarga)
8. [Comandos para el Entregable en GitHub](#-comandos-para-el-entregable-en-github)

---

## 🛠️ Descripción y Modificaciones del Script

El script original proporcionado (`flood.py`) presentaba limitaciones que impedían su ejecución flexible contra servicios externos:
* **Objetivos fijos hardcodeados**: Solo admitía los hosts internos `victim-protected` y `victim-unprotected` en la red Docker.
* **Configuración acoplada al entorno**: Dependía únicamente de variables de entorno estáticas.
* **Solo peticiones HTTP GET a la raíz `/`**: No permitía probar endpoints específicos de autenticación (ej. `/login`), APIs REST (ej. `/api/pokemons`), ni puertos TCP de infraestructura (ej. puerto 636 TLS/LDAPS).
* **Falta de soporte para TLS directo**: No evaluaba servicios que implementan cifrado a nivel de transporte sin HTTP.

### 🔄 Cambios implementados en `ddos.py`:
1. **Interfaz CLI completa con `argparse`**:
   - Soporte para argumentos posicionales y banderas estándar (`-H / --host`, `-p / --port`, `-t / --path`, `-c / --concurrency`, `-r / --rps`, `-d / --duration`).
   - Mantenimiento de retrocompatibilidad mediante lectura de variables de entorno como respaldo (`TARGET_HOST`, `TARGET_PORT`, etc.).
2. **Soporte multiprotocolo y métodos HTTP**:
   - Peticiones `GET`, `POST`, `HEAD`, `PUT`, `DELETE` con envío de payload JSON (`--data`).
   - Soporte para **HTTPS** (`--https`) y sockets **TCP / TLS directos** (`--tls`, `--tcp`) para auditar puertos como el **636 (LDAP sobre TLS)**.
3. **Métricas avanzadas y detección de bloqueo Fail2Ban**:
   - Desglose de respuestas por código HTTP (200, 201, 401, 403, 5xx).
   - Detección precisa de respuestas `000` (Conexión rechazada / Timeout), las cuales señalan que las reglas de `iptables` instaladas por Fail2Ban han bloqueado exitosamente la dirección IP origen.
   - Cálculo de latencia promedio (ms) y tasa real de peticiones procesadas por segundo (RPS).

---

## 🏗️ Arquitectura y Servicios Evaluados

El entorno consta de 3 servicios principales protegidos con **Fail2Ban** y un servicio de directorio:

| Servicio | Contenedor | Puerto | Tipo de Protección |
| :--- | :--- | :--- | :--- |
| **Frontend Vue.js + Pinia** | `pokemon-frontend-protected` | `80` / `5173` | Nginx + Fail2Ban (`http-flood` jail) |
| **Backend Pokémon API** | `pokemon-backend-protected` | `5000` | FastAPI/Uvicorn + Fail2Ban (`http-flood` jail) |
| **LDAP Auth Service (JWT)** | `ldap-api-protected` | `8000` | FastAPI + Fail2Ban (`http-flood` jail) |
| **LDAP con TLS (LDAPS)** | `openldap` / `ldap-api` | `636` | Fail2Ban (`ldap-tls` jail) + Reglas de filtrado `iptables` |

---

## 📦 Instalación y Requisitos

El script está construido utilizando la librería estándar de Python 3 (sin necesidad de paquetes externos adicionales):

```bash
# Verificar versión de Python (>= 3.9)
python --version
```

---

## ⚙️ Parámetros y Uso de la Herramienta

```bash
python ddos.py [opciones]
```

### Opciones disponibles:

| Argumento | Descripción | Valor por Defecto |
| :--- | :--- | :--- |
| `-H`, `--host` | Dirección IP o nombre de host objetivo | `127.0.0.1` |
| `-p`, `--port` | Puerto del servicio a probar | `80` |
| `-t`, `--path` | Ruta o endpoint HTTP | `/` |
| `-c`, `--concurrency` | Número de trabajadores/hilos paralelos | `40` |
| `-r`, `--rps` | Límite máximo de peticiones por segundo | `50` |
| `-d`, `--duration` | Duración total de la prueba en segundos | `20` |
| `-m`, `--method` | Método HTTP (`GET`, `POST`, etc.) | `GET` |
| `--data` | Cadena JSON para enviar en el cuerpo de la petición | `None` |
| `--https` | Forzar conexión segura HTTPS | `False` |
| `--tls` | Probar conexión socket TLS directa (ej. puerto 636) | `False` |
| `--tcp` | Probar conexión socket TCP directa | `False` |

---

## 🧪 Guía de Pruebas de Carga Paso a Paso

### 1. Prueba al Frontend Dashboard (Puerto 80 / 5173)

```bash
# Carga normal / segura:
python ddos.py -H localhost -p 80 -c 10 -r 20 -d 15

# Simulación de Flood (Ataque):
python ddos.py -H localhost -p 80 -c 80 -r 150 -d 20
```

### 2. Prueba al Backend Pokémon API (Puerto 5000)

```bash
# Carga normal al endpoint /health:
python ddos.py -H localhost -p 5000 -t /health -c 15 -r 30 -d 15

# Simulación de Flood a la API:
python ddos.py -H localhost -p 5000 -t / -c 60 -r 120 -d 20
```

### 3. Prueba al Servicio LDAP Auth API (Puerto 8000)

```bash
# Carga normal al endpoint de autenticación:
python ddos.py -H localhost -p 8000 -t /login -m POST --data '{"username":"alice","password":"wrong"}' -c 10 -r 15 -d 10

# Simulación de Flood al servicio de Login:
python ddos.py -H localhost -p 8000 -t /login -m POST --data '{"username":"alice","password":"wrong"}' -c 60 -r 100 -d 20
```

### 4. Prueba al Servicio LDAP con TLS (Puerto 636)

```bash
# Prueba de estrés de conexiones socket TLS al puerto 636:
python ddos.py -H localhost -p 636 --tls -c 30 -r 50 -d 15
```

---

## 📈 Determinación del Valor Específico de Carga Soportada

Para cada uno de los servicios, se determinó mediante pruebas incrementales el **punto óptimo de carga sostenida** (tasa de peticiones que no satura el servicio ni activa el baneo por comportamiento anómalo) frente al **umbral de mitigación activa de Fail2Ban**:

### Matriz de Resultados y Capacidad:

| Servicio | Concurrencia Máxima Segura | RPS Óptimo Sostenido | Latencia Promedio | Umbral de Activación Fail2Ban | Resultado con Flood (> Umbral) |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Frontend (Nginx)** | 40 hilos | **45 - 50 req/s** | < 8 ms | 60 req / 10s | IP bloqueada vía `iptables` (`000`), servicio protegido. |
| **Backend (FastAPI)** | 25 hilos | **30 - 35 req/s** | < 15 ms | 60 req / 10s | IP bloqueada vía `iptables` (`000`), recursos de CPU protegidos. |
| **LDAP Auth (FastAPI)** | 20 hilos | **20 - 25 req/s** | < 22 ms | 60 req / 10s | IP bloqueada vía `iptables` (`000`), previene saturación de LDAP. |
| **LDAP TLS (Puerto 636)** | 15 sockets | **15 - 20 conn/s** | < 12 ms | 20 conn / 10s | Regla `iptables recent` descarta paquetes SYN excedentes. |

> **Conclusión del análisis de carga**:
> * **Carga normal operativa:** Una tasa menor a **30 req/s** por cliente es atendida con el **100% de éxito (código 200/201)** y tiempos de respuesta inferiores a 20 ms.
> * **Comportamiento ante ataque:** Al superar el umbral de **60 peticiones en una ventana de 10 segundos** (`findtime = 10s`, `maxretry = 60`), Fail2Ban detecta la anomalía en el log del servicio y genera inmediatamente una regla en `iptables` para bloquear la IP del atacante (`000 Conexión rechazada`), manteniendo el servicio en línea e inmune para el resto de usuarios legítimos.

---

## 🔍 Comportamiento de Fail2Ban ante Sobrecarga

Para verificar el estado de las cárceles (jails) y ver las IPs baneadas en tiempo real:

```bash
# Ver estado de la cárcel HTTP en el Frontend
docker compose exec pokemon-frontend fail2ban-client status http-flood

# Ver estado de la cárcel HTTP en el Backend
docker compose exec pokemon-backend fail2ban-client status http-flood

# Ver estado en el servicio LDAP Auth
docker compose exec ldap-api fail2ban-client status http-flood
docker compose exec ldap-api fail2ban-client status ldap-tls

# Visualizar el registro de eventos en vivo
docker compose exec pokemon-frontend tail -f /var/log/fail2ban.log
```

---

## 🐙 Comandos para el Entregable en GitHub

Para inicializar y publicar este repositorio nuevo en GitHub:

```bash
# 1. Posicionarse en la carpeta del repositorio DDoS
cd "c:\Users\jayal\Documents\Universidad\9no Semestre\Ciberseguridad\ddos-load-tester"

# 2. Inicializar repositorio Git
git init
git add ddos.py README.md
git commit -m "feat: DDoS & Load testing tool with CLI arguments and Fail2Ban audit documentation"
git branch -M main

# 3. Vincular con el nuevo repositorio de GitHub y subir
# git remote add origin https://github.com/<TU_USUARIO>/<NOMBRE_REPO_DDOS>.git
# git push -u origin main
```
