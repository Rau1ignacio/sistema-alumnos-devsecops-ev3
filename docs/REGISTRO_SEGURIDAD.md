# Registro de seguridad · Sistema Alumnos

Estudiante: **Raúl Bustamante**   Repositorio: **https://github.com/Rau1ignacio/sistema-alumnos-devsecops-ev3**   Fecha: **27-11-2026**

Cada fila se puede seguir hasta un **build de Jenkins** (job `sistema-alumnos-pipeline`) y un **commit** (`VULN-xx`, `DEPS`, `CI`).
Versión desplegada = `1.0.<build>+<commit>` (se ve en `/version`, en Grafana y en `TRAZABILIDAD.md`).

| Build | Commit | Qué se verificó | Resultado |
|---|---|---|---|
| #1 | `38b134c` | Pipeline base (Build → Test → Deploy) | SUCCESS · producción 1.0.1 (código vulnerable) |
| #2 | `7f4b006` | Primera ejecución con SAST, SCA y DAST | UNSTABLE · gate bloquea producción |
| #3 | `293d8f1` | Correcciones VULN-01 … VULN-08 | UNSTABLE solo por dependencias · Bandit y ZAP limpios |
| #4 | `4b71ef5` | Dependencias actualizadas por Dependabot | SUCCESS · 18/18 pruebas · Bandit 0 · pip-audit 0 · ZAP 0 · **producción 1.0.4+4b71ef5** |

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit 1.8.6 en la etapa `Security Review (SAST)` | #2 → #3 | #2: **2 High / 2 Medium / 1 Low** → #3: **0 / 0 / 0** |
| R2 | Dependencias (SCA) | pip-audit 2.9.0 en la etapa `Dependency Management (SCA)` + alertas de Dependabot | #2 → #4 | #2: **19 vulnerabilidades en 4 paquetes** (Dependabot: 20 alertas, 5 altas, incluye pytest) → #4: **0** |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP 2.16.1 (spider + pasivo + activo) sobre staging `http://jenkins:5001` | #2 → #3 | #2: **3 High / 3 Medium / 1 Low** → #3: **0 / 0 / 0** (2 informativas) |
| R4 | Revisión manual | Lectura de `app.py` (OWASP Top 10) | — | Confirma los hallazgos de las herramientas y agrega CSRF, fuerza bruta e inyección en logs, que Bandit no detecta |
| R5 | Producción | Grafana + Prometheus (dashboard y 3 reglas de alerta) | — | Incidente 27-11-2026 17:02–17:07: fuerza bruta + SQLi + XSS contra producción 1.0.1 (ver sección 4) |
| R6 | Pruebas de regresión | `tests/test_seguridad.py` (pytest, etapa `Test`) | #3 | 9 pruebas de seguridad + 9 funcionales = **18/18 OK** |

Política del pipeline: cualquier hallazgo Medium/High de Bandit, cualquier CVE de pip-audit o cualquier alerta High/Medium de ZAP
deja el build en **UNSTABLE** y el `when { currentBuild.currentResult == 'SUCCESS' }` de la etapa *Deploy Producción* impide desplegar.

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) y divulgación de la consulta en el error (CWE-209) | Bandit B608, ZAP 40018, revisión manual, `simular_ataque.py` | `app.py` `buscar_alumnos()` | Alto | Consulta parametrizada `LIKE ? ESCAPE '\'`, escape de comodines, error genérico y registro solo en servidor | `914c57d` | #3 |
| VULN-02 | XSS reflejado (CWE-79) | ZAP 40012 y 40026, revisión manual | `app.py` `hello()` | Alto | Salida escapada con Jinja2 (`render_template_string` + autoescape) y largo máximo | `d31bf68` | #3 |
| VULN-03 | Secreto escrito en el código (CWE-798 / CWE-259) | Bandit B105 | `app.py` `SECRET_KEY` | Medio | `SECRET_KEY` desde variable de entorno; si falta, `secrets.token_hex(32)` | `813d4d8` | #3 |
| VULN-04 | Hash débil MD5 y clave por defecto `admin` (CWE-327, CWE-521, CWE-798) | Bandit B324, ataque de fuerza bruta (clave encontrada) | `app.py` `login()` | Alto | Hash PBKDF2-SHA256 (600 000 iteraciones, con sal) desde `ADMIN_CLAVE_HASH`; sin clave por defecto; comparación en tiempo constante | `2827a08` | #3 |
| VULN-05 | Falta de token anti-CSRF (CWE-352) | ZAP 10202, revisión manual | Formulario `/login` | Medio | Token por sesión (synchronizer token) validado con `hmac.compare_digest`; sin token → HTTP 400 | `7d21a05` | #3 |
| VULN-06 | Sin límite de intentos / fuerza bruta (CWE-307) e inyección en logs (CWE-117) | Grafana (alerta de fuerza bruta), revisión manual | `app.py` `login()` | Alto | Máximo 5 fallos por IP en 300 s → HTTP 429 + `Retry-After` + métrica `peticiones_sospechosas_total{tipo="fuerza_bruta"}`; usuario registrado con `%r` | `c555e54` | #3 |
| VULN-07 | Depurador de Flask activo y escucha en 0.0.0.0 (CWE-94, CWE-605) | Bandit B201 y B104 | `app.py` bloque `__main__` | Alto | `debug=False`, `host="127.0.0.1"`; producción la sirve gunicorn | `1769efb` | #3 |
| VULN-08 | Faltan cabeceras de seguridad y cookie débil (CWE-693, CWE-1021) | ZAP 10038, 10020, 10021 | Todas las respuestas | Medio | CSP restrictiva, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, COOP/CORP/COEP, `Cache-Control: no-store`; cookie `HttpOnly` + `SameSite=Strict` | `293d8f1` | #3 |
| VULN-09 | Componentes con vulnerabilidades conocidas (CWE-1104, OWASP A06) | pip-audit, Dependabot | `requirements.txt` | Alto | Actualización vía Dependabot (sección 5) | PR #5, #6, #7, #8 + `4b71ef5` | #4 |

## 3. Resultados de OWASP ZAP

Escaneo del build #2 (código vulnerable) y del build #3 (código corregido). Reporte completo: `reports/zap-report.html` de cada build.

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| SQL Injection (40018) | High | `/alumnos/buscar?nombre='` | VULN-01 | Consulta parametrizada | Sí · #3 |
| Cross Site Scripting (Reflected) (40012) | High | `/hello?name=</h1><scrIpt>alert(1);</scRipt><h1>` | VULN-02 | Escape de salida (autoescape) + CSP | Sí · #3 |
| Cross Site Scripting (DOM Based) (40026) | High | `/hello?name=<script>alert(5397)</script>` | VULN-02 | Escape de salida + CSP `default-src 'none'` | Sí · #3 |
| Absence of Anti-CSRF Tokens (10202) | Medium | `/` (formulario de login) | VULN-05 | Token anti-CSRF por sesión | Sí · #3 |
| Content Security Policy (CSP) Header Not Set (10038) | Medium | `/`, `/robots.txt` | VULN-08 | Cabecera `Content-Security-Policy` | Sí · #3 |
| Missing Anti-clickjacking Header (10020) | Medium | `/hello?name=Ana` | VULN-08 | `X-Frame-Options: DENY` + `frame-ancestors 'none'` | Sí · #3 |
| X-Content-Type-Options Header Missing (10021) | Low | `/alumnos` | VULN-08 | `X-Content-Type-Options: nosniff` | Sí · #3 |
| Session Management Response Identified | Informational | `/` | — | Es la cookie de sesión del token CSRF (esperado, `HttpOnly` + `SameSite=Strict`) | No requiere |
| User Agent Fuzzer | Informational | `/` | — | Prueba informativa de ZAP, sin hallazgo | No requiere |

## 4. Monitoreo e incidentes

Dashboard **«Sistema Alumnos – Producción (seguridad)»** (Grafana, carpeta *EV3 Seguridad*), fuente **Prometheus** (`http://prometheus:9090`, scrape cada 5 s).
Reglas de alerta (grupo `seguridad-produccion`, evaluación cada 10 s):
`Fuerza bruta en /login` (> 10 logins fallidos/min), `Peticiones sospechosas (XSS / SQLi / path traversal)` (> 0/min) y `Producción caída` (`up < 1` durante 30 s).

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| 16:59 | *Staging: peticiones sospechosas* (`peticiones_sospechosas_total{job="staging"}`) | Pico de ~53 sqli y ~11 xss por minuto | Staging | Esperado (escaneo OWASP ZAP del build #2) | Ninguna: ataque controlado del pipeline | Coincide con la etapa DAST del build #2 |
| 17:02 | *Logins fallidos* (`login_fallidos_total`) | 30 fallos en segundos desde 172.19.0.6; un login exitoso con `admin/admin` | Producción 1.0.1 | **Incidente alto**: fuerza bruta con éxito (credencial por defecto) | Alerta *Fuerza bruta en /login* → Firing; se identifican VULN-04 y VULN-06 | Logs de gunicorn: 180 líneas «Login fallido» |
| 17:02 | *Peticiones sospechosas por tipo* (`tipo=sqli`, `tipo=xss`) | Inyección SQL que expone `sqlite_master` y XSS reflejado | Producción 1.0.1 | **Incidente alto**: explotación de VULN-01 y VULN-02 | Alerta *Peticiones sospechosas* → Firing; contención: el gate impide nuevos despliegues vulnerables; erradicación: commits VULN-01…08 | Build #3 verde en Bandit/ZAP/pruebas |
| 17:47 | *Versión desplegada* (`app_info`) | Producción pasa de 1.0.1 a 1.0.4+4b71ef5 | Producción | Recuperación | Despliegue automático del build #4 tras pasar todas las revisiones | `simular_ataque.py`: clave no encontrada, 429 tras 5 intentos, SQLi y XSS bloqueados; alertas vuelven a Normal |

## 5. Gestión de dependencias

Proceso: **Dependabot** (alertas + security updates + `.github/dependabot.yml` diario) abre un PR por paquete → antes de fusionar se prueba la
combinación completa en el contenedor `taller` (pytest 18/18 + `pip-audit` sin vulnerabilidades) → se fusiona en `main` → Jenkins
reconstruye y vuelve a ejecutar pruebas, Bandit, pip-audit y ZAP → solo si todo queda limpio se despliega en producción.

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | CVE-2023-30861, CVE-2026-27205 | 3.1.3 | Alerta/PR #3 de Dependabot → commit `4b71ef5` (*) | Sí · #4 |
| Werkzeug | 2.2.2 | CVE-2023-23934, CVE-2023-25577, CVE-2023-46136, CVE-2024-34069, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 | 3.1.9 | PR #5 de Dependabot | Sí · #4 |
| Jinja2 | 3.1.2 | CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | 3.1.6 | Alerta/PR #1 de Dependabot → commit `4b71ef5` (*) | Sí · #4 |
| gunicorn | 21.2.0 | CVE-2024-1135, CVE-2024-6827 | 27.0.1 | PR #8 de Dependabot (reemplaza al #2) | Sí · #4 |
| prometheus-client | 0.17.1 | ninguna | 0.26.0 | PR #6 de Dependabot (version update, mantenimiento preventivo) | Sí · #4 |
| pytest (dev) | 8.3.4 | CVE-2025-71176 | 9.2.0 | PR #7 de Dependabot (reemplaza al #4) | Sí · #4 |

(*) Los PR #1–#4 los creó Dependabot (security updates) antes de existir `dependabot.yml`; al agregar la configuración Dependabot pidió cerrarlos y abrió #6, #7 y #8 con la nueva política (prefijo `DEPS`, última versión). Flask 3.1.3 y Jinja2 3.1.6 se aplicaron en el commit `4b71ef5`, que cita los GHSA de las alertas de Dependabot que cierra. Antes de fusionar, la combinación completa se probó en el contenedor `taller` (pytest 18/18, arranque real con gunicorn, `pip-audit`: *No known vulnerabilities found*). Resultado: **20/20 alertas de Dependabot en estado *fixed*** y build #4 en SUCCESS.

## 6. Trazabilidad

`reports/TRAZABILIDAD.md` del último build (lo genera `scripts/trazabilidad.py` en cada ejecución):

Cada fila la agrega Jenkins al terminar un build (`scripts/trazabilidad.py`).

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 19:55 | 1.0.1+38b134c | `38b134c` | CI: código base vulnerable de Sistema Alumnos (punto de partida EV3) | 9/9 OK | n/a | n/a | n/a | SUCCESS | 1.0.1+38b134c |
| 2 | 2026-11-27 19:59 | 1.0.2+7f4b006 | `7f4b006` | CI: etapas SAST (Bandit), SCA (pip-audit), staging, DAST (OWASP ZAP) y | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 3 | 2026-11-27 20:14 | 1.0.3+293d8f1 | `293d8f1` | VULN-08: cabeceras de seguridad (CSP, X-Frame-Options, nosniff) y cook | 18/18 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 4 | 2026-11-27 20:47 | 1.0.4+4b71ef5 | `4b71ef5` | DEPS: Flask 2.2.2 -> 3.1.3 y Jinja2 3.1.2 -> 3.1.6 (alertas Dependabot | 18/18 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.4+4b71ef5 |

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | B324 MD5 (High) y B201 debug (High) | #2 | `2827a08` (VULN-04), `1769efb` (VULN-07) | #3 | 1.0.4+4b71ef5 |
| Prueba automatizada (OWASP ZAP) | SQL Injection (High) | #2 | `914c57d` (VULN-01) | #3 | 1.0.4+4b71ef5 |
| Gestión de dependencias (Dependabot) | Werkzeug 2.2.2: 10 CVE (2 altas) | #2 | PR #5 | #4 | 1.0.4+4b71ef5 |
