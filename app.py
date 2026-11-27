"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).

Además de las rutas de negocio, la app publica métricas para Prometheus en /metrics.
Las métricas de seguridad (logins fallidos y peticiones sospechosas) se ven en Grafana.
"""
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

## VULN-03: la clave de la aplicación llega por variable de entorno (gestor de secretos / Jenkins credentials).
## Si no está definida se genera una aleatoria al iniciar: nunca queda escrita en el código ni en Git.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
## VULN-08: la cookie de sesión no es accesible desde JavaScript y no viaja en peticiones de otros sitios.
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")
CABECERAS_SEGURIDAD = {
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store",
}
## VULN-04: la clave del administrador se guarda como hash PBKDF2-SHA256 con sal (werkzeug), no como MD5,
## y llega por variable de entorno. Sin ella no existe clave por defecto: se usa una aleatoria que nadie conoce.
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_CLAVE_HASH") or generate_password_hash(secrets.token_urlsafe(32), method="pbkdf2:sha256:600000")

## Versión desplegada: la inyecta el pipeline (1.0.<build>+<commit>). Sirve para la trazabilidad.
VERSION = os.environ.get("APP_VERSION", "dev")
## Archivo SQLite con los alumnos (cada entorno usa el suyo).
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

## Patrones que delatan un intento de ataque (detección, no bloqueo).
PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def conectar():
    """!
    @brief Abre (una vez por petición) la conexión a la base de datos SQLite.
    @return Conexión sqlite3 con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión a la base de datos al terminar cada petición.
    @param _error Excepción de la petición (si la hubo); no se usa.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales si está vacía.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Marca el inicio de la petición y cuenta los parámetros con patrones de ataque.
    """
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Registra la métrica de cada petición atendida.
    @param respuesta Respuesta que Flask enviará al cliente.
    @return La misma respuesta.
    """
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    # VULN-08: cabeceras de seguridad en todas las respuestas (alertas de OWASP ZAP).
    respuesta.headers.update(CABECERAS_SEGURIDAD)
    return respuesta


@app.route("/")
def portada():
    """!
    @brief Portada HTML con enlaces y formularios del sistema.
    @return Página HTML.
    """
    return render_template_string(PORTADA, version=VERSION, csrf_token=token_csrf())


def token_csrf():
    """!
    @brief VULN-05: token anti-CSRF por sesión (patrón synchronizer token).
    @return Token aleatorio guardado en la sesión firmada del usuario.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def csrf_valido():
    """!
    @brief Comprueba en tiempo constante que el formulario trae el token de la sesión.
    @return True si el token es válido.
    """
    esperado = session.get("csrf_token", "")
    recibido = request.form.get("csrf_token", "")
    return bool(esperado) and hmac.compare_digest(esperado, recibido)


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario cuyo nombre llega en el parámetro de URL «name».
    @return Página HTML con el saludo.
    """
    name = request.args.get("name", "visitante")[:100]
    # VULN-02: el nombre se escapa (Jinja2 autoescape) antes de insertarlo en el HTML.
    return render_template_string("<h1>Hola, {{ name }}!</h1>", name=name)


@app.route("/health")
def health():
    """!
    @brief Estado de la aplicación (lo usan el despliegue y el monitoreo).
    @return JSON {"estado": "ok"}.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Versión desplegada, para la trazabilidad.
    @return JSON con el nombre y la versión de la aplicación.
    """
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Lista todos los alumnos.
    @return JSON con la lista de alumnos.
    """
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por su identificador.
    @param alumno_id Identificador numérico del alumno.
    @return JSON con el alumno, o error 404 si no existe.
    """
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos cuyo nombre contenga el texto del parámetro «nombre».
    @return JSON con los alumnos encontrados.
    """
    nombre = request.args.get("nombre", "")[:100]
    # VULN-01: consulta parametrizada; el valor del usuario nunca se concatena al SQL.
    # Se escapan los comodines de LIKE para que «%» y «_» se busquen como texto literal.
    patron = "%" + nombre.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    try:
        filas = conectar().execute(
            "SELECT * FROM alumnos WHERE nombre LIKE ? ESCAPE '\\' ORDER BY id", (patron,)
        ).fetchall()
    except sqlite3.Error:
        # No se devuelve el error ni la consulta al cliente (CWE-209); se registra solo en el servidor.
        app.logger.exception("Error de base de datos en /alumnos/buscar")
        return jsonify({"error": "No se pudo completar la búsqueda"}), 500
    return jsonify([dict(f) for f in filas])


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Valida las credenciales del administrador enviadas por formulario.
    @return JSON con el resultado; 401 si las credenciales no son válidas.
    """
    if not csrf_valido():
        app.logger.warning("Login rechazado: token CSRF ausente o inválido desde %s", request.remote_addr)
        return jsonify({"error": "Token CSRF inválido"}), 400
    ip = request.remote_addr or "desconocida"
    usuario = request.form.get("usuario", "")[:64]
    clave = request.form.get("clave", "")[:256]
    # VULN-06: tras MAX_FALLIDOS intentos fallidos en VENTANA_S segundos la IP queda bloqueada (HTTP 429).
    espera = segundos_bloqueo(ip)
    if espera:
        LOGIN_FALLIDOS.inc()
        SOSPECHOSAS.labels(tipo="fuerza_bruta").inc()
        app.logger.warning("Login bloqueado por fuerza bruta desde %s (%s s restantes)", ip, espera)
        return jsonify({"error": "Demasiados intentos. Intenta más tarde."}), 429, {"Retry-After": str(espera)}
    # check_password_hash compara en tiempo constante; siempre se calcula el hash para no revelar si el usuario existe.
    clave_ok = check_password_hash(ADMIN_CLAVE_HASH, clave)
    if hmac.compare_digest(usuario, ADMIN_USUARIO) and clave_ok:
        limpiar_fallos(ip)
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})
    registrar_fallo(ip)
    LOGIN_FALLIDOS.inc()
    # %r escapa saltos de línea: el usuario no puede falsificar líneas del log (CWE-117).
    app.logger.warning("Login fallido para el usuario %r desde %s", usuario, ip)
    return jsonify({"error": "Credenciales inválidas"}), 401


# ---------------------------------------------------------------- VULN-06: límite de intentos de login
MAX_FALLIDOS = int(os.environ.get("LOGIN_MAX_FALLIDOS", "5"))
VENTANA_S = int(os.environ.get("LOGIN_VENTANA_S", "300"))
_FALLOS = defaultdict(deque)
_FALLOS_LOCK = threading.Lock()


def _purgar(ip, ahora):
    cola = _FALLOS[ip]
    while cola and cola[0] <= ahora - VENTANA_S:
        cola.popleft()
    return cola


def segundos_bloqueo(ip):
    """!
    @brief Indica si la IP superó el máximo de intentos fallidos dentro de la ventana.
    @param ip Dirección IP del cliente.
    @return Segundos que faltan para desbloquear (0 si no está bloqueada).
    """
    ahora = time.monotonic()
    with _FALLOS_LOCK:
        cola = _purgar(ip, ahora)
        if len(cola) < MAX_FALLIDOS:
            return 0
        return max(1, int(cola[0] + VENTANA_S - ahora))


def registrar_fallo(ip):
    """!
    @brief Registra un intento fallido de la IP.
    @param ip Dirección IP del cliente.
    """
    with _FALLOS_LOCK:
        _purgar(ip, time.monotonic()).append(time.monotonic())


def limpiar_fallos(ip):
    """!
    @brief Borra los intentos fallidos de la IP tras un login correcto.
    @param ip Dirección IP del cliente.
    """
    with _FALLOS_LOCK:
        _FALLOS.pop(ip, None)


@app.route("/metrics")
def metrics():
    """!
    @brief Métricas en formato Prometheus.
    @return Texto con las métricas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    # VULN-07: solo para desarrollo local. Sin depurador de Werkzeug (ejecución remota de código) y escuchando
    # únicamente en localhost. En staging/producción la app la sirve gunicorn (scripts/deploy.sh).
    app.run(host="127.0.0.1", port=5000, debug=False)
