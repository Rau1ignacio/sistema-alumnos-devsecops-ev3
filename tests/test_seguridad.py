"""Pruebas de regresión de seguridad: cada una verifica que una vulnerabilidad corregida (VULN-xx) no vuelva."""
import pytest

import app as modulo_app


@pytest.fixture
def client():
    modulo_app.app.config["TESTING"] = True
    modulo_app._FALLOS.clear()
    with modulo_app.app.test_client() as c:
        yield c
    modulo_app._FALLOS.clear()


def test_vuln01_inyeccion_sql_no_expone_la_base(client):
    carga = "zzz' UNION SELECT 0, name, sql, 0 FROM sqlite_master --"
    r = client.get("/alumnos/buscar", query_string={"nombre": carga})
    assert r.status_code == 200
    assert r.get_json() == []
    assert "CREATE TABLE" not in r.get_data(as_text=True)


def test_vuln01_comilla_no_provoca_error_ni_filtra_consulta(client):
    r = client.get("/alumnos/buscar", query_string={"nombre": "'"})
    assert r.status_code == 200
    assert "SELECT" not in r.get_data(as_text=True)


def test_vuln02_xss_reflejado_se_escapa(client):
    r = client.get("/hello", query_string={"name": "<script>alert('xss')</script>"})
    cuerpo = r.get_data(as_text=True)
    assert "<script>" not in cuerpo
    assert "&lt;script&gt;" in cuerpo


def _login(client, usuario, clave):
    import re
    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/").get_data(as_text=True))
    return client.post("/login", data={"usuario": usuario, "clave": clave,
                                       **({"csrf_token": token.group(1)} if token else {})})


def test_vuln04_clave_por_defecto_admin_ya_no_funciona(client):
    assert _login(client, "admin", "admin").status_code == 401


def test_vuln04_hash_robusto_y_login_correcto(client, monkeypatch):
    from werkzeug.security import generate_password_hash
    monkeypatch.setattr(modulo_app, "ADMIN_CLAVE_HASH", generate_password_hash("Clave-Larga-De-Prueba-2026"))
    assert modulo_app.ADMIN_CLAVE_HASH.startswith(("pbkdf2:", "scrypt:"))
    assert _login(client, "admin", "Clave-Larga-De-Prueba-2026").status_code == 200


def test_vuln05_login_sin_token_csrf_se_rechaza(client):
    r = client.post("/login", data={"usuario": "admin", "clave": "admin"})
    assert r.status_code == 400


def test_vuln05_portada_incluye_token_csrf(client):
    assert 'name="csrf_token" value="' in client.get("/").get_data(as_text=True)


def test_vuln06_fuerza_bruta_bloquea_con_429(client):
    codigos = [_login(client, "admin", f"clave-{i}").status_code for i in range(modulo_app.MAX_FALLIDOS + 2)]
    assert codigos[:modulo_app.MAX_FALLIDOS] == [401] * modulo_app.MAX_FALLIDOS
    assert codigos[-1] == 429


def test_vuln08_cabeceras_de_seguridad(client):
    r = client.get("/")
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
