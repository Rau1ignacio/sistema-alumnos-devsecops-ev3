"""Pruebas de regresión de seguridad: cada una verifica que una vulnerabilidad corregida (VULN-xx) no vuelva."""
import pytest

import app as modulo_app


@pytest.fixture
def client():
    modulo_app.app.config["TESTING"] = True
    with modulo_app.app.test_client() as c:
        yield c


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
