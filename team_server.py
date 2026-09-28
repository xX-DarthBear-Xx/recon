#!/usr/bin/env python3
"""
team_server.py - Backend mínimo para uso colaborativo en CTFs de equipo.

Cada miembro corre recon.py normalmente, y con --team-server URL envía
un resumen de su corrida a este servidor (POST /runs). El servidor
acumula todo en su propia SQLite (independiente del ~/.recon/history.db
local de cada uno) y expone:

    GET  /              -> dashboard HTML simple con el estado combinado
    GET  /machine/<ip>  -> detalle de lo que ha aportado cada miembro sobre esa IP
    POST /runs           -> recibe un payload JSON de una corrida

Pensado para levantarse en una máquina del equipo (o localhost si están
en la misma red de VPN), NO para exponerse a internet -- no tiene auth,
a propósito de mantenerlo simple para v3.0; si lo despliegas en red
abierta, ponle un reverse proxy con autenticación.
"""

import sqlite3
import os
import json
from pathlib import Path
from datetime import datetime

try:
    from flask import Flask, request, jsonify, render_template_string
except ImportError:
    Flask = None

DB_PATH = Path.home() / ".recon" / "team_server.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS team_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member TEXT NOT NULL,
    ip TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    tcp_ports TEXT,
    findings TEXT
);
"""


def _conectar():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


TEMPLATE = """
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Team Recon Server</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width:900px; margin:40px auto; background:#0f172a; color:#e2e8f0; }
  h1 { color:#38bdf8; }
  table { width:100%; border-collapse:collapse; margin-top:16px; }
  th, td { text-align:left; padding:8px; border-bottom:1px solid #334155; }
</style></head><body>
<h1>Team Recon Server</h1>
<table>
<tr><th>Máquina</th><th>Miembro</th><th>Puertos TCP</th><th>Findings</th><th>Hora</th></tr>
{% for r in runs %}
<tr><td>{{ r[2] }}</td><td>{{ r[1] }}</td><td>{{ r[4] }}</td><td>{{ r[6] }}</td><td>{{ r[3] }}</td></tr>
{% endfor %}
</table>
</body></html>
"""


def crear_app():
    if Flask is None:
        raise ImportError("Flask no está instalado. pip install flask --break-system-packages")

    app = Flask(__name__)

    @app.route("/runs", methods=["POST"])
    def recibir_run():
        payload = request.get_json(force=True)

        conn = _conectar()
        conn.execute(
            "INSERT INTO team_runs (member, ip, submitted_at, tcp_ports, findings) VALUES (?, ?, ?, ?, ?)",
            (
                payload.get("member", "anonimo"),
                payload.get("ip", ""),
                datetime.now().isoformat(),
                json.dumps(payload.get("tcp_ports", [])),
                json.dumps(payload.get("findings", [])),
            ),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})

    @app.route("/")
    def index():
        conn = _conectar()
        cur = conn.cursor()
        cur.execute("SELECT id, member, ip, submitted_at, tcp_ports, findings FROM team_runs ORDER BY submitted_at DESC LIMIT 100")
        filas = cur.fetchall()
        conn.close()

        runs = []
        for f in filas:
            findings = json.loads(f[5] or "[]")
            runs.append((f[0], f[1], f[2], f[3], f[4], f[5], len(findings)))

        return render_template_string(TEMPLATE, runs=runs)

    @app.route("/machine/<ip>")
    def detalle_maquina(ip):
        conn = _conectar()
        cur = conn.cursor()
        cur.execute("SELECT member, submitted_at, tcp_ports, findings FROM team_runs WHERE ip = ? ORDER BY submitted_at", (ip,))
        filas = cur.fetchall()
        conn.close()
        return jsonify([
            {"member": f[0], "submitted_at": f[1], "tcp_ports": json.loads(f[2]), "findings": json.loads(f[3])}
            for f in filas
        ])

    return app


def enviar_corrida(server_url, member, ip, tcp_ports, findings):
    """Usado desde recon.py con --team-server <url>."""
    import requests

    try:
        requests.post(
            f"{server_url.rstrip('/')}/runs",
            json={"member": member, "ip": ip, "tcp_ports": tcp_ports, "findings": findings},
            timeout=10,
        )
        print(f"[+] Corrida enviada al servidor de equipo: {server_url}")
    except Exception as e:
        print(f"[!] No se pudo enviar al servidor de equipo: {e}")


if __name__ == "__main__":
    if Flask is None:
        print("[!] Flask no está instalado.")
    else:
        app = crear_app()
        # Fix de seguridad: antes escuchaba en 0.0.0.0 sin autenticación,
        # exponiendo /runs (escritura) y /machine/<ip> (lectura) a
        # cualquiera en la misma red/VPN. Por defecto ahora solo
        # localhost; para uso real de equipo, exponlo detrás de un
        # reverse proxy con autenticación, o define TEAM_SERVER_ALLOW_LAN=1
        # si entiendes el riesgo y tu red es de confianza real.
        host = "0.0.0.0" if os.environ.get("TEAM_SERVER_ALLOW_LAN") == "1" else "127.0.0.1"
        if host == "0.0.0.0":
            print("[!] TEAM_SERVER_ALLOW_LAN=1: escuchando en toda la red, SIN autenticación. Úsalo solo en una red de confianza.")
        print(f"[+] Team server en http://{host}:5001")
        app.run(host=host, port=5001, debug=False)
