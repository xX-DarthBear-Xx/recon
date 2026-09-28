#!/usr/bin/env python3
"""
Modo offline (--offline): correlación de CVEs sin tocar la red.

Usa una base SQLite local (~/.recon/cve_offline.db) poblada de
antemano con un dump de la NVD (ver descargar_dump_nvd(), que SÍ
requiere red -- se corre una vez, con conexión, antes de ir a un
examen/entorno air-gapped). Durante el recon en sí, con --offline, la
correlación consulta solo esta base local, nunca internet.
"""

import json
import sqlite3
from pathlib import Path

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

DB_PATH = Path.home() / ".recon" / "cve_offline.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product TEXT NOT NULL,
    version TEXT,
    cve_id TEXT NOT NULL,
    severity TEXT,
    cvss REAL,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);
"""


def _conectar():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def base_disponible():
    if not DB_PATH.exists():
        return False
    conn = _conectar()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cves")
    total = cur.fetchone()[0]
    conn.close()
    return total > 0


def importar_dump_json(ruta_json):
    """
    Importa un archivo JSON con la forma:
        [{"product": "Apache httpd", "version": "2.4.49", "cve_id": "CVE-2021-41773",
          "severity": "HIGH", "cvss": 7.5, "description": "..."}, ...]
    """
    data = json.loads(Path(ruta_json).read_text(encoding="utf-8"))

    conn = _conectar()
    cur = conn.cursor()
    for entrada in data:
        cur.execute(
            "INSERT INTO cves (product, version, cve_id, severity, cvss, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                entrada.get("product", ""), entrada.get("version", ""),
                entrada.get("cve_id", ""), entrada.get("severity", ""),
                entrada.get("cvss"), entrada.get("description", ""),
            ),
        )
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    conn.close()

    print(colored(f"[+] Base offline poblada: {total} CVE(s) en {DB_PATH}", "green"))
    return total


def consultar_offline(product, version, max_resultados=5):
    """Equivalente offline de vuln_correlation.consultar_nvd()."""
    if not DB_PATH.exists():
        return []

    conn = _conectar()
    cur = conn.cursor()

    cur.execute(
        "SELECT cve_id, severity, cvss, description FROM cves "
        "WHERE product LIKE ? LIMIT ?",
        (f"%{product}%", max_resultados),
    )
    filas = cur.fetchall()
    conn.close()

    return [
        {"cve_id": f[0], "severity": f[1] or "UNKNOWN", "cvss": f[2],
         "description": f[3] or "", "references": []}
        for f in filas
    ]


def descargar_dump_nvd(salida_json, keywords, api_delay=6):
    """
    Utilidad de UNA SOLA VEZ, con red, para poblar el dump antes de ir a
    un entorno air-gapped. Reutiliza vuln_correlation.consultar_nvd().
    """
    from modules.vuln_correlation import consultar_nvd
    import time

    resultados = []
    for kw in keywords:
        print(colored(f"[+] Descargando CVEs para '{kw}'...", "cyan"))
        cves = consultar_nvd(kw, "")
        for c in cves:
            resultados.append({
                "product": kw, "version": "", "cve_id": c["cve_id"],
                "severity": c["severity"], "cvss": c["cvss"],
                "description": c["description"],
            })
        time.sleep(api_delay)

    Path(salida_json).write_text(json.dumps(resultados, indent=2, ensure_ascii=False), encoding="utf-8")
    print(colored(f"[+] Dump guardado en {salida_json} ({len(resultados)} entradas)", "green"))
    return resultados
