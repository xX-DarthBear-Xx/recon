#!/usr/bin/env python3
"""
Módulo de correlación de vulnerabilidades (CVE).

Flujo:
    Nmap (targeted.xml) -> productos/versiones detectados
        -> consulta a NVD (CVE + CVSS)
        -> consulta a GitHub (búsqueda de PoCs públicos, sin clonar)
        -> nivel de confianza (HIGH/MEDIUM/LOW) según granularidad de versión
        -> findings.json + findings.md

No marca nada como "VULNERABLE" de forma definitiva: todo queda como
"POTENTIALLY VULNERABLE" salvo que --deep con nuclei confirme coincidencia
de plantilla (entonces sube a VERIFIED).

Requiere red saliente. Si no hay conexión, el módulo avisa y no rompe el
resto del recon.
"""

import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

try:
    import requests
except ImportError:
    requests = None

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"

# Ser buen ciudadano con las APIs públicas (sin API key, límites bajos)
NVD_DELAY = 6          # NVD sin key: ~6s entre requests recomendado
GITHUB_DELAY = 2


# ============================================================
# 1. EXTRACCIÓN DE PRODUCTO/VERSIÓN DESDE NMAP XML
# ============================================================

def extraer_servicios_desde_xml(xml_path):
    """
    Devuelve una lista de dicts: {port, protocol, product, version, service}
    a partir del XML de nmap -sCV (targeted.xml).
    """
    servicios = []

    if not xml_path.exists():
        return servicios

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return servicios

    root = tree.getroot()

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for port_el in ports.findall("port"):
            service = port_el.find("service")
            if service is None:
                continue

            product = service.get("product")
            version = service.get("version")

            if not product:
                continue

            servicios.append({
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol"),
                "service": service.get("name", ""),
                "product": product,
                "version": version or "",
            })

    return servicios


# ============================================================
# 2. NIVEL DE CONFIANZA
# ============================================================

def calcular_confianza(version_detectada, version_afectada):
    """
    Heurística simple de confianza según granularidad de la versión.
    """
    if not version_detectada:
        return "LOW"

    # Versión exacta detectada (ej. "2.4.49") y coincide tal cual con la
    # que reporta el CVE como afectada.
    if version_detectada == version_afectada:
        return "HIGH"

    # Solo se conoce la rama mayor.minor (ej. "2.4.x")
    if re.match(r"^\d+\.\d+$", version_detectada):
        return "MEDIUM"

    return "LOW"


# ============================================================
# 3. CONSULTA A NVD
# ============================================================

def consultar_nvd(product, version, max_resultados=5):
    """
    Busca CVEs relacionados con `product` (y opcionalmente version) en NVD.
    Devuelve lista de dicts con cve_id, severity, cvss, description, references.
    """
    if requests is None:
        print(colored("[!] Falta 'requests'. Instálalo con: pip install requests", "red"))
        return []

    keyword = f"{product} {version}".strip()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_resultados,
    }

    data = None
    intentos = 3

    for intento in range(1, intentos + 1):
        try:
            resp = requests.get(NVD_API, params=params, timeout=15)

            if resp.status_code == 429:
                espera = NVD_DELAY * intento * 2
                print(colored(
                    f"[!] NVD rate-limit (429). Reintentando en {espera}s "
                    f"({intento}/{intentos})...", "yellow"
                ))
                time.sleep(espera)
                continue

            resp.raise_for_status()
            data = resp.json()
            break

        except Exception as e:
            print(colored(f"[!] Error consultando NVD para '{keyword}': {e}", "yellow"))
            return []

    if data is None:
        print(colored(f"[!] NVD siguió con rate-limit tras {intentos} intentos, se omite '{keyword}'.", "red"))
        return []

    resultados = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descripciones = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descripciones if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss_data = metrics[metric_key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", metrics[metric_key][0].get("baseSeverity", "UNKNOWN"))
                break

        references = [ref.get("url") for ref in cve.get("references", [])][:5]

        resultados.append({
            "cve_id": cve_id,
            "description": desc_en[:400],
            "cvss": cvss_score,
            "severity": severity,
            "references": references,
        })

    time.sleep(NVD_DELAY)
    return resultados


# ============================================================
# 4. BÚSQUEDA DE POC PÚBLICO EN GITHUB (sin clonar)
# ============================================================

def buscar_poc_github(cve_id):
    """
    Busca repositorios públicos relacionados al CVE. Solo devuelve URL y
    metadata, nunca clona nada.
    """
    if requests is None:
        return []

    try:
        resp = requests.get(
            GITHUB_SEARCH_API,
            params={"q": cve_id, "sort": "stars", "order": "desc", "per_page": 3},
            headers={"Accept": "application/vnd.github+json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(colored(f"[!] Error buscando PoC en GitHub para {cve_id}: {e}", "yellow"))
        return []

    pocs = []
    for repo in data.get("items", []):
        pocs.append({
            "repo": repo.get("full_name"),
            "url": repo.get("html_url"),
            "stars": repo.get("stargazers_count", 0),
        })

    time.sleep(GITHUB_DELAY)
    return pocs


# ============================================================
# 5. VERIFICACIÓN OPCIONAL CON NUCLEI
# ============================================================

def verificar_con_nuclei(urls, folder):
    """
    Si nuclei está instalado y hay URLs web, corre templates orientados a
    CVEs conocidos. Devuelve el texto de salida crudo (para cruce manual)
    y también lo guarda en 06_vulnerabilities/nuclei.txt.
    """
    from modules.utils import run_command, tool_exists

    if not urls or not tool_exists("nuclei"):
        return ""

    output = folder / "06_vulnerabilities" / "nuclei.txt"
    salida = run_command(
        ["nuclei", "-u", ",".join(urls), "-severity", "medium,high,critical", "-silent"],
        output,
    )
    return salida or ""


# ============================================================
# 6. ORQUESTADOR: CORRELACIÓN COMPLETA
# ============================================================

def correlacionar_vulnerabilidades(folder, urls=None, deep=False, offline=False):
    """
    Punto de entrada del módulo. Lee 03_nmap/targeted.xml, consulta NVD
    (o la base local si offline=True) y GitHub (se omite en modo
    offline, no tiene sentido buscar PoCs sin red), opcionalmente cruza
    con nuclei si --deep, y escribe 06_vulnerabilities/findings.md +
    findings.json.
    """
    if offline:
        from modules.offline_cve import consultar_offline, base_disponible
        if not base_disponible():
            print(colored(
                "[!] --offline activado pero no hay base local poblada. "
                "Corre prepare_offline.py primero (con red) antes de venir "
                "al entorno air-gapped.", "red"
            ))
            return []
    elif requests is None:
        print(colored(
            "[!] Módulo de vulnerabilidades desactivado: falta 'requests' "
            "(pip install requests).", "red"
        ))
        return []

    xml_path = folder / "03_nmap" / "targeted.xml"
    servicios = extraer_servicios_desde_xml(xml_path)

    if not servicios:
        print(colored("[!] No se detectaron productos/versiones para correlacionar CVEs.", "yellow"))
        return []

    fuente = "base offline local" if offline else "NVD"
    print(colored(f"\n[+] Correlacionando {len(servicios)} servicio(s) con {fuente}...", "cyan"))

    nuclei_output = verificar_con_nuclei(urls, folder) if (deep and not offline) else ""

    findings = []

    for svc in servicios:
        product = svc["product"]
        version = svc["version"]

        if not version:
            # Sin versión no hay mucho que correlacionar de forma fiable
            continue

        if offline:
            from modules.offline_cve import consultar_offline
            cves = consultar_offline(product, version)
        else:
            cves = consultar_nvd(product, version)

        for cve in cves:
            confidence = calcular_confianza(version, version)  # heurística base
            status = "POTENTIAL"

            if nuclei_output and cve["cve_id"] in nuclei_output:
                status = "VERIFIED"
                confidence = "HIGH"

            pocs = [] if offline else buscar_poc_github(cve["cve_id"])

            findings.append({
                "service": svc["service"],
                "product": product,
                "version": version,
                "port": svc["port"],
                "cve": cve["cve_id"],
                "severity": cve["severity"],
                "cvss": cve["cvss"],
                "description": cve["description"],
                "status": status,
                "confidence": confidence,
                "references": cve["references"],
                "poc": pocs,
            })

    escribir_findings_json(folder, findings)
    escribir_findings_md(folder, findings)

    print(colored(f"[+] {len(findings)} finding(s) potencial(es) registrados.", "green"))
    return findings


# ============================================================
# 7. SALIDA: findings.json y findings.md
# ============================================================

def _leer_findings_existentes(folder):
    """Lee findings.json ya generado en una corrida previa (usado por --resume)."""
    findings_path = Path(folder) / "06_vulnerabilities" / "findings.json"
    if not findings_path.exists():
        return []
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        return data.get("findings", [])
    except Exception:
        return []


def escribir_findings_json(folder, findings):
    output = folder / "06_vulnerabilities" / "findings.json"
    output.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "target": folder.name if hasattr(folder, "name") else str(folder),
        "findings": findings,
    }

    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def escribir_findings_md(folder, findings):
    output = folder / "06_vulnerabilities" / "findings.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# Vulnerability Findings", ""]

    if not findings:
        lines.append("No se encontraron correlaciones de CVE para los servicios detectados.")
    else:
        for f in sorted(findings, key=lambda x: (x.get("severity") or ""), reverse=True):
            lines += [
                f"## [{f.get('severity', '?')}] {f.get('cve', '?')}", "",
                "**Service**", f"{f.get('product', '?')}", "",
                "**Version**", f"{f.get('version', '?')}", "",
                "**Port**", f"{f.get('port', '?')}", "",
                "**Status**", f"{f.get('status', '?')}", "",
                "**Confidence**", f"{f.get('confidence', '?')}", "",
                "**CVSS**", f"{f.get('cvss', '?')}", "",
                "**Description**", f"{f.get('description', '')}", "",
                "**References**",
            ]
            lines += [f"- {ref}" for ref in f.get("references", [])] or ["- (sin referencias)"]

            lines += ["", "**Public PoC**"]
            if f.get("poc"):
                for poc in f["poc"]:
                    lines.append(f"- {poc.get('repo', '?')} ({poc.get('stars', 0)}⭐) — {poc.get('url', '?')}")
            else:
                lines.append("- No encontrado en GitHub")

            lines += ["", "---", ""]

    output.write_text("\n".join(lines), encoding="utf-8")
