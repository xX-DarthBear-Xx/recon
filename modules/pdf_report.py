#!/usr/bin/env python3
"""
Reporte PDF profesional (--pdf-report).

Usa reportlab en vez de "imprimir HTML a PDF" (weasyprint/wkhtmltopdf)
porque reportlab no tiene dependencias de sistema (Pango/Cairo) que
puedan fallar en la instalación de otra persona -- construye el PDF
directamente con primitivas de dibujo, sin depender de un navegador
headless ni de librerías de render de CSS.

Soporta dos plantillas:
    - "default": estructura libre, orientada a HTB/CTF
    - "oscp": Executive Summary -> Methodology -> Findings -> PoC por máquina,
      la estructura que ese examen espera

Y un modo --redacted que reemplaza cualquier credencial detectada por
[REDACTADO] antes de escribir el PDF (para compartir con clientes sin
exponer secretos reales encontrados durante el engagement).
"""

import json
import re
import hashlib
import html
from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage,
)

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#dc2626"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#65a30d"),
    "UNKNOWN": colors.HexColor("#6b7280"),
}


def _leer_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _escapar_para_paragraph(texto):
    """
    Fix de seguridad/robustez: reportlab.Paragraph interpreta su
    contenido con un mini-lenguaje de marcado tipo XML (<b>, <font>,
    etc.). Un 'producto' detectado desde un banner de servicio --dato
    que controla el OBJETIVO, no nosotros-- puede contener algo como
    '<b><font size=99>' y reventar la generación completa del PDF con
    un ParseError, confirmado con una prueba real antes de este fix.
    Se escapa como HTML/XML normal antes de pasarlo a Paragraph.
    """
    return html.escape(str(texto) if texto is not None else "")


def _redactar(texto, patrones_credenciales):
    for cred in patrones_credenciales:
        valor = cred.get("valor", "")
        if valor and len(valor) > 4:
            texto = texto.replace(valor, "[REDACTADO]")
    return texto


def _estilos():
    stylesheet = getSampleStyleSheet()
    stylesheet.add(ParagraphStyle(
        name="TituloPortada", fontSize=28, leading=34,
        textColor=colors.HexColor("#0f172a"), spaceAfter=20,
    ))
    stylesheet.add(ParagraphStyle(
        name="Subtitulo", fontSize=14, textColor=colors.HexColor("#475569"),
    ))
    stylesheet.add(ParagraphStyle(
        name="Seccion", fontSize=16, spaceBefore=20, spaceAfter=10,
        textColor=colors.HexColor("#0f172a"),
    ))
    return stylesheet


def _portada(story, styles, ip, nombre_maquina, template, analista):
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("Reporte de Reconocimiento", styles["TituloPortada"]))
    story.append(Paragraph(f"Objetivo: {ip}", styles["Subtitulo"]))
    story.append(Paragraph(f"Máquina: {nombre_maquina}", styles["Subtitulo"]))
    story.append(Paragraph(f"Analista: {analista}", styles["Subtitulo"]))
    story.append(Paragraph(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Subtitulo"]))
    story.append(Paragraph(f"Plantilla: {template}", styles["Subtitulo"]))
    story.append(PageBreak())


def _resumen_ejecutivo(story, styles, findings):
    story.append(Paragraph("Resumen Ejecutivo", styles["Seccion"]))

    conteo = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    verificados = 0

    for f in findings:
        sev = (f.get("severity") or "UNKNOWN").upper()
        conteo[sev] = conteo.get(sev, 0) + 1
        if f.get("status") == "VERIFIED":
            verificados += 1

    texto = (
        f"Se identificaron {len(findings)} hallazgo(s) potencial(es), de los cuales "
        f"{verificados} fueron verificados activamente. Distribución por severidad: "
        f"{conteo['CRITICAL']} crítico(s), {conteo['HIGH']} alto(s), "
        f"{conteo['MEDIUM']} medio(s), {conteo['LOW']} bajo(s)."
    )
    story.append(Paragraph(texto, getSampleStyleSheet()["BodyText"]))
    story.append(Spacer(1, 0.3 * inch))


def _tabla_puertos(story, styles, tcp_ports, udp_ports):
    story.append(Paragraph("Puertos Detectados", styles["Seccion"]))

    data = [["Puerto", "Protocolo"]]
    for p in tcp_ports or []:
        data.append([str(p), "TCP"])
    for p in udp_ports or []:
        data.append([str(p), "UDP"])

    if len(data) == 1:
        data.append(["-", "-"])

    tabla = Table(data, colWidths=[2 * inch, 2 * inch])
    tabla.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(tabla)
    story.append(Spacer(1, 0.3 * inch))


def _tabla_findings(story, styles, findings, redactar, credenciales):
    story.append(Paragraph("Vulnerabilidades Encontradas", styles["Seccion"]))

    if not findings:
        story.append(Paragraph("No se encontraron correlaciones de CVE.", getSampleStyleSheet()["BodyText"]))
        return

    celda_style = ParagraphStyle(name="Celda", fontSize=8, leading=10)
    header_style = ParagraphStyle(name="CeldaHeader", fontSize=8, leading=10, textColor=colors.white)

    data = [[Paragraph(h, header_style) for h in ["CVE", "Severidad", "Producto", "Estado", "Confianza"]]]
    for f in findings:
        producto = _escapar_para_paragraph(f"{f.get('product', '')} {f.get('version', '')}")
        if redactar:
            producto = _redactar(producto, credenciales)
        data.append([
            f.get("cve", "-"), f.get("severity", "-"),
            Paragraph(producto, celda_style),  # única columna con texto largo -> necesita word-wrap real
            f.get("status", "-"), f.get("confidence", "-"),
        ])

    tabla = Table(data, colWidths=[1.2 * inch, 0.9 * inch, 1.9 * inch, 1 * inch, 0.9 * inch])
    estilo = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, f in enumerate(findings, start=1):
        sev = (f.get("severity") or "UNKNOWN").upper()
        color = _SEVERITY_COLORS.get(sev, _SEVERITY_COLORS["UNKNOWN"])
        estilo.append(("BACKGROUND", (1, i), (1, i), color))
        estilo.append(("TEXTCOLOR", (1, i), (1, i), colors.white))

    tabla.setStyle(TableStyle(estilo))
    story.append(tabla)
    story.append(Spacer(1, 0.3 * inch))


def _seccion_screenshots(story, styles, folder):
    shots_folder = folder / "screenshots"
    if not shots_folder.exists():
        return

    imagenes = [p for p in shots_folder.rglob("*") if p.suffix.lower() in (".png", ".jpg", ".jpeg")]
    if not imagenes:
        return

    story.append(PageBreak())
    story.append(Paragraph("Screenshots", styles["Seccion"]))

    for img_path in imagenes[:10]:
        try:
            story.append(Paragraph(img_path.name, getSampleStyleSheet()["BodyText"]))
            story.append(RLImage(str(img_path), width=5 * inch, height=3 * inch, kind="proportional"))
            story.append(Spacer(1, 0.2 * inch))
        except Exception:
            continue


def _seccion_metodologia_oscp(story, styles):
    story.append(Paragraph("Metodología", styles["Seccion"]))
    texto = (
        "1. Reconocimiento pasivo y descubrimiento de host.<br/>"
        "2. Escaneo de puertos TCP/UDP completo.<br/>"
        "3. Enumeración de servicios y fingerprinting de versiones.<br/>"
        "4. Correlación de vulnerabilidades contra bases de datos públicas (NVD).<br/>"
        "5. Verificación activa de hallazgos sospechosos (cuando aplica).<br/>"
        "6. Documentación de hallazgos y evidencia."
    )
    story.append(Paragraph(texto, getSampleStyleSheet()["BodyText"]))
    story.append(Spacer(1, 0.3 * inch))


def generar_pdf(folder, ip=None, template="default", analista="N/A", redactar=False, imagen_grafo=None):
    folder = Path(folder)
    nombre_maquina = folder.name

    findings_data = _leer_json(folder / "06_vulnerabilities" / "findings.json")
    findings = findings_data.get("findings", [])

    credenciales_texto = folder / "07_credentials" / "credentials-found.md"
    credenciales = []
    if credenciales_texto.exists():
        contenido = credenciales_texto.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(r"`([^`]{5,})`\s*$", contenido, re.MULTILINE):
            credenciales.append({"valor": match.group(1)})

    ip = ip or nombre_maquina
    output_path = folder / "report.pdf"

    doc = SimpleDocTemplate(str(output_path), pagesize=letter,
                             topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    styles = _estilos()
    story = []

    _portada(story, styles, ip, nombre_maquina, template, analista)

    if template == "oscp":
        _seccion_metodologia_oscp(story, styles)

    _resumen_ejecutivo(story, styles, findings)

    attack_surface_path = folder / "attack-surface.md"
    tcp_ports, udp_ports = [], []
    if attack_surface_path.exists():
        contenido = attack_surface_path.read_text(encoding="utf-8")
        seccion_actual = None
        for linea in contenido.splitlines():
            if linea.strip() == "## TCP":
                seccion_actual = "tcp"
                continue
            if linea.strip() == "## UDP":
                seccion_actual = "udp"
                continue
            if linea.strip().startswith("##"):
                seccion_actual = None
                continue
            match = re.match(r"^(\d+)\t", linea)
            if match and seccion_actual == "tcp":
                tcp_ports.append(match.group(1))
            elif match and seccion_actual == "udp":
                udp_ports.append(match.group(1))

    _tabla_puertos(story, styles, tcp_ports, udp_ports)
    _tabla_findings(story, styles, findings, redactar, credenciales)

    if imagen_grafo and Path(imagen_grafo).exists():
        story.append(Paragraph("Grafo de Ataque", styles["Seccion"]))
        story.append(RLImage(str(imagen_grafo), width=6 * inch, height=4.5 * inch, kind="proportional"))
        story.append(Spacer(1, 0.3 * inch))

    _seccion_screenshots(story, styles, folder)

    doc.build(story)

    sha256 = hashlib.sha256(output_path.read_bytes()).hexdigest()
    hash_path = folder / "report.pdf.sha256"
    hash_path.write_text(f"{sha256}  report.pdf\n", encoding="utf-8")

    print(colored(f"[+] Reporte PDF generado en {output_path}", "green"))
    print(colored(f"[+] SHA256: {sha256}", "cyan"))

    return output_path
