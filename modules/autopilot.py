#!/usr/bin/env python3
"""
Modo autopiloto (--auto).

Es un motor de reglas, NO un LLM tomando decisiones -- eso ya existe
por separado en llm_assist.py (--assist), que sí llama a un modelo real
y cuesta una petición de API. --auto es determinista y gratis: son
reglas de "si ves X, activa Y" escritas a mano, basadas en heurísticas
razonables de qué hace un analista humano con experiencia. Se llama
"autopiloto" y no "IA" a propósito, para no prometer algo que no es.

Cada decisión se registra con su justificación en
01_target/decisiones-autopiloto.md, para que el modo autónomo nunca
sea una caja negra -- el usuario siempre puede ver el "por qué".

Con un solo flag (--auto), reemplaza tener que elegir entre --deep,
--smart, --screenshots, --pdf-report, --export-tickets,
--custom-templates, --html-report, --attack-graph uno por uno.

Filosofía de seguridad: --auto NUNCA activa por sí solo lo que toca el
objetivo más allá de lectura (--active-verify, --auto-exploit,
--param-fuzz) -- esos siguen requiriendo que el usuario los pida
explícitamente, autopiloto o no. Autonomía en QUÉ DOCUMENTAR, nunca en
QUÉ TAN AGRESIVO SER contra el objetivo.
"""

from pathlib import Path

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


class Decisiones:
    """Acumula las decisiones tomadas con su justificación, para volcarlas
    a un archivo legible al final -- la 'explicación' del autopiloto."""

    def __init__(self):
        self._registro = []

    def decidir(self, flag, valor, razon):
        self._registro.append({"flag": flag, "valor": valor, "razon": razon})
        marca = "✓" if valor else "✗"
        print(colored(f"[autopiloto] {marca} {flag} = {valor} — {razon}", "cyan"))

    def escribir(self, folder):
        output = Path(folder) / "01_target" / "decisiones-autopiloto.md"
        output.parent.mkdir(parents=True, exist_ok=True)

        lines = ["# Decisiones del modo autopiloto (--auto)", "",
                 "Motor de reglas determinista, no un LLM. Cada decisión "
                 "tiene una razón explícita listada abajo.", ""]

        for d in self._registro:
            marca = "Activado" if d["valor"] else "No activado"
            lines.append(f"- **{d['flag']}** → {marca}: {d['razon']}")

        output.write_text("\n".join(lines), encoding="utf-8")


def decidir_intensidad_inicial(args, decisiones):
    """
    Antes de escanear nada, la única decisión posible es conservadora:
    empezar con un escaneo normal (no --deep), porque --deep implica
    UDP top1000 + NSE vuln, que puede tardar mucho en máquinas con
    muchos puertos -- se escala después de ver los puertos reales.
    """
    if not args.deep:
        decisiones.decidir("deep", False, "Se decide tras ver los puertos reales (fase 2), no antes.")
    return args


def decidir_tras_puertos(args, decisiones, puertos, puertos_udp=None):
    """
    Con los puertos TCP ya conocidos: decide si vale la pena escalar a
    --deep (NSE vuln + nuclei), basado en cuántos servicios "interesantes"
    hay -- una máquina con 2 puertos no necesita el mismo esfuerzo que
    una con 15.
    """
    puertos_interesantes = len([p for p in puertos if p not in (22,)])  # SSH solo no cuenta

    if puertos_interesantes >= 4 and not args.deep:
        args.deep = True
        decisiones.decidir("deep", True, f"{puertos_interesantes} puertos no-SSH detectados, vale la pena el escaneo agresivo.")
    elif not args.deep:
        decisiones.decidir("deep", False, f"Solo {puertos_interesantes} puerto(s) interesante(s), --deep no aporta mucho aquí.")

    tiene_web = any(p in (80, 443, 8080, 8443, 8000, 8888) for p in puertos)
    tiene_smb = 445 in puertos or 139 in puertos
    es_posible_dc = {88, 389, 445}.issubset(set(puertos))

    if tiene_web and not args.screenshots:
        args.screenshots = True
        decisiones.decidir("screenshots", True, "Hay servicio(s) web, vale la pena documentar visualmente.")
    elif not tiene_web:
        decisiones.decidir("screenshots", False, "No hay servicios web detectados.")

    if tiene_web and not args.custom_templates:
        args.custom_templates = True
        decisiones.decidir("custom_templates", True, "Hay web expuesta, se corren los templates de verificación disponibles.")

    if es_posible_dc:
        decisiones.decidir("posible_dc", True, "Patrón Kerberos+LDAP+SMB detectado -- se intentará AD si aparece un dominio confiable.")
    elif tiene_smb:
        decisiones.decidir("smb_standalone", True, "SMB sin patrón completo de AD -- probablemente Samba/Windows standalone.")

    return args


def decidir_tras_hostname(args, decisiones, hostnames_confirmados, puertos):
    """
    Una vez hay un hostname CONFIRMADO en /etc/hosts (no solo candidato):
    si además hay patrón de DC, ahora sí se activa AD -- nunca antes,
    porque adivinar un dominio sin evidencia real generaría ruido de
    kerbrute contra un dominio inventado.
    """
    es_posible_dc = {88, 389, 445}.issubset(set(puertos))

    if es_posible_dc and hostnames_confirmados and not args.ad_domain:
        dominio = sorted(hostnames_confirmados)[0]
        args.ad_domain = dominio
        decisiones.decidir("ad_domain", dominio, f"Patrón de DC + hostname confirmado ({dominio}) -- se activa enumeración AD.")

    return args


def decidir_reportes_finales(args, decisiones, findings, puertos):
    """
    Al final, con los findings ya conocidos: decide qué reportes generar.
    Un PDF y tickets solo tienen sentido si hay algo que reportar; un
    grafo de ataque solo aporta si hay más de un tipo de nodo relevante.
    """
    tiene_web = any(p in (80, 443, 8080, 8443, 8000, 8888) for p in puertos)

    if (findings or tiene_web) and not args.pdf_report:
        args.pdf_report = True
        decisiones.decidir("pdf_report", True, "Hay findings o superficie web suficiente para justificar un reporte.")
    elif not findings and not tiene_web:
        decisiones.decidir("pdf_report", False, "Sin findings ni web, un PDF no aportaría mucho todavía.")

    if findings and not args.export_tickets:
        args.export_tickets = "ambos"
        decisiones.decidir("export_tickets", "ambos", f"{len(findings)} finding(s) encontrados, vale la pena tenerlos como tickets.")

    if len(findings) >= 2 and not args.attack_graph:
        args.attack_graph = True
        decisiones.decidir("attack_graph", True, f"{len(findings)} findings -- suficientes para que un grafo de relaciones aporte algo.")
    elif len(findings) < 2:
        decisiones.decidir("attack_graph", False, "Muy pocos findings para que un grafo de ataque aporte claridad.")

    return args
