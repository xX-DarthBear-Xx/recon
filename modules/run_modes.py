#!/usr/bin/env python3
"""
Modos de ejecución (v5.0).

CORE es deliberadamente pequeño: nmap TCP/UDP, enumeración de servicios,
web básico, correlación de CVEs, reporting (README/attack-surface). Es
lo que casi cualquier corrida real usa.

Todo lo demás (AD, LLM, grafos, team-server, PDF, templates propios,
tickets, param-fuzz, webhooks, verificación activa) es EXTENDIDO --
sigue existiendo y sigue siendo tan real como antes, pero con
--core-only se apaga de un solo flag en vez de tener que acordarte de
no pasar quince flags distintos.

--smart no activa TODO lo extendido de una: activa selectivamente según
lo que se va descubriendo durante la corrida (ver aplicar_smart_mid_run).
"""

FASES_EXTENDIDAS = [
    "ad_recon", "llm_assist", "attack_graph", "active_verify",
    "team_server", "webhook", "pdf_report", "export_tickets",
    "custom_templates", "param_fuzz", "auto_exploit", "screenshots",
    "html_report",
]


def aplicar_core_only(args):
    """
    Apaga toda la funcionalidad extendida de golpe. No toca --deep,
    --profile, --resume, --lang -- esos son "modo de escaneo", no
    "funcionalidad extra", y siguen aplicando igual en core.
    """
    if not getattr(args, "core_only", False):
        return args

    args.ad_domain = None
    args.ad_userlist = None
    args.assist = False
    args.attack_graph = False
    args.active_verify = False
    args.team_server = None
    args.webhook_url = None
    args.pdf_report = False
    args.export_tickets = None
    args.custom_templates = False
    args.param_fuzz = False
    args.auto_exploit = False
    args.screenshots = False
    args.html_report = False

    print("[+] --core-only: solo nmap + web + CVE + reporting. Todo lo extendido está desactivado.")
    return args


def aplicar_smart_inicial(args):
    """
    --smart no adivina nada antes de tener datos -- al inicio solo
    activa lo que es barato y siempre útil (verificación activa liviana,
    grafo de ataque) y deja el resto para decidirse a mitad de corrida
    con aplicar_smart_mid_run(), una vez ya hay puertos/servicios reales
    que mirar.
    """
    if not getattr(args, "smart", False):
        return args

    args.attack_graph = True
    args.active_verify = True
    print("[+] --smart: activado. Se ajustará dinámicamente según lo que se descubra.")
    return args


def aplicar_smart_mid_run(args, puertos, hostnames_tempranos):
    """
    Se llama una vez ya se conocen los puertos (después del nmap TCP) y,
    más adelante, los hostnames tempranos -- para activar selectivamente
    lo que tiene sentido para ESTA máquina en particular, en vez de
    prender todo desde el inicio.
    """
    if not getattr(args, "smart", False):
        return args

    es_posible_dc = {88, 389, 445}.issubset(set(puertos))
    if es_posible_dc and not args.ad_domain and hostnames_tempranos:
        # Solo auto-activamos AD si además ya tenemos un dominio candidato
        # real (no adivinamos un nombre de dominio de la nada).
        dominio_candidato = sorted(hostnames_tempranos)[0]
        args.ad_domain = dominio_candidato
        print(f"[+] --smart: patrón de Domain Controller detectado, usando '{dominio_candidato}' como --ad-domain.")

    tiene_web = any(p in (80, 443, 8080, 8443) for p in puertos)
    if tiene_web and not args.pdf_report:
        args.pdf_report = True
        print("[+] --smart: servicio web detectado, se generará --pdf-report al final.")

    if tiene_web and not args.screenshots:
        args.screenshots = True
        print("[+] --smart: se activan --screenshots (hay servicios web que documentar visualmente).")

    return args
