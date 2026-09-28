#!/usr/bin/env python3
"""
recon.py v4.0 - Framework de reconocimiento modular open source para
hackers éticos (HTB, eJPT, labs autorizados).

Uso básico:
    recon.py <ip> -n <nombre_carpeta> [--deep] [--profile ctf]

Novedades v4.0 (además de todo lo de v1/v2/v3):
    --pdf-report [--pdf-template default|oscp] [--pdf-redacted]
                                   Reporte PDF profesional (reportlab)
    --export-tickets [csv|json|ambos]
                                   Exporta findings como tickets Jira/Trello
    --custom-templates             Corre templates YAML propios (templates/custom/)
    --param-fuzz                   Fuzzing pasivo de parámetros GET comunes
    --lang es|en                   Idioma del contenido de los reportes
    --webhook-url URL --webhook-platform discord|slack
                                   Notifica al equipo al terminar
    --show-checkpoints              Muestra qué fases ya están completas (con --resume)
    --resume                        Salta fases cuyo archivo de salida ya existe

Utilidades separadas (ver README para todas):
    api_server.py     API REST (--serve) para disparar recons vía HTTP
    team_server.py    Backend colaborativo
    dashboard.py      Dashboard web local
"""

import argparse
import logging
import os
from pathlib import Path

from modules.utils import banner, validar_ip, Carpeta
from modules import (
    nmap_scan, web, services, hostnames as hn, reporting,
    vuln_correlation, misconfig, active_directory, screenshots,
    credentials, notify, bruteforce_suggest, html_report, diffing,
    history_db, exploit_assist, profiles as profiles_mod, json_output,
    llm_assist, attack_graph, attack_graph_viz, active_verify,
    pdf_report, attack_graph_static, ticket_export, checkpoints,
    custom_templates, param_fuzz, team_webhooks, run_modes, autopilot,
    final_assist,
)
from modules.parallel import correr_en_paralelo
from modules.plugin_loader import descubrir_plugins, ejecutar_plugins

VERSION = "6.0.0"

SUBFOLDERS = [
    "01_target", "02_discovery", "03_nmap", "04_web",
    "05_services", "06_vulnerabilities", "07_credentials",
    "exploits", "loot", "scripts", "screenshots",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Framework de reconocimiento modular open source (HTB/eJPT)."
    )
    parser.add_argument("--version", action="version", version=f"recon.py {VERSION}")
    parser.add_argument("ip", nargs="?", help="Dirección IP del objetivo (omitir si usas --targets-file)")
    parser.add_argument("-n", "--nombre", help="Nombre de la carpeta del workspace")
    parser.add_argument("--targets-file", help="Archivo con una IP por línea para correr en lote")
    parser.add_argument("--deep", action="store_true",
                         help="Escaneo más agresivo: UDP top1000, NSE vuln, nuclei")
    parser.add_argument("--profile", choices=["stealth", "ctf", "oscp-report", "self-audit"],
                         help="Perfil predefinido que ajusta varios flags a la vez")
    parser.add_argument("--vhost-domain", help="Dominio base para fuzzing de vhosts (ej. target.htb)")
    parser.add_argument("--ad-domain", help="Dominio de Active Directory conocido (para kerbrute/AS-REP)")
    parser.add_argument("--ad-userlist", help="Wordlist de usuarios para kerbrute userenum")
    parser.add_argument("--screenshots", action="store_true", help="Tomar screenshots de cada URL web")
    parser.add_argument("--html-report", action="store_true", help="Generar report.html consolidado al final")
    parser.add_argument("--auto-exploit", action="store_true",
                         help="Clonar automáticamente el mejor PoC de GitHub para cada CVE encontrado (nunca lo ejecuta)")
    parser.add_argument("--json-only", action="store_true",
                         help="Suprime salida cosmética; imprime solo un JSON final a stdout")
    parser.add_argument("--assist", action="store_true",
                         help="Sugerencias de próximos pasos vía LLM (requiere ANTHROPIC_API_KEY)")
    parser.add_argument("--assist-final", action="store_true",
                         help="Análisis final vía LLM sobre el reporte YA COMPLETO (una sola llamada, "
                              "después de generar README/attack-surface/findings/misconfig/credenciales). "
                              "Requiere ANTHROPIC_API_KEY.")
    parser.add_argument("--attack-graph", action="store_true",
                         help="Genera un grafo de ataque (JSON + HTML interactivo) relacionando puertos/CVEs/credenciales")
    parser.add_argument("--active-verify", action="store_true",
                         help="Verificación activa de bajo riesgo para confirmar CVEs sospechosos (toca el objetivo)")
    parser.add_argument("--team-server", help="URL de un team_server.py para compartir la corrida con tu equipo")
    parser.add_argument("--member", default="anonimo", help="Tu nombre/alias para el team server")
    parser.add_argument("--no-notify", action="store_true", help="Desactivar el beep/notify-send al terminar")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Auto-confirmar cambios en /etc/hosts sin preguntar")

    # --- v4.0 ---
    parser.add_argument("--pdf-report", action="store_true", help="Generar reporte PDF profesional")
    parser.add_argument("--pdf-template", choices=["default", "oscp"], default="default",
                         help="Plantilla del PDF (default o estructura tipo OSCP)")
    parser.add_argument("--pdf-redacted", action="store_true",
                         help="Redacta credenciales encontradas en el PDF (para compartir con clientes)")
    parser.add_argument("--export-tickets", choices=["csv", "json", "ambos"],
                         help="Exporta findings como tickets (Jira CSV / Trello JSON)")
    parser.add_argument("--custom-templates", action="store_true",
                         help="Corre templates YAML propios (templates/custom/) contra las URLs detectadas")
    parser.add_argument("--param-fuzz", action="store_true",
                         help="Fuzzing pasivo de parámetros GET comunes (detecta, no confirma)")
    parser.add_argument("--lang", choices=["es", "en"], default="es",
                         help="Idioma del contenido de los reportes generados")
    parser.add_argument("--webhook-url", help="URL de webhook (Discord/Slack) para notificar al equipo")
    parser.add_argument("--webhook-platform", choices=["discord", "slack"], default="discord",
                         help="Plataforma del webhook")
    parser.add_argument("--resume", action="store_true",
                         help="Salta fases cuyo archivo de salida ya existe (recon interrumpido)")
    parser.add_argument("--show-checkpoints", action="store_true",
                         help="Muestra el estado de checkpoints existentes y termina")

    # --- v5.0 ---
    parser.add_argument("--core-only", action="store_true",
                         help="Solo nmap+web+CVE+reporting; apaga toda la funcionalidad extendida de golpe")
    parser.add_argument("--auto", action="store_true",
                         help="Modo autopiloto: decide qué activar (deep, screenshots, PDF, AD, etc.) "
                              "según lo que va descubriendo, con justificación en decisiones-autopiloto.md. "
                              "Nunca activa por sí solo lo que toca el objetivo (--active-verify, "
                              "--auto-exploit, --param-fuzz siguen requiriendo pedirse a mano).")
    parser.add_argument("--smart", action="store_true",
                         help="Activa selectivamente AD/PDF/screenshots según lo que se descubra durante la corrida")
    parser.add_argument("--offline", action="store_true",
                         help="Correlación de CVEs sin red, contra la base local (ver prepare_offline.py)")

    args = parser.parse_args()
    args.min_rate = "5000"
    args.nse_vuln_forzado = None
    return args


def ejecutar_recon(ip, args, plugins):
    """Corre el pipeline completo de recon contra una sola IP."""

    if not validar_ip(ip):
        return

    nombre_carpeta = args.nombre or ip
    carpeta = Carpeta(nombre_carpeta)
    carpeta.crear_carpeta(SUBFOLDERS)

    if args.show_checkpoints:
        checkpoints.resumen_estado(carpeta.nombre, deep=args.deep)
        return

    decisiones = autopilot.Decisiones() if args.auto else None
    if args.auto:
        print("[+] Modo --auto: el motor de reglas irá decidiendo qué activar (ver decisiones-autopiloto.md al final).")

    logging.basicConfig(
        filename=carpeta.nombre / "recon.log",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        force=True,
    )
    logging.info(f"recon.py {VERSION} iniciado contra {ip} (deep={args.deep}, profile={args.profile})")

    findings_anteriores = diffing.comparar_y_archivar(carpeta.nombre)

    resume = args.resume

    # 1. Host discovery
    if not (resume and checkpoints.fase_completa(carpeta.nombre, "host_discovery")):
        nmap_scan.host_discovery(ip, carpeta.nombre)

    # 2. TCP full
    if resume and checkpoints.fase_completa(carpeta.nombre, "tcp_full"):
        puertos = nmap_scan.extraer_puertos(carpeta.nombre / "03_nmap" / "allPortsTCP")
        print("[i] --resume: fase TCP full ya completa, reutilizando puertos detectados.")
    else:
        puertos = nmap_scan.escanear_puertos_tcp(ip, carpeta.nombre, min_rate=args.min_rate)

    if not puertos:
        print("[!] No hay puertos TCP abiertos. Fin del recon para esta IP.")
        return

    args = run_modes.aplicar_smart_mid_run(args, puertos, set())
    if args.auto:
        args = autopilot.decidir_tras_puertos(args, decisiones, puertos)

    # 3. TCP service enumeration
    if not (resume and checkpoints.fase_completa(carpeta.nombre, "tcp_targeted")):
        nmap_scan.escanear_puertos_personalizados(ip, carpeta.nombre, puertos)

    # 4. UDP
    if resume and checkpoints.fase_completa(carpeta.nombre, "udp", deep=args.deep):
        print("[i] --resume: fase UDP ya completa, se omite.")
        puertos_udp = []
    else:
        puertos_udp = nmap_scan.escanear_udp(ip, carpeta.nombre, deep=args.deep)

    # 5. OS detection + NSE discovery
    if not (resume and checkpoints.fase_completa(carpeta.nombre, "os_detection")):
        nmap_scan.detectar_os(ip, carpeta.nombre)
    nmap_scan.nse_discovery(ip, carpeta.nombre, puertos)

    # 6. Web -- primero una sonda liviana para descubrir el hostname real
    #    (ej. ghostlink.htb) ANTES de gastar tiempo enumerando directorios
    #    contra la IP, que en HTB casi siempre da resultados distintos
    #    (o vacíos) comparado con enumerar directamente contra el vhost.
    candidatos_hostname = web.sondar_hostname_temprano(ip, puertos)
    if args.vhost_domain:
        candidatos_hostname.add(args.vhost_domain)

    objetivo_web = ip  # fallback: si no se descubre ni confirma nada, se sigue usando la IP

    if candidatos_hostname:
        # agregar_hosts devuelve solo los que quedaron resueltos de verdad
        # en /etc/hosts (ya existían o se acaban de escribir) -- solo esos
        # son seguros de usar como URL, un candidato no confirmado podría
        # no resolver y hacer fallar todo el recon web silenciosamente.
        resueltos = hn.agregar_hosts(ip, sorted(candidatos_hostname), auto_confirm=args.yes)
        if resueltos:
            objetivo_web = resueltos[0]
            print(f"[i] Usando '{objetivo_web}' como objetivo para el recon web (en vez de {ip}).")
            # Ahora sí hay un hostname candidato real -- re-evaluar --smart
            # por si el dominio recién confirmado habilita AD.
            args = run_modes.aplicar_smart_mid_run(args, puertos, {objetivo_web})
            if args.auto:
                args = autopilot.decidir_tras_hostname(args, decisiones, {objetivo_web}, puertos)

    urls = web.http_recon(objetivo_web, carpeta.nombre, puertos)
    web.ssl_recon(objetivo_web, carpeta.nombre, puertos)

    if args.vhost_domain:
        web.vhost_fuzz(ip, carpeta.nombre, args.vhost_domain)

    if args.screenshots:
        screenshots.tomar_screenshots(urls, carpeta.nombre)

    # 7. Servicios independientes en paralelo
    tareas_paralelas = [
        ("smb", services.smb_recon, (ip, carpeta.nombre, puertos)),
        ("ftp", services.ftp_recon, (ip, carpeta.nombre, puertos)),
        ("dns", services.dns_recon, (ip, carpeta.nombre, puertos)),
        ("snmp", services.snmp_recon, (ip, carpeta.nombre, puertos)),
        ("ldap", services.ldap_recon, (ip, carpeta.nombre, puertos)),
        ("smtp", services.smtp_recon, (ip, carpeta.nombre, puertos)),
        ("databases", services.database_recon, (ip, carpeta.nombre, puertos)),
    ]
    correr_en_paralelo(tareas_paralelas)

    # 8. Active Directory
    active_directory.ad_recon(
        ip, carpeta.nombre, puertos,
        domain=args.ad_domain, userlist=args.ad_userlist
    )

    # 9. Vulnerabilidades
    if args.deep or args.nse_vuln_forzado:
        nmap_scan.nse_vuln(ip, carpeta.nombre, puertos)

    if resume and checkpoints.fase_completa(carpeta.nombre, "vuln_correlation"):
        print("[i] --resume: correlación de CVEs ya completa, se reutiliza findings.json existente.")
        findings_actuales = vuln_correlation._leer_findings_existentes(carpeta.nombre)
        if not findings_actuales:
            findings_actuales = vuln_correlation.correlacionar_vulnerabilidades(
                carpeta.nombre, urls=urls, deep=args.deep, offline=args.offline
            )
    else:
        findings_actuales = vuln_correlation.correlacionar_vulnerabilidades(
            carpeta.nombre, urls=urls, deep=args.deep, offline=args.offline
        )

    diffing.escribir_diff(carpeta.nombre, findings_anteriores, findings_actuales)

    misconfig.buscar_archivos_interesantes(urls, carpeta.nombre)

    # 10. Verificación activa (opcional)
    if args.active_verify:
        active_verify.verificar_activamente(urls, findings_actuales, carpeta.nombre)

    # 10b. Templates personalizados (v4.0)
    if args.custom_templates:
        custom_templates.ejecutar_templates(urls, carpeta.nombre)

    # 10c. Fuzzing de parámetros (v4.0)
    if args.param_fuzz:
        param_fuzz.fuzzear_parametros(urls, carpeta.nombre)

    # 11. Explotación asistida
    exploit_assist.preparar_todos(
        findings_actuales, ip, carpeta.nombre,
        auto_confirm=(args.auto_exploit and not args.offline)
    )
    if args.offline and args.auto_exploit:
        print("[i] --offline: se omite --auto-exploit (requiere clonar de GitHub, necesita red).")

    # 12. Credenciales y sugerencias de bruteforce
    hallazgos_credenciales = credentials.escanear_credenciales(carpeta.nombre)
    bruteforce_suggest.sugerir_bruteforce(ip, carpeta.nombre, puertos)

    # 13. Hostnames
    hostnames_encontrados = hn.extraer_hostnames(carpeta.nombre)
    hostname_file = carpeta.nombre / "content_hostnames.txt"
    hostname_file.write_text("\n".join(hostnames_encontrados), encoding="utf-8")
    hn.agregar_hosts(ip, hostnames_encontrados, auto_confirm=args.yes)

    context = {
        "puertos": puertos,
        "puertos_udp": puertos_udp,
        "urls": urls,
        "hostnames": hostnames_encontrados,
        "findings": findings_actuales,
    }

    # 14. Plugins de usuario
    ejecutar_plugins(plugins, ip, carpeta.nombre, context)

    if args.auto:
        args = autopilot.decidir_reportes_finales(args, decisiones, findings_actuales, puertos)

    # 15. Grafo de ataque (opcional) -- interactivo (D3) + estático (PNG para PDF)
    imagen_grafo = None
    if args.attack_graph or args.pdf_report:
        grafo = attack_graph.generar_grafo_de_ataque(
            context, findings_actuales, hallazgos_credenciales, carpeta.nombre
        )
        if args.attack_graph:
            attack_graph_viz.generar_html_grafo(grafo, carpeta.nombre)
        imagen_grafo = attack_graph_static.generar_imagen_grafo(grafo, carpeta.nombre)

    # 16. Sugerencias vía LLM (opcional)
    if args.assist:
        llm_assist.sugerir_siguientes_pasos(context, findings_actuales, carpeta.nombre)

    # 17. Reporting
    reporting.generar_attack_surface(ip, carpeta.nombre, puertos, puertos_udp, hostnames_encontrados)
    reporting.generar_readme(ip, carpeta, puertos, hostnames_encontrados)

    if args.html_report:
        html_report.generar_reporte_html(carpeta.nombre)

    # 17b. PDF profesional (v4.0)
    if args.pdf_report:
        pdf_report.generar_pdf(
            carpeta.nombre, ip=ip, template=args.pdf_template,
            analista=args.member, redactar=args.pdf_redacted,
            imagen_grafo=imagen_grafo,
        )

    # 17c. Exportar tickets (v4.0)
    if args.export_tickets:
        ticket_export.exportar_tickets(findings_actuales, carpeta.nombre, ip, formato=args.export_tickets)

    # 17d. Análisis final vía LLM sobre el reporte YA COMPLETO (v5.2)
    if args.assist_final:
        final_assist.analizar_reporte_completo(carpeta.nombre, ip)

    # 18. Histórico SQLite local
    history_db.registrar_corrida(
        ip, carpeta.nombre, puertos, puertos_udp, hostnames_encontrados, findings_actuales
    )

    # 19. Team server (opcional, colaborativo)
    if args.team_server:
        from team_server import enviar_corrida
        enviar_corrida(args.team_server, args.member, ip, puertos, findings_actuales)

    # 19b. Webhook de equipo (v4.0)
    if args.webhook_url:
        team_webhooks.notificar_equipo(args.webhook_url, args.webhook_platform, args.member, ip, findings_actuales)

    if args.json_only:
        json_output.emitir_resultado_json(
            ip, carpeta.nombre, puertos, puertos_udp, hostnames_encontrados, findings_actuales
        )
    else:
        print("\n[+] Recon completado.")
        print(f"[+] Workspace: {carpeta.nombre}")
        print(f"[+] TCP: {','.join(map(str, puertos))}")
        if puertos_udp:
            print(f"[+] UDP: {','.join(map(str, puertos_udp))}")
        if hostnames_encontrados:
            print(f"[+] Hostnames: {', '.join(hostnames_encontrados)}")

    logging.info("Recon completado correctamente.")

    if args.auto:
        decisiones.escribir(carpeta.nombre)
        print(f"[+] Decisiones del autopiloto documentadas en {carpeta.nombre}/01_target/decisiones-autopiloto.md")

    if not args.no_notify:
        notify.notificar(f"Recon de {ip} completado")


def main():
    args = parse_args()
    args = profiles_mod.aplicar_perfil(args)
    args = run_modes.aplicar_core_only(args)
    args = run_modes.aplicar_smart_inicial(args)

    if args.json_only:
        json_output.silenciar_stdout_normal()

    os.system("cls" if os.name == "nt" else "clear")
    banner()

    plugins = descubrir_plugins()

    if args.targets_file:
        targets_path = Path(args.targets_file)
        if not targets_path.exists():
            print(f"[!] No se encontró el archivo: {args.targets_file}")
            return

        ips = [
            line.strip() for line in targets_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        if args.nombre:
            print("[!] --nombre se ignora en modo batch: cada IP usa su propia carpeta.")
            args.nombre = None

        print(f"[+] Modo batch: {len(ips)} objetivo(s) a procesar.")

        for i, ip in enumerate(ips, start=1):
            print(f"\n{'='*60}\n[{i}/{len(ips)}] Procesando {ip}\n{'='*60}")
            ejecutar_recon(ip, args, plugins)

        if not args.no_notify:
            notify.notificar(f"Batch de {len(ips)} objetivos completado")

        return

    if not args.ip:
        print("[!] Debes indicar una IP o usar --targets-file.")
        return

    ejecutar_recon(args.ip, args, plugins)


if __name__ == "__main__":
    main()
