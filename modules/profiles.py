#!/usr/bin/env python3
"""
Perfiles de escaneo. En vez de solo el binario --deep, un perfil ajusta
varios comportamientos a la vez.

Uso: --profile stealth | ctf | oscp-report
"""

PERFILES = {
    "stealth": {
        "deep": False,
        "min_rate": "300",          # mucho más lento, menos detectable
        "nse_vuln": False,
        "screenshots": False,
        "descripcion": "Mínimo ruido, para exámenes con detección de intrusos.",
    },
    "ctf": {
        "deep": True,
        "min_rate": "5000",
        "nse_vuln": True,
        "screenshots": True,
        "descripcion": "Todo lo que tengas, sin preocuparte por ruido. Uso por defecto en HTB.",
    },
    "oscp-report": {
        "deep": True,
        "min_rate": "1000",
        "nse_vuln": True,
        "screenshots": True,
        "descripcion": "Agresivo pero moderado, pensado para generar evidencia reportable.",
    },
    "self-audit": {
        "deep": False,
        "min_rate": "500",
        "nse_vuln": False,
        "screenshots": False,
        "descripcion": (
            "Pensado para auditar TU PROPIA infraestructura: escaneo "
            "conservador, sin --param-fuzz ni --active-verify (que sí "
            "tocan el objetivo), sin --auto-exploit. Prioriza no tumbar "
            "un servicio productivo por accidente sobre encontrar todo."
        ),
        "bloquea_agresivo": True,  # ver aplicar_perfil: fuerza estos flags a False
    },
}


def aplicar_perfil(args):
    """
    Sobreescribe args con los valores del perfil elegido, salvo que el
    usuario ya haya pasado --deep explícitamente (en cuyo caso se respeta
    lo que puso a mano).
    """
    if not getattr(args, "profile", None):
        return args

    perfil = PERFILES.get(args.profile)
    if not perfil:
        print(f"[!] Perfil desconocido: {args.profile}. Disponibles: {list(PERFILES)}")
        return args

    if not args.deep:
        args.deep = perfil["deep"]

    args.min_rate = perfil["min_rate"]
    args.nse_vuln_forzado = perfil["nse_vuln"]

    if perfil["screenshots"] and not args.screenshots:
        args.screenshots = True

    if perfil.get("bloquea_agresivo"):
        # self-audit: estos flags nunca se activan por accidente, aunque
        # el usuario los haya pasado a mano -- si de verdad quiere
        # param-fuzz/active-verify contra su propia infra, que no use
        # este perfil, o los pase y acepte que se ignoran aquí a propósito.
        if getattr(args, "param_fuzz", False):
            print("[!] self-audit: --param-fuzz se ignora (perfil conservador).")
            args.param_fuzz = False
        if getattr(args, "active_verify", False):
            print("[!] self-audit: --active-verify se ignora (perfil conservador).")
            args.active_verify = False
        if getattr(args, "auto_exploit", False):
            print("[!] self-audit: --auto-exploit se ignora (perfil conservador).")
            args.auto_exploit = False

    print(f"[+] Perfil '{args.profile}' aplicado: {perfil['descripcion']}")
    return args
