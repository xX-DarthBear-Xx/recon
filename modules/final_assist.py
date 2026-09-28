#!/usr/bin/env python3
"""
Análisis final con LLM (--assist-final), sobre el reporte YA COMPLETO.

Diferencia con llm_assist.py (--assist), que ya existía desde v3.0:
- --assist corre A MITAD del recon, con el context parcial (solo
  puertos/urls/findings en memoria) -- una sugerencia rápida y liviana.
- --assist-final corre AL TERMINAR todo, y le pasa al modelo el
  contenido real de los archivos ya generados: README, attack-surface,
  findings.md completo (con descripciones), misconfigurations.md,
  credentials-found.md (redactado) y el diff con la corrida anterior.
  Es una sola llamada, pero con mucho más contexto real para razonar
  sobre la máquina completa -- no "qué sugerirías con esto que ya sé",
  sino "aquí está TODO lo que encontramos, dime por dónde seguir".

Sigue sin ejecutar nada: es texto para que el usuario decida. Y sigue
siendo agnóstico de proveedor -- ver _llamar_llm(), el único punto que
habría que tocar para usar OpenAI en vez de Anthropic.
"""

import os
from pathlib import Path

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

try:
    import requests
except ImportError:
    requests = None

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"

# Límite de caracteres por archivo para no disparar el tamaño del
# prompt (y su costo) sin control -- un findings.md de 50 CVEs no
# necesita mandarse completo para que el modelo entienda el panorama.
LIMITE_POR_ARCHIVO = 6000


def _leer_truncado(path):
    if not path.exists():
        return ""
    contenido = path.read_text(encoding="utf-8", errors="ignore")
    if len(contenido) > LIMITE_POR_ARCHIVO:
        contenido = contenido[:LIMITE_POR_ARCHIVO] + "\n[...truncado para el análisis, ver archivo completo...]"
    return contenido


def recopilar_reporte_completo(folder):
    """Junta el contenido real de todos los reportes ya generados en un
    solo bloque de texto, lo que el LLM necesita para razonar sobre la
    máquina completa en vez de solo un resumen estructurado."""
    folder = Path(folder)

    secciones = {
        "README": folder / "README.md",
        "Attack Surface": folder / "attack-surface.md",
        "Vulnerability Findings": folder / "06_vulnerabilities" / "findings.md",
        "Misconfigurations": folder / "06_vulnerabilities" / "misconfigurations.md",
        "Credenciales encontradas (redactar antes de compartir)": folder / "07_credentials" / "credentials-found.md",
        "Diff con corrida anterior": folder / "06_vulnerabilities" / "diff.md",
    }

    bloques = []
    for titulo, path in secciones.items():
        contenido = _leer_truncado(path)
        if contenido.strip():
            bloques.append(f"## {titulo}\n\n{contenido}")

    return "\n\n---\n\n".join(bloques)


def _construir_prompt(reporte_texto, ip):
    return (
        f"Eres un asistente de pentesting para un CTF/HTB/lab AUTORIZADO. "
        f"A continuación está el reporte COMPLETO de reconocimiento ya generado "
        f"para el objetivo {ip}. Analízalo como lo haría un analista senior "
        f"revisando el trabajo de reconocimiento de otra persona:\n\n"
        f"1. ¿Cuál es el vector de entrada más prometedor, y por qué (con evidencia "
        f"concreta del reporte, no genérico)?\n"
        f"2. ¿Hay alguna combinación de hallazgos que juntos sean más peligrosos que "
        f"por separado (ej. una credencial + un servicio donde reusarla)?\n"
        f"3. ¿Qué verificarías manualmente ANTES de intentar explotar algo, dado lo que "
        f"ves aquí?\n"
        f"4. ¿Hay algo en el reporte que parezca un falso positivo o necesite más "
        f"verificación antes de confiar en él?\n\n"
        f"Sé específico y basado en evidencia del reporte, no genérico. Máximo "
        f"~20 líneas. No inventes CVEs ni datos que no estén en el reporte. No des "
        f"instrucciones de explotación destructiva, solo análisis y priorización.\n\n"
        f"--- REPORTE COMPLETO ---\n\n{reporte_texto}"
    )


def _llamar_llm(prompt):
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        print(colored(
            "[!] --assist-final requiere ANTHROPIC_API_KEY en el entorno "
            "(export ANTHROPIC_API_KEY=tu_key_aqui antes de correr recon.py).",
            "yellow"
        ))
        return None

    if requests is None:
        print(colored("[!] Falta 'requests' para usar --assist-final.", "red"))
        return None

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 800,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=45,
        )
        resp.raise_for_status()
        data = resp.json()
        return "".join(block.get("text", "") for block in data.get("content", []))

    except Exception as e:
        print(colored(f"[!] Error consultando LLM: {e}", "yellow"))
        return None


def analizar_reporte_completo(folder, ip):
    """Punto de entrada: junta todo lo ya generado, hace UNA llamada al
    LLM, y guarda + imprime el análisis final."""
    folder = Path(folder)
    reporte_texto = recopilar_reporte_completo(folder)

    if not reporte_texto.strip():
        print(colored("[!] No hay suficiente contenido generado todavía para analizar.", "yellow"))
        return None

    print(colored("\n[+] Enviando el reporte completo al análisis final (una sola petición)...", "cyan"))

    prompt = _construir_prompt(reporte_texto, ip)
    analisis = _llamar_llm(prompt)

    if not analisis:
        return None

    output = folder / "ANALISIS-FINAL.md"
    output.write_text(
        f"# Análisis final del reporte completo\n\n"
        f"⚠️ Generado por un LLM sobre el reporte ya recolectado. Verifica cada "
        f"afirmación contra la evidencia real antes de actuar.\n\n"
        f"{analisis}\n",
        encoding="utf-8",
    )

    print(colored("\n" + "=" * 60, "green"))
    print(colored("  ANÁLISIS FINAL — POR DÓNDE SEGUIR", "green"))
    print(colored("=" * 60, "green"))
    print(analisis)
    print(colored(f"\n[+] Guardado también en {output}", "green"))

    return analisis
