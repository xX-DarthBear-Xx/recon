#!/usr/bin/env python3
"""
recon-writeups.py - Ayuda de estudio POST-resolución para máquinas
retiradas de HTB.

IMPORTANTE — salvaguardas de diseño, no solo de texto:
- Este script NUNCA se llama automáticamente desde recon.py. Es una
  utilidad separada que el usuario invoca manualmente, después de haber
  rooteado la máquina.
- Requiere el flag --ya-la-resolvi, sin el cual se niega a correr. Esto
  no impide que alguien mienta, pero deja explícito que el uso previsto
  es post-resolución, no durante el intento.
- No hace scraping de sitios de writeups (legal y técnicamente frágil,
  y muchos prohíben scraping en su ToS). Usa la API pública de
  ippsec.rocks (un índice de timestamps de los videos de Ippsec sobre
  máquinas de HTB, pensado exactamente para este uso: encontrar dónde
  en qué video se cubre una máquina dada) y nada más.
- No descarga ni reproduce contenido con derechos de autor -- solo
  devuelve el link al video y el timestamp relevante.

Uso:
    python3 recon-writeups.py ghostlink --ya-la-resolvi
"""

import argparse
import sys

try:
    import requests
except ImportError:
    requests = None

IPPSEC_API = "https://ippsec.rocks/searchv2.php"


def buscar_en_ippsec(nombre_maquina):
    """
    Consulta la API pública de ippsec.rocks por el nombre de la máquina.
    Devuelve una lista de {title, url, timestamp} o [] si no hay red o
    no hay resultados.
    """
    if requests is None:
        print("[!] Falta 'requests' para buscar writeups.")
        return []

    try:
        resp = requests.get(IPPSEC_API, params={"name": nombre_maquina}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] No se pudo consultar ippsec.rocks: {e}")
        return []

    resultados = []
    for item in data if isinstance(data, list) else []:
        resultados.append({
            "title": item.get("title", ""),
            "url": item.get("url", ""),
            "timestamp": item.get("timestamp", ""),
        })

    return resultados


def main():
    parser = argparse.ArgumentParser(
        description="Ayuda de estudio POST-resolución: busca dónde Ippsec cubrió una máquina retirada."
    )
    parser.add_argument("maquina", help="Nombre de la máquina de HTB (ej. 'ghostlink')")
    parser.add_argument("--ya-la-resolvi", action="store_true",
                         help="Confirma explícitamente que ya rooteaste la máquina (requerido)")
    args = parser.parse_args()

    if not args.ya_la_resolvi:
        print(
            "[!] Este script es una ayuda de ESTUDIO POST-resolución, no para "
            "resolver la máquina. Pásalo con --ya-la-resolvi solo si ya la "
            "rooteaste y quieres ver qué otros caminos existían.\n"
            "[!] Usarlo para hacer trampa en una máquina activa viola las "
            "reglas de HTB y el espíritu de aprender a hackear de verdad."
        )
        sys.exit(1)

    print(f"[+] Buscando cobertura de '{args.maquina}' en ippsec.rocks...")
    resultados = buscar_en_ippsec(args.maquina)

    if not resultados:
        print("[!] No se encontró cobertura de Ippsec para esa máquina (o no hay red).")
        return

    print(f"\n[+] {len(resultados)} resultado(s):")
    for r in resultados:
        print(f"  - {r['title']}")
        print(f"    {r['url']}" + (f"&t={r['timestamp']}" if r["timestamp"] else ""))


if __name__ == "__main__":
    main()
