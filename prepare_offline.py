#!/usr/bin/env python3
"""
prepare_offline.py - Prepara la base CVE local para uso con --offline.

Se corre UNA VEZ, con conexión a internet, antes de entrar a un entorno
air-gapped (examen certificado, laboratorio sin salida a internet).
Después de esto, `recon.py --offline` no vuelve a tocar la red para
correlación de CVEs.

Uso:
    python3 prepare_offline.py                     # productos comunes de HTB/CTF por defecto
    python3 prepare_offline.py --keywords Apache nginx OpenSSH
    python3 prepare_offline.py --from-json mi_dump.json   # importar un dump ya armado
"""

import argparse
from pathlib import Path

from modules.offline_cve import descargar_dump_nvd, importar_dump_json, base_disponible

PRODUCTOS_COMUNES_HTB = [
    "Apache httpd", "nginx", "OpenSSH", "Samba", "MySQL", "PostgreSQL",
    "vsftpd", "ProFTPD", "PHP", "WordPress", "Jenkins", "Tomcat",
    "Microsoft IIS", "Microsoft Windows SMB", "OpenSSL", "Exim", "Postfix",
    "Redis", "MongoDB", "Elasticsearch", "Confluence", "GitLab",
]


def main():
    parser = argparse.ArgumentParser(description="Prepara la base CVE offline para --offline.")
    parser.add_argument("--keywords", nargs="+", help="Productos a pre-cachear (default: lista común de HTB/CTF)")
    parser.add_argument("--from-json", help="Importar un dump JSON ya armado, sin llamar a la NVD")
    parser.add_argument("--output", default="cve_dump.json", help="Dónde guardar el dump descargado")
    args = parser.parse_args()

    if args.from_json:
        importar_dump_json(args.from_json)
        return

    keywords = args.keywords or PRODUCTOS_COMUNES_HTB
    print(f"[+] Preparando base offline para {len(keywords)} producto(s) — esto puede tardar varios minutos (rate-limit de NVD).")

    descargar_dump_nvd(args.output, keywords)
    importar_dump_json(args.output)

    print(f"\n[+] Listo. {base_disponible() and 'Base disponible' or 'Algo falló, revisa arriba'}.")
    print("[+] Ya puedes usar: python3 recon.py <ip> --offline")


if __name__ == "__main__":
    main()
