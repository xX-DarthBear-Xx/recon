#!/usr/bin/env python3
"""Utilidades compartidas por todos los módulos de recon."""

import shutil
import subprocess
import ipaddress
from pathlib import Path

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


def banner():
    from recon import VERSION as _v
    print(colored(r"""
   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
""", "red") + colored(f"""
   🐾 by DarthBear  ·  v{_v}  ·  github.com/xX-DarthBear-Xx/recon

   ┌─────────────────────────────────────────────────────────┐
   │  nmap · web · AD · CVE correlation · PDF reports · auto  │
   └─────────────────────────────────────────────────────────┘
""", "cyan"))


def run_command(command, output_file=None, timeout=None, mask_after=None):
    """
    Ejecuta un comando y opcionalmente guarda stdout/stderr.
    Devuelve el stdout como string ("" si la herramienta no existe o falla).

    mask_after: índice (0-based) del argumento a partir del cual se
    imprime "***" en vez del valor real -- para comandos que reciben una
    contraseña por CLI (ej. bloodhound-python -u user -p PASSWORD).
    No evita que la contraseña sea visible vía `ps aux`/`/proc/<pid>/cmdline`
    para otros usuarios del mismo sistema (eso es una limitación del
    sistema operativo, no de este script -- ver SECURITY.md), pero sí
    evita que quede en texto plano en la terminal, en logs de tmux/screen,
    o en cualquier captura de pantalla/grabación de la sesión.
    """
    if mask_after is not None:
        visible = list(command[:mask_after]) + ["***"] * len(command[mask_after:])
    else:
        visible = command

    print(colored(f"\n[>] {' '.join(str(c) for c in visible)}", "cyan"))

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
        )

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)

        return result.stdout

    except FileNotFoundError:
        print(colored(f"[!] Herramienta no encontrada: {command[0]}", "red"))
        return ""
    except subprocess.TimeoutExpired:
        print(colored(f"[!] Timeout ejecutando: {command[0]}", "yellow"))
        return ""


def tool_exists(tool):
    return shutil.which(tool) is not None


def validar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(colored("[!] Dirección IP no válida.", "red"))
        return False


WORKSPACES_BASE = Path("workspaces")


class RutaInseguraError(ValueError):
    """Se lanza cuando --nombre intentaría escribir fuera del workspace esperado."""


def sanitizar_nombre_workspace(nombre):
    """
    Corrige un hallazgo de seguridad real: Carpeta(nombre) antes hacía
    Path(nombre).mkdir() sin validar nada. Un --nombre como
    '../../../../tmp/pwned' (o el mismo campo llegando sin validar desde
    api_server.py) permitía crear/escribir fuera del directorio de
    workspaces esperado -- path traversal.

    Reglas:
    - Se rechaza cualquier componente '..' o una ruta absoluta.
    - Se permite un nombre simple (ej. 'ghostlink') o una subcarpeta
      relativa simple (ej. 'clientes/acme'), pero siempre resuelto
      DENTRO de WORKSPACES_BASE.
    """
    ruta = Path(nombre)

    if ruta.is_absolute():
        raise RutaInseguraError(
            f"--nombre no puede ser una ruta absoluta: '{nombre}'. "
            f"Usa un nombre simple, se guardará bajo {WORKSPACES_BASE}/"
        )

    if ".." in ruta.parts:
        raise RutaInseguraError(
            f"--nombre no puede contener '..': '{nombre}' (posible path traversal)."
        )

    return WORKSPACES_BASE / ruta


class Carpeta:
    """Gestiona el workspace de la máquina objetivo. Los workspaces viven
    siempre bajo WORKSPACES_BASE (ver sanitizar_nombre_workspace) -- ya
    no es posible escribir fuera de ahí pasando un --nombre malicioso."""

    def __init__(self, nombre):
        self.nombre = sanitizar_nombre_workspace(nombre)
        self.nombre.mkdir(parents=True, exist_ok=True)

    def crear_carpeta(self, carpetas):
        for carpeta in carpetas:
            ruta = self.nombre / carpeta
            if ruta.exists():
                print(colored(f"[=] Ya existe: {ruta}", "yellow"))
            else:
                ruta.mkdir(parents=True, exist_ok=True)
                print(colored(f"[+] Creada: {ruta}", "green"))
