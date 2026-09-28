#!/usr/bin/env python3
"""
Módulo de Active Directory.

Se activa cuando se detecta un patrón típico de Domain Controller:
Kerberos (88) + LDAP (389) + SMB (445). No lanza fuerza bruta de
contraseñas por su cuenta -- solo enumeración no destructiva y, si ya
hay usuarios/hashes, deja listos los comandos para roasting.
"""

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

from modules.utils import run_command, tool_exists

AD_PORTS = {88, 389, 445}


def es_probable_dc(puertos):
    return AD_PORTS.issubset(set(puertos))


def rpc_null_session(ip, folder):
    output_folder = folder / "05_services" / "ad"
    output_folder.mkdir(parents=True, exist_ok=True)

    if not tool_exists("rpcclient"):
        return

    comandos_rpc = "\n".join([
        "enumdomusers", "enumdomgroups", "querydominfo", "srvinfo"
    ])

    run_command([
        "rpcclient", "-U", "", "-N", "-c", comandos_rpc, ip
    ], output_folder / "rpcclient-null.txt")


def kerbrute_userenum(ip, folder, domain, userlist=None):
    """
    Requiere un dominio conocido (ej. de --vhost-domain o de hostnames
    detectados que terminen en .htb/.local) y una wordlist de usuarios.
    Sin wordlist no se ejecuta (evitar ruido/adivinar nombres al azar).
    """
    if not domain or not userlist or not tool_exists("kerbrute"):
        return []

    output_folder = folder / "05_services" / "ad"
    output_folder.mkdir(parents=True, exist_ok=True)
    output = output_folder / "kerbrute-userenum.txt"

    salida = run_command([
        "kerbrute", "userenum", "-d", domain, "--dc", ip, userlist
    ], output)

    usuarios_validos = []
    for line in (salida or "").splitlines():
        if "VALID USERNAME" in line:
            # formato típico: "[+] VALID USERNAME: user@domain"
            partes = line.split(":")
            if len(partes) >= 2:
                usuarios_validos.append(partes[-1].strip().split("@")[0])

    if usuarios_validos:
        print(colored(f"[+] Usuarios válidos encontrados: {usuarios_validos}", "green"))

    return usuarios_validos


def asrep_roast(ip, folder, domain, usuarios):
    """
    AS-REP roasting solo tiene sentido si ya sabemos que hay usuarios
    válidos (de kerbrute o de otra fuente). Requiere impacket.
    """
    if not usuarios or not domain or not tool_exists("GetNPUsers.py"):
        return

    output_folder = folder / "05_services" / "ad"
    users_file = output_folder / "users.txt"
    users_file.write_text("\n".join(usuarios), encoding="utf-8")

    run_command([
        "GetNPUsers.py", f"{domain}/", "-usersfile", str(users_file),
        "-no-pass", "-dc-ip", ip
    ], output_folder / "asrep-roast.txt")


def sugerir_kerberoast(domain):
    """
    Kerberoasting requiere credenciales válidas (no solo enumeración
    anónima), así que aquí solo se deja el comando sugerido para cuando
    el usuario ya tenga un usuario/contraseña o hash.
    """
    if not domain:
        return None

    return (
        f"GetUserSPNs.py {domain}/USUARIO:CONTRASEÑA -dc-ip <DC_IP> -request"
    )


def bloodhound_collect(ip, folder, domain, username=None, password=None):
    """
    Solo corre si se le pasan credenciales explícitas -- collection
    anónima no suele funcionar y no queremos adivinar credenciales aquí.
    """
    if not (domain and username and password) or not tool_exists("bloodhound-python"):
        return

    output_folder = folder / "05_services" / "ad" / "bloodhound"
    output_folder.mkdir(parents=True, exist_ok=True)

    comando = [
        "bloodhound-python", "-u", username, "-p", password,
        "-d", domain, "-ns", ip, "-c", "All",
        "--zip"
    ]
    # mask_after=4: el índice 4 es la contraseña ("-p" en 3, password en 4) --
    # evita que quede en texto plano en la terminal/logs (ver run_command).
    run_command(comando, mask_after=4)
    print(colored(f"[+] BloodHound collection en {output_folder}", "green"))
    print(colored(
        "[i] Nota de seguridad: la contraseña pasada a bloodhound-python sigue "
        "siendo visible vía 'ps aux'/'/proc/<pid>/cmdline' para otros usuarios "
        "del mismo sistema mientras el comando corre -- limitación del sistema "
        "operativo al pasar secretos por argv, no de este script. Evita correr "
        "esto en máquinas multiusuario compartidas.",
        "yellow"
    ))


def ad_recon(ip, folder, puertos, domain=None, userlist=None):
    """Orquestador del módulo AD."""
    if not es_probable_dc(puertos):
        return

    print(colored("\n[+] Patrón de Domain Controller detectado (88+389+445).", "cyan"))

    rpc_null_session(ip, folder)

    usuarios = []
    if domain:
        usuarios = kerbrute_userenum(ip, folder, domain, userlist)
        asrep_roast(ip, folder, domain, usuarios)

        sugerencia = sugerir_kerberoast(domain)
        if sugerencia:
            print(colored(f"[i] Si consigues credenciales, prueba Kerberoasting:\n    {sugerencia}", "cyan"))
    else:
        print(colored(
            "[i] No se especificó dominio (--ad-domain). Se omite kerbrute/AS-REP roasting.",
            "yellow"
        ))

    return usuarios
