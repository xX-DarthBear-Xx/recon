# recon

Framework de reconocimiento modular open source para hackers éticos
(HTB, TryHackMe, eJPT, OSCP labs, engagements autorizados).

Por [Kevin Carballo Herrera (DarthBear)](https://github.com/xX-DarthBear-Xx) — [github.com/xX-DarthBear-Xx/recon](https://github.com/xX-DarthBear-Xx/recon)

## Instalación

```bash
pip install -r requirements.txt --break-system-packages
```

Herramientas externas opcionales (el script detecta cuáles faltan y las
salta sin romper la ejecución):

`nmap`, `whatweb`, `gobuster`, `ffuf`, `sslscan`, `smbclient`,
`enum4linux-ng`, `smbmap`, `dig`, `snmpwalk`, `ldapsearch`, `nuclei`,
`rpcclient`, `kerbrute`, `impacket` (GetNPUsers.py / GetUserSPNs.py),
`bloodhound-python`, `gowitness` o `eyewitness`, `hashcat`, `notify-send`.

## Uso básico

```bash
# Recon normal
python3 recon.py 10.129.121.28 -n ghostlink

# Recon agresivo: UDP top1000, NSE vuln, verificación con nuclei
python3 recon.py 10.129.121.28 -n ghostlink --deep

# Con fuzzing de vhosts sobre un dominio conocido
python3 recon.py 10.129.121.28 -n ghostlink --vhost-domain ghostlink.htb
```

## Uso avanzado

```bash
# Máquina tipo Domain Controller: kerbrute userenum + AS-REP roasting
python3 recon.py 10.129.121.28 -n dc01 --ad-domain corp.local --ad-userlist users.txt

# Screenshots de todas las URLs web detectadas
python3 recon.py 10.129.121.28 -n ghostlink --screenshots

# Reporte HTML consolidado al final (incluye screenshots embebidos en base64)
python3 recon.py 10.129.121.28 -n ghostlink --screenshots --html-report

# Batch mode: varias IPs de una VPN de HTB en secuencia
python3 recon.py --targets-file hosts.txt --deep --html-report

# Auto-confirmar cambios en /etc/hosts, sin beep al terminar
python3 recon.py 10.129.121.28 -n ghostlink -y --no-notify
```

## v3.0: comunidad y flujo completo

```bash
# Sugerencias de próximos pasos vía LLM (requiere ANTHROPIC_API_KEY)
python3 recon.py 10.129.121.28 -n ghostlink --assist

# Grafo de ataque (relaciona puertos/CVEs/credenciales, con visualización HTML)
python3 recon.py 10.129.121.28 -n ghostlink --attack-graph

# Verificación activa de bajo riesgo (confirma CVEs sospechosos con una petición real)
python3 recon.py 10.129.121.28 -n ghostlink --active-verify

# Modo colaborativo: levantar el servidor de equipo
python3 team_server.py   # sirve en http://0.0.0.0:5001

# ... y cada miembro corre esto contra la misma máquina:
python3 recon.py 10.129.121.28 -n ghostlink --team-server http://IP_DEL_SERVIDOR:5001 --member alice

# Post-explotación: correlacionar loot de linpeas/winpeas con el recon inicial
python3 recon-postexploit.py ghostlink loot.txt

# Análisis de patrones de tu histórico completo
python3 pattern_analysis.py

# Actualizar templates de nuclei y verificar wordlists configuradas
python3 update_resources.py

# Instalación como paquete pip (nunca probado end-to-end en este entorno)
pip install . --break-system-packages
```

## Filosofía de diseño

Todo lo que "toca" el objetivo más allá de reconocimiento pasivo requiere
un flag explícito (`--active-verify`, `--auto-exploit`) y ningún módulo
ejecuta exploits reales por su cuenta — como mucho clona un PoC o confirma
una vulnerabilidad con una sola petición no destructiva. Las sugerencias
de fuerza bruta y las de LLM son texto, nunca acciones automáticas.

Pensado para la comunidad de hacking ético en general (HTB, TryHackMe,
eJPT, OSCP labs, engagements autorizados) — no está acoplado a ninguna
plataforma específica.

## v4.0: entrega profesional

```bash
# Reporte PDF profesional (portada, resumen ejecutivo, tablas, grafo, screenshots)
python3 recon.py 10.129.121.28 -n ghostlink --pdf-report --pdf-template oscp

# Versión para compartir con un cliente, sin exponer credenciales reales encontradas
python3 recon.py 10.129.121.28 -n ghostlink --pdf-report --pdf-redacted

# Exportar findings como tickets para Jira (CSV) o Trello (JSON)
python3 recon.py 10.129.121.28 -n ghostlink --export-tickets ambos

# Correr templates YAML propios (contribuibles por la comunidad, ver templates/custom/)
python3 recon.py 10.129.121.28 -n ghostlink --custom-templates

# Fuzzing pasivo de parámetros GET comunes (detecta, no confirma)
python3 recon.py 10.129.121.28 -n ghostlink --param-fuzz

# Reanudar un recon interrumpido (salta fases ya completas)
python3 recon.py 10.129.121.28 -n ghostlink --resume

# Ver qué fases ya están completas antes de decidir --resume
python3 recon.py 10.129.121.28 -n ghostlink --show-checkpoints

# Notificar al equipo por Discord/Slack al terminar
python3 recon.py 10.129.121.28 -n ghostlink --webhook-url https://discord.com/api/webhooks/... --webhook-platform discord

# Reportes en inglés (para compartir con la comunidad internacional)
python3 recon.py 10.129.121.28 -n ghostlink --lang en

# API REST para disparar recons vía HTTP (independiente de la CLI)
python3 api_server.py   # sirve en http://127.0.0.1:5002
```

## v5.0: menos fricción, más alcance

```bash
# Solo lo esencial: nmap + web + CVE + reporting, nada más
python3 recon.py 10.129.121.28 -n ghostlink --core-only

# Modo inteligente: decide sobre la marcha qué activar según lo que encuentra
python3 recon.py 10.129.121.28 -n ghostlink --smart

# Preparar la base CVE local UNA VEZ, con red (antes de un examen air-gapped)
python3 prepare_offline.py --keywords Apache nginx OpenSSH Samba

# Correr el recon completo sin tocar la red para CVEs
python3 recon.py 10.129.121.28 -n ghostlink --offline

# Auditar tu propia infraestructura (bloquea flags agresivos aunque los pidas)
python3 recon.py 192.168.1.50 -n mi-servidor --profile self-audit

# Ayuda de estudio, solo después de haber rooteado una máquina retirada
python3 recon-writeups.py ghostlink --ya-la-resolvi
```

## v5.1: modo autopiloto

Un solo flag en vez de memorizar 35. El motor de reglas decide qué
activar según lo que va descubriendo, y deja escrita la razón de cada
decisión:

```bash
# Autopiloto: decide --deep, --screenshots, --pdf-report, --ad-domain,
# --export-tickets, --attack-graph, --custom-templates por ti
python3 recon.py 10.129.121.28 -n ghostlink --auto

# Después de correr, revisa por qué decidió lo que decidió:
cat ghostlink/01_target/decisiones-autopiloto.md
```

Nunca activa por sí solo lo que toca el objetivo más allá de lectura
(`--active-verify`, `--auto-exploit`, `--param-fuzz` siguen requiriendo
pedirse a mano) — autonomía en qué documentar, nunca en qué tan
agresivo ser.

## v5.2: análisis final con LLM sobre el reporte completo

```bash
# Al terminar todo, una sola llamada al LLM analiza el reporte YA COMPLETO
export ANTHROPIC_API_KEY=tu_key_aqui
python3 recon.py 10.129.121.28 -n ghostlink --assist-final

# Revisa el análisis guardado
cat ghostlink/ANALISIS-FINAL.md
```

Diferencia con `--assist` (que corre a mitad del recon, con datos
parciales): `--assist-final` junta README + attack-surface + findings
completos + misconfigurations + credenciales + diff, y pide un análisis
de analista senior: vector de entrada más prometedor con evidencia,
combinaciones de hallazgos peligrosas juntas, qué verificar antes de
explotar, y qué podría ser falso positivo. Sigue sin ejecutar nada —
es una sola llamada de solo lectura sobre texto ya generado.



`hosts.txt` (una IP por línea, `#` para comentarios):
```
10.129.121.28
10.129.55.10
# 10.129.99.99  <- esta se ignora
```

## Estructura de salida

```
ghostlink/
├── 01_target/
├── 02_discovery/
├── 03_nmap/
├── 04_web/
├── 05_services/
│   └── ad/                    (kerbrute, rpcclient, AS-REP, BloodHound)
├── 06_vulnerabilities/
│   ├── nmap-vuln.txt          (solo con --deep)
│   ├── nuclei.txt             (solo con --deep)
│   ├── findings.md / .json
│   ├── misconfigurations.md
│   ├── diff.md                (si ya existía una corrida previa)
│   └── history/               (findings.json archivados por timestamp)
├── 07_credentials/
│   ├── credentials-found.md
│   └── bruteforce-suggestions.md  (comandos sugeridos, nunca ejecutados)
├── screenshots/                (con --screenshots)
├── exploits/
├── loot/
├── scripts/
├── README.md                   (autogenerado)
├── attack-surface.md           (autogenerado)
├── report.html                 (con --html-report)
└── recon.log
```

## Correlación de CVEs

El módulo `vuln_correlation.py`:

1. Lee `03_nmap/targeted.xml` (salida de `nmap -sCV`) y extrae producto/versión de cada servicio.
2. Consulta la API pública de **NVD** por CVEs relacionados (sin API key; delay de 6s entre requests, con retry/backoff automático si responde 429).
3. Busca PoCs públicos en **GitHub** por nombre de CVE (solo guarda el link, nunca clona repos automáticamente).
4. Asigna un nivel de **confianza** (`HIGH` / `MEDIUM` / `LOW`) según qué tan específica es la versión detectada.
5. Con `--deep` y `nuclei` instalado, cruza resultados: si nuclei confirma el CVE, el finding pasa de `POTENTIAL` a `VERIFIED`.
6. Nunca marca algo como "vulnerable" sin más — todo queda como `POTENTIALLY VULNERABLE` salvo verificación explícita.
7. Si ya existía una corrida anterior, `diffing.py` archiva el `findings.json` previo y genera `diff.md` con los CVEs nuevos/desaparecidos.

## Active Directory

Se activa automáticamente cuando se detecta el patrón 88 (Kerberos) + 389 (LDAP) + 445 (SMB):

- `rpcclient -U "" -N` para enumeración anónima (usuarios, grupos, info de dominio)
- `kerbrute userenum` si se pasa `--ad-domain` y `--ad-userlist` (nunca adivina nombres de usuario sin wordlist)
- AS-REP roasting automático (`GetNPUsers.py`) sobre los usuarios válidos encontrados
- Sugerencia de comando de Kerberoasting (requiere credenciales, no se ejecuta solo)
- BloodHound collection solo si se proveen credenciales explícitas

## Credenciales y fuerza bruta

- `credentials.py` recorre todo lo recolectado buscando patrones de password/API keys/hashes NTLM/claves privadas — todo marcado como **requiere verificación manual**, muchos falsos positivos esperables.
- `bruteforce_suggest.py` deja comandos de `hydra` sugeridos para SSH/FTP/SMB/RDP detectados, pero **nunca los ejecuta**.

## Notas

- Sin conexión a internet, el módulo de correlación de CVEs avisa y se desactiva solo; el resto del recon sigue funcionando con normalidad.
- Pensado exclusivamente para laboratorios autorizados (HTB, eJPT, entornos propios).
