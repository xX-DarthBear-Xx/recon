# Changelog

## v6.1.0 — identidad visual

### Cambiado
- **README.md rediseñado por completo**: badges, tabla de features por categoría, diagrama de arquitectura en Mermaid (renderiza nativo en GitHub), secciones colapsables por tipo de comando, identidad visual consistente con el portafolio de DarthBear (oscuro + acento rojo).
- **Banner de terminal rediseñado** (`modules/utils.py: banner()`): wordmark "RECON" en block letters ASCII, firma "by DarthBear" con versión y link al repo. Probado sin import circular (usa import perezoso de `VERSION` dentro de la función).

## v6.0.0 — release de seguridad

Auditoría de seguridad real: cada hallazgo se confirmó con un exploit
de prueba antes de corregirse, y se re-probó contra el mismo exploit
después del fix. Ver `SECURITY.md` para el detalle completo.

### Corregido (crítico)
- **Path traversal vía `-n`/`--nombre`** (incluyendo desde `api_server.py` sin autenticación): `modules/utils.py: sanitizar_nombre_workspace()` ahora rechaza rutas absolutas y componentes `..`, resolviendo siempre dentro de `workspaces/`.
- **`team_server.py` escuchaba en `0.0.0.0` sin autenticación**: ahora `127.0.0.1` por defecto, requiere `TEAM_SERVER_ALLOW_LAN=1` explícito para exponerse en red.
- **XSS almacenada en `attack-graph.html`**: un hostname/credencial con `</script>` literal (dato que el objetivo controla) rompía el tag y ejecutaba JS arbitrario. Corregido escapando `</` como `<\/` en el JSON embebido.
- **Fuga de workspaces (credenciales reales) a git**: `workspaces/` ahora vive en `.gitignore` de raíz; antes una carpeta como `ghostlink/` con hashes AS-REP/contraseñas reales no estaba protegida.

### Corregido (alto)
- **CSV Formula Injection en `--export-tickets`**: sanitización defensiva real en `ticket_export._sanitizar_celda_csv()` (antepone `'` si una celda empezaría con `=`, `+`, `-`, `@`). Nota de honestidad: tras revisión más rigurosa, el riesgo práctico actual era menor de lo inicialmente reportado (los campos van prefijados con texto fijo), pero el fix es correcto como defensa en profundidad para exports futuros.
- **Contraseñas visibles en consola/logs** (`bloodhound_collect`): `run_command()` soporta `mask_after=N` para no imprimir secretos en stdout. Limitación documentada y no eliminable del todo: `ps aux` sigue exponiéndolas a otros usuarios del mismo sistema mientras corre — es una limitación de cómo funcionan los argumentos CLI en general, ver `SECURITY.md`.

### Corregido (medio)
- **Crash del PDF con banner de servicio malicioso**: `reportlab.Paragraph` interpretaba pseudo-markup (`<b><font size=99>`) como su propio lenguaje y crasheaba `--pdf-report` completo. Corregido con `html.escape()` antes de pasar texto derivado del objetivo a `Paragraph`.
- **`--auto-exploit`**: advertencia reforzada sobre typosquatting en GitHub search (más estrellas ≠ repo legítimo).

### Añadido
- **`SECURITY.md`**: registro completo de hallazgos, con qué se probó, qué se corrigió, y qué limitaciones NO se pueden eliminar del código (documentadas en vez de ocultadas).
- 6 tests nuevos (`tests/test_security_fixes.py`) que re-ejecutan cada exploit confirmado contra el fix correspondiente — **47/47 tests totales pasan**.

## v5.2.0 — análisis final sobre el reporte completo

### Añadido
- **`--assist-final`** (`modules/final_assist.py`): a diferencia de `--assist` (que corre a mitad del recon con datos parciales en memoria), esto corre **al terminar todo**, junta el contenido real de README, attack-surface, findings.md completo, misconfigurations, credenciales encontradas y el diff con la corrida anterior, y hace **una sola llamada al LLM** pidiéndole que actúe como un analista senior revisando el trabajo ya hecho: vector de entrada más prometedor con evidencia, combinaciones de hallazgos peligrosas juntas, qué verificar antes de explotar, y qué podría ser falso positivo. Se guarda en `ANALISIS-FINAL.md`.
- **Probado de verdad**: la recopilación del reporte, el truncado de archivos largos (límite de 6000 caracteres por sección para no disparar el costo del prompt sin control), la construcción del prompt final, y el fallo limpio sin `ANTHROPIC_API_KEY` configurada — todo verificado con el escenario de ejemplo de Active Directory de la respuesta anterior. La llamada real a la API de Anthropic sigue sin poder probarse en este entorno de desarrollo (sin red saliente a ese dominio).

### Corregido
- **Bug real de robustez** en `modules/vuln_correlation.py: escribir_findings_md()`: la función asumía que cada finding siempre tenía las claves `references`, `poc`, `severity`, `cve`, `product`, etc., y crasheaba con `KeyError` si un `findings.json` (por ejemplo, editado a mano, o generado por una versión anterior/distinta) no las tenía todas. Encontrado en el proceso de probar `--assist-final` contra el workspace de ejemplo de AD. Corregido usando `.get()` con valores por defecto en todos los accesos.

### Nota de honestidad
Esto sigue sin ser un "agente" que ejecuta cosas por su cuenta -- es una sola llamada de API, de solo lectura, sobre texto ya generado. La opción de un agente real en loop (que pida ejecutar comandos y siga razonando con el resultado) se consideró y se descartó por ahora: cuesta una llamada de API por iteración y necesitaría límites y confirmaciones más elaboradas antes de ser seguro por defecto.

## v5.1.1 — bug real de overflow en la tabla de findings del PDF

### Corregido
- Bug real encontrado generando un ejemplo de reporte para un escenario de Active Directory: nombres de producto largos (ej. "Active Directory Certificate Services") se salían de su celda en la tabla de vulnerabilidades del PDF y se sobreponían visualmente con las columnas "Estado"/"Confianza". La tabla usaba strings crudos en vez de objetos `Paragraph` de reportlab, que son los que hacen word-wrap real dentro de una celda. Corregido en `modules/pdf_report.py` — solo la columna "Producto" usa `Paragraph` (las demás son cortas y no lo necesitan; además los objetos `Paragraph` ignoran el `TEXTCOLOR` de `TableStyle`, así que mantener las demás columnas como texto plano evitó un segundo bug de texto invisible sobre fondo de color). **Verificado visualmente antes y después del fix** con un escenario real de AD (Zerologon + noPac + Certifried + Kerberos KDC).

## v5.1.0 — modo autopiloto

### Añadido
- **`--auto`** (`modules/autopilot.py`): un solo flag en vez de tener que elegir entre `--deep`, `--screenshots`, `--pdf-report`, `--attack-graph`, `--export-tickets`, `--custom-templates`, `--ad-domain` uno por uno. Es un **motor de reglas determinista, no un LLM** (eso ya existe aparte en `--assist`) — llamado "autopiloto" y no "IA" a propósito, para no prometer algo que no es. Decide en 3 momentos:
  - Tras conocer los puertos TCP: si hay ≥4 puertos no-SSH, escala a `--deep`; si hay web, activa `--screenshots` y `--custom-templates`.
  - Tras confirmar un hostname real en `/etc/hosts`: si además hay patrón de Domain Controller (88+389+445), activa `--ad-domain` con ese hostname — **nunca antes**, para no adivinar un dominio sin evidencia.
  - Al final, con los findings ya conocidos: activa `--pdf-report` si hay algo que reportar, `--export-tickets` si hay findings, `--attack-graph` si hay ≥2 findings (un grafo con un solo nodo no aporta nada).
  - **Nunca** activa por sí solo `--active-verify`, `--auto-exploit` ni `--param-fuzz` — autonomía en qué documentar, nunca en qué tan agresivo ser contra el objetivo.
  - Cada decisión se registra con su justificación en `01_target/decisiones-autopiloto.md` — el modo autónomo nunca es una caja negra.
- **Probado de verdad**: 7 tests nuevos (`tests/test_autopilot.py`) cubriendo máquina simple (no escala), máquina compleja (escala todo), AD sin/con hostname confirmado, reportes finales con/sin findings, y la escritura real del archivo de justificación — **36/36 tests totales pasan**.

### Nota de honestidad sobre el nombre
El usuario pidió algo que se sintiera "como si una IA lo estuviera corriendo". Esto es un motor de reglas escrito a mano, elegido a propósito sobre llamar a un LLM en cada decisión (que sí sería posible, combinando esto con `--assist`, pero cuesta una petición de API por decisión y no es determinista/auditable de la misma forma). Se documenta así explícitamente para no sobre-vender la funcionalidad.

## v5.0.0

Reducir la fricción de decisión y ampliar a quién le sirve la
herramienta: modo inteligente, modo core, modo offline, y un perfil
para auditar tu propia infraestructura en vez de solo atacar la ajena.

### Añadido
- **`--core-only`** (`modules/run_modes.py`): apaga de un solo flag toda la funcionalidad extendida (AD, LLM, grafos, team-server, webhooks, PDF, tickets, templates propios, param-fuzz, auto-exploit, screenshots, html-report), dejando solo nmap+web+CVE+reporting. **Probado de verdad**: confirma que apaga los 13 flags extendidos sin tocar `--deep`/`--profile`/`--resume`/`--lang`.
- **`--smart`** (`modules/run_modes.py`): en vez de prender todo desde el inicio, activa selectivamente según lo que se va descubriendo — si detecta patrón de Domain Controller (88+389+445) Y ya hay un hostname candidato confirmado, activa `--ad-domain` automáticamente con ese dominio (nunca adivina uno de la nada); si detecta puertos web, activa `--pdf-report` y `--screenshots` al final. **Probado de verdad** en los 4 escenarios (con evidencia, sin evidencia, con web, sin web).
- **Modo offline** (`modules/offline_cve.py`, `--offline`, `prepare_offline.py`): correlación de CVEs contra una base SQLite local en vez de la API de NVD en tiempo real, para exámenes/entornos air-gapped. Se prepara UNA VEZ con red (`prepare_offline.py`) y después el recon en sí nunca vuelve a tocar internet para CVEs. **Probado de verdad end-to-end**: importé un dump JSON de prueba, corrí `correlacionar_vulnerabilidades(..., offline=True)` contra un XML de nmap simulado, y encontró correctamente el CVE — sin ninguna llamada de red.
- **`recon-writeups.py`**: ayuda de estudio POST-resolución vía la API pública de ippsec.rocks, con salvaguarda real (no solo textual): se niega a correr sin `--ya-la-resolvi`. **Probado de verdad** que la salvaguarda bloquea (`exit code 1`) sin el flag.
- **Perfil `self-audit`** (`modules/profiles.py`, `--profile self-audit`): escaneo conservador para auditar tu propia infraestructura; bloquea `--param-fuzz`, `--active-verify` y `--auto-exploit` **incluso si se pasan explícitamente** — es una salvaguarda real, no solo un valor por defecto. **Probado de verdad**.
- 6 tests nuevos (`tests/test_v5_modules.py`) cubriendo `run_modes` y `offline_cve` — 29/29 tests totales verificados como correctos (uno de ellos requiere el fixture `monkeypatch` de pytest real, que no estaba disponible en el runner manual de este entorno de desarrollo, pero se verificó la misma lógica manualmente con el mismo resultado).

### Descubrimiento sobre el entorno de desarrollo
- Durante esta sesión se confirmó que el sandbox donde se ha construido y probado este proyecto tiene un **egress allowlist**, no ausencia total de red: las peticiones a dominios no listados (NVD, GitHub, ippsec.rocks, incluso github.com/pypi.org) devuelven `403 Host not in allowlist`, en vez de timeout o connection refused. Esto no cambia ninguna conclusión de sesiones anteriores (seguía siendo cierto que no se pudo probar contra APIs reales), pero aclara la causa exacta.

### Pendiente honesto
- `recon-writeups.py` nunca se probó con la API de ippsec.rocks realmente accesible (el sandbox de desarrollo no tiene ese dominio en su allowlist).
- `prepare_offline.py --keywords ...` (la ruta que sí llama a NVD para armar el dump inicial) nunca se probó con red real; solo se probó la importación de un dump ya armado manualmente.
- Sigue sin probarse el pipeline completo contra una máquina real de HTB.

## v4.0.1 — recon web dirigido al hostname real, no a la IP

### Añadido
- **Sonda temprana de hostname** (`modules/web.py: sondar_hostname_temprano`): antes de correr el recon web pesado (directorios, whatweb, screenshots), se hace una sonda liviana (headers HTTP + Common Name del certificado TLS) para descubrir el hostname real de la máquina (ej. `ghostlink.htb`). Si se encuentra y se confirma en `/etc/hosts`, **todo el recon web pesado se dirige al hostname en vez de la IP** — que en HTB casi siempre da resultados de enumeración de directorios distintos (o vacíos) comparado con enumerar directamente contra el vhost real.
- `modules/hostnames.py` refactorizado: la lógica de regex ahora vive en `extraer_de_texto()`, reutilizable tanto para escanear archivos como para la sonda temprana sobre texto suelto (headers, certificados). `agregar_hosts()` ahora devuelve qué hostnames quedaron efectivamente resueltos (ya existían o se acaban de escribir), para que el llamador sepa cuáles son seguros de usar como URL.

### Probado de verdad
- `extraer_de_texto()` detecta correctamente un hostname en un header `Location:` simulado y en un `subject=CN=` de certificado simulado.
- `sondar_hostname_temprano()` falla limpio (sin crash, con timeout controlado) cuando no hay red real.
- La lógica de decisión "usar objetivo_web en vez de ip" probada con mocks: si la sonda encuentra un hostname y se confirma en `/etc/hosts`, ese hostname se usa como target para `http_recon`/`ssl_recon`.

### Pendiente honesto
- No se probó contra un servidor HTTP real con redirect a vhost — el comportamiento de la sonda con datos reales de HTB sigue sin validar.
- `vhost_fuzz` sigue usando la IP intencionalmente (necesita golpear la IP directa con distintos headers `Host:` para descubrir vhosts, no tendría sentido apuntarlo al hostname que ya se descubrió).

## v4.0.0

De plataforma comunitaria a suite de entrega profesional: reportes PDF,
templates propios, checkpoints, y las últimas integraciones de equipo.

### Añadido
- **Reporte PDF profesional** (`modules/pdf_report.py`, `--pdf-report --pdf-template default|oscp --pdf-redacted`): portada, resumen ejecutivo con conteo real de severidades, tabla de puertos, tabla de findings con colores por severidad, grafo de ataque embebido, screenshots, hash SHA256 del PDF final. Usa `reportlab` (no `weasyprint`, para evitar dependencias de sistema como Pango/Cairo). **Probado de verdad**: PDF de 2-3 páginas generado, validado como PDF real con `file`, y visualizado página por página con `pdf2image` — se ve profesional, colores correctos, cálculos del resumen ejecutivo verificados.
- **Grafo de ataque estático** (`modules/attack_graph_static.py`): versión PNG (networkx + matplotlib) del mismo grafo interactivo de v3.0, para embeber en el PDF (que no ejecuta JavaScript). **Probado de verdad** con el mismo escenario credencial-SMB-a-SSH/WinRM de v3.0, visualizado y confirmado correcto.
- **Exportador de tickets** (`modules/ticket_export.py`, `--export-tickets csv|json|ambos`): cada finding como fila CSV (formato de importación Jira) o entrada JSON (Trello/scripts propios), con severidad mapeada a prioridad. **Probado de verdad**, y se encontró+corrigió un bug real: ni `exportar_csv` ni `exportar_json` creaban la carpeta destino si no existía.
- **Modo resume/checkpoint** (`modules/checkpoints.py`, `--resume`, `--show-checkpoints`): detecta heurísticamente qué fases ya completaron (por la existencia y tamaño de su archivo de salida) y las salta. **Probado de verdad** end-to-end desde el CLI: detectó correctamente 2 de 8 fases completas en un workspace con progreso parcial simulado.
- **Templates propios tipo Nuclei** (`modules/custom_templates.py`, `--custom-templates`, formato YAML en `templates/custom/`): la comunidad puede contribuir checks de verificación activa sin tocar Python. **Probado de verdad**: cargó el template de ejemplo (CVE-2021-41773) y el matcher regex detectó/no-detectó correctamente contra texto simulado.
- **Fuzzing de parámetros** (`modules/param_fuzz.py`, `--param-fuzz`): prueba una wordlist corta de parámetros GET comunes y señala diferencias de status/longitud como pistas para revisión manual, nunca como confirmación.
- **Multi-idioma en reportes** (`modules/i18n.py`, `--lang es|en`): diccionario de strings para el contenido de los reportes (no la CLI). **Probado de verdad**, incluyendo el fallback a español si falta una clave.
- **API REST** (`api_server.py`, independiente): `/scan`, `/scan/<job_id>`, `/history` para disparar recons vía HTTP en background. **Probado de verdad** en los casos sin red (validación de input, 404 de job inexistente, /history vacío) — nunca se probó disparando un recon real en background.
- **Webhooks de equipo** (`modules/team_webhooks.py`, `--webhook-url --webhook-platform discord|slack`): notifica al canal del equipo al terminar, con severidad resaltada. **Probado de verdad** la construcción de payloads (JSON válido, contenido correcto) — nunca se probó contra un webhook real de Discord/Slack.

### Corregido
- Bug real en `modules/ticket_export.py`: ni `exportar_csv` ni `exportar_json` creaban `06_vulnerabilities/` si no existía, encontrado al correr los tests con un directorio temporal limpio.

### Pendiente honesto
- `api_server.py` y `modules/team_webhooks.py` tienen su lógica de red sin probar contra servicios reales (sin red en este entorno de desarrollo) — sí se probó toda la lógica que no requiere red saliente.
- El motor de templates propio (`custom_templates.py`) es deliberadamente simple (solo matcher "word"/regex sobre el body); para necesidades más avanzadas se sigue recomendando nuclei real.
- Sigue sin probarse el pipeline completo contra una máquina real de HTB.

## v3.0.1 — correcciones post-release

### Corregido (bugs reales encontrados con pruebas)
- **Vendoring de `termcolor` y `pyperclip`**: antes el proyecto crasheaba por completo sin estas dos librerías instaladas. Ahora `modules/_vendor_termcolor.py` y `modules/_vendor_pyperclip.py` son fallbacks locales sin dependencias externas — **probado de verdad**: `recon.py --version` corre limpio en un entorno donde ninguna de las dos está instalada.
- **`pyproject.toml` no empaquetaba `modules/`**: el sdist/wheel solo incluía los scripts top-level, dejando el paquete completamente roto al instalar. Corregido agregando `packages = ["modules", "modules.custom"]`. **Probado de verdad**: build de sdist y wheel reales con `setuptools.build_meta`, instalación en un venv aislado, y los tres entry points (`recon`, `recon-note`, `recon-postexploit`) ejecutados exitosamente desde la instalación.
- **Tests automatizados reales** (`tests/`): 15 tests cubriendo hostnames, correlación de CVEs, grafo de ataque, plugins y paralelización. Corridos de verdad (sin `pytest` disponible en el entorno de desarrollo, con un runner manual equivalente) — **15/15 pasan**, y en el proceso se encontró y corrigió un bug real en uno de los tests (no en el código: la aserción esperaba una clave de contexto con el prefijo `recon_custom_` que `plugin_loader.py` en realidad elimina).
- **CI de GitHub Actions** (`.github/workflows/ci.yml`): corre los tests y valida sintaxis en Python 3.9–3.12 en cada push/PR.
- **`CONTRIBUTING.md`**: guía para quien quiera aportar al proyecto open source (cómo agregar plugins vs módulos built-in, filosofía de "nunca ejecutar exploits sin confirmación", cómo correr los tests).

### Pendiente honesto
- `TU_USUARIO`/`[TU NOMBRE]` en `LICENSE` y `pyproject.toml` siguen siendo placeholders — requieren tu información real antes de publicar.
- El CI de GitHub Actions nunca corrió en GitHub real (sin red en este entorno) — la sintaxis del YAML es estándar pero no se validó ejecutándolo.
- Los tests cubren lógica pura (parseo, regex, cálculos); no cubren integración real con nmap/NVD/GitHub — eso sigue pendiente de tu primera corrida real.

## v3.0.0

De framework a plataforma para la comunidad. Open source, pensado para
hackers éticos más allá de solo HTB/eJPT.


### Añadido
- **Asistencia con LLM** (`modules/llm_assist.py`, `--assist`): analiza puertos/URLs/findings ya recolectados y sugiere próximos pasos vía la API de Anthropic (agnóstico de proveedor, un solo punto de integración para cambiarlo). Nunca ejecuta nada, solo sugiere en texto.
- **Grafo de ataque** (`modules/attack_graph.py` + `attack_graph_viz.py`, `--attack-graph`): relaciona puertos, CVEs, credenciales y hostnames como nodos conectados (ej. "credencial de SMB → probar en SSH/WinRM"), con export a JSON y visualización interactiva en HTML (D3.js). **Probado de verdad**: generó correctamente el camino "credencial SMB → SSH/WinRM" y detectó el nodo de mayor centralidad con `networkx`.
- **Modo colaborativo** (`team_server.py`, `--team-server URL --member NOMBRE`): backend Flask+SQLite independiente donde varios miembros de un equipo envían sus corridas y ven el estado combinado. **Probado de verdad** con un POST simulado + verificación del dashboard — encontró y corrigió un bug real de sintaxis Jinja2 en el proceso.
- **Verificación activa** (`modules/active_verify.py`, `--active-verify`): checks puntuales y no destructivos (una sola petición) para confirmar explotabilidad real de CVEs sospechosos (ej. CVE-2021-41773), en vez de quedarse en "POTENTIAL". Requiere flag explícito porque sí toca el objetivo.
- **Análisis de patrones personales** (`pattern_analysis.py`): consulta el histórico SQLite acumulado y reporta qué puertos/combinaciones se repiten más y en qué productos sueles encontrar más vulnerabilidades. **Probado de verdad** con 3 corridas simuladas — detectó correctamente el patrón repetido.
- **Post-explotación** (`recon-postexploit.py`): parsea output de linpeas/winpeas ya generado (nunca lo ejecuta remotamente) y lo correlaciona contra el `findings.json` del recon inicial.
- **Empaquetado pip real** (`pyproject.toml`): `pip install .` instalable, con extras opcionales (`[graph]`, `[full]`). TOML validado sintácticamente; el build/install end-to-end no se ha probado por falta de red en el entorno de desarrollo.
- **Actualizador de recursos** (`update_resources.py`): actualiza templates de nuclei y verifica que las wordlists de `config/tools.conf` existan.

### Corregido
- Bug real en `team_server.py`: el CSS del template usaba `{{ }}` (sintaxis de f-string) dentro de un string plano renderizado por Jinja2, lo que causaba un `TemplateSyntaxError` en cualquier request a `/`. Encontrado y corregido mediante prueba real con Flask test client.

### Conocido / pendiente
- `pip install .` (pyproject.toml) nunca se probó end-to-end — solo se validó que el TOML es sintácticamente correcto.
- `--assist` requiere `ANTHROPIC_API_KEY` en el entorno; sin red en este entorno de desarrollo, la llamada real a la API nunca se probó (sí se probó que falla controladamente sin la key).
- `--active-verify` nunca se probó contra un servidor HTTP real (sí se probó que no crashea sin red).
- El modo colaborativo (`team_server.py`) no tiene autenticación — pensado para red local/VPN de equipo, no para exponerse a internet.
- Se omitió deliberadamente la integración con la API oficial de HTB (a pedido del usuario, para mantener la herramienta agnóstica de plataforma y útil para la comunidad de hacking ético en general, no solo HTB).

## v2.0.0

Salto de arquitectura: de "script con muchos módulos" a framework extensible.

### Añadido
- **Arquitectura de plugins** (`modules/plugin_loader.py`): cualquier `.py` en `modules/custom/` con una función `run(ip, folder, context)` se auto-descubre y se ejecuta, sin tocar `recon.py`. Probado con un plugin de ejemplo real en este entorno.
- **Paralelización real** (`modules/parallel.py`): SMB, FTP, DNS, SNMP, LDAP, SMTP y bases de datos corren en threads simultáneos vía `ThreadPoolExecutor` en vez de secuencial. Verificado: 3 tareas de 0.3s cada una terminan en 0.3s total, no 0.9s.
- **Base de datos histórica SQLite** (`modules/history_db.py`, en `~/.recon/history.db`): cada corrida queda registrada; permite preguntar "¿en qué otras máquinas vi este CVE?" (`buscar_cve_en_historico`) o ver estadísticas agregadas (`resumen_historico`). Probado con dos corridas simuladas y una búsqueda cruzada real.
- **Dashboard web local** (`dashboard.py`, Flask): sirve en `http://127.0.0.1:5000` un resumen del histórico (máquinas escaneadas, CVEs más frecuentes). Renderizado verificado con Flask test client.
- **Explotación asistida** (`modules/exploit_assist.py`, `--auto-exploit`): con confirmación explícita, clona (nunca ejecuta) el PoC de GitHub con más estrellas para cada CVE encontrado, dentro de `exploits/<CVE>/`, con un `target.txt` ya rellenado (IP, puerto, versión).
- **Perfiles de escaneo** (`modules/profiles.py`, `--profile stealth|ctf|oscp-report`): ajustan de golpe `--min-rate` de nmap, si se corre NSE vuln, y si se toman screenshots, en vez de solo el binario `--deep`.
- **Modo JSON-only** (`--json-only`): imprime un único JSON a stdout (todo lo demás va a `recon.log`), para encadenar `recon.py` con otros scripts sin parsear texto de terminal.
- **Bitácora integrada** (`recon-note.py`): `python3 recon-note.py <workspace> "nota"` inserta la nota con timestamp en el README, sin abrir el editor. Probado de verdad, inserta correctamente bajo la sección indicada.

### Cambiado
- `nmap_scan.escanear_puertos_tcp` ahora acepta `min_rate` (antes hardcodeado a 5000), para que los perfiles lo controlen.
- El flujo principal de `recon.py` se reestructuró: fase secuencial (discovery → TCP → UDP → OS → web) seguida de fase paralela (servicios) seguida de fase de plugins de usuario.

### Conocido / pendiente
- Los módulos de red real (kerbrute, rpcclient, gowitness, NVD, GitHub) siguen sin probarse contra una máquina real — todo lo de esta sección sí se probó de verdad, pero es lógica nueva (plugins, paralelismo, DB, dashboard), no las llamadas a herramientas externas de red.
- Sin soporte de autenticación en el dashboard (pensado para uso local en localhost, no para exponer en red).

## v1.0.0

Primera versión estable del framework modular.

### Añadido
- Estructura modular completa (`modules/`): nmap, web, servicios, hostnames, reporting, correlación de vulnerabilidades, misconfiguraciones.
- **Active Directory**: enumeración anónima con `rpcclient`, `kerbrute userenum`, AS-REP roasting automático, sugerencia de Kerberoasting, BloodHound collection (con credenciales).
- **Screenshots automáticos** de cada URL web/vhost con `gowitness`/`eyewitness` (`--screenshots`).
- **Credenciales activas**: grep de patrones (passwords, API keys, hashes NTLM, claves privadas) sobre todo lo recolectado.
- **Sugerencias de fuerza bruta** (hydra) para SSH/FTP/SMB/RDP — nunca se ejecutan automáticamente.
- **Notificación** (beep + notify-send) al terminar cada recon (`--no-notify` para desactivar).
- **Reporte HTML consolidado** (`--html-report`) con README + attack-surface + findings + misconfigs + credenciales + screenshots embebidos en un solo archivo portable.
- **Batch mode** (`--targets-file`) para correr varias IPs en secuencia, cada una en su propia carpeta.
- **Diffing entre corridas**: si ya existía un recon previo de la misma máquina, archiva el `findings.json` anterior y genera `diff.md` con CVEs nuevos/desaparecidos.
- CLI con `argparse`: `--deep`, `--vhost-domain`, `--ad-domain`, `--ad-userlist`, `--screenshots`, `--html-report`, `--no-notify`, `-y`, `--version`.
- Extracción real de puertos UDP (antes se ignoraban).
- Correlación de CVEs contra NVD + búsqueda de PoC en GitHub, con niveles de confianza (HIGH/MEDIUM/LOW) y verificación opcional con `nuclei` en modo `--deep`.
- Retry/backoff automático ante rate-limit (429) de la API de NVD.
- Detección de misconfiguraciones y archivos interesantes expuestos por HTTP (`.git`, `.env`, backups, etc.).
- `README.md` y `attack-surface.md` autogenerados por máquina.
- `config/tools.conf` centraliza rutas de wordlists y parámetros, ya conectado al código.
- Logging a `recon.log` dentro del workspace de cada máquina.

### Corregido
- Bug de precedencia de operadores en el filtro de hostnames (`not x or y` → filtraba casi nada).
- Módulos LDAP, SMTP y bases de datos, ausentes en la v0.

### Conocido / pendiente para v1.1
- El módulo de correlación de CVEs no ha sido probado contra la API real de NVD en este entorno de desarrollo (sin acceso a red); validar en el primer uso real.
- Kerberoasting real (`GetUserSPNs.py`) requiere credenciales y solo se sugiere el comando, no se ejecuta.
- El render de markdown en `html_report.py` es minimalista (hecho a mano, sin librería externa) — suficiente para los reportes propios, no para markdown arbitrario.
- BloodHound collection solo corre con credenciales explícitas por CLI; falta soporte para pasarlas de forma más segura (variable de entorno / prompt oculto).

