# Seguridad

Este documento registra un análisis de seguridad real hecho sobre el
código (no una checklist genérica) — cada hallazgo fue **probado con
un exploit de prueba antes de corregirse**, y cada fix fue **reprobado
contra el mismo exploit** para confirmar que quedó neutralizado.

## Hallazgos corregidos

### Crítico

**Path traversal vía `-n`/`--nombre` (incluyendo desde `api_server.py`)**
`Carpeta(nombre)` hacía `Path(nombre).mkdir()` sin sanitizar. Un
`--nombre` como `../../../../tmp/pwned` —o el mismo campo llegando sin
validar desde una petición HTTP a `api_server.py`— permitía escribir
fuera del directorio de workspaces esperado.
**Fix**: `modules/utils.py: sanitizar_nombre_workspace()` rechaza rutas
absolutas y cualquier componente `..`, y resuelve siempre dentro de
`workspaces/`.

**`team_server.py` escuchaba en `0.0.0.0` sin autenticación**
Cualquiera en la misma red/VPN podía leer o escribir el histórico
compartido del equipo.
**Fix**: por defecto escucha en `127.0.0.1`; requiere
`TEAM_SERVER_ALLOW_LAN=1` explícito (con advertencia impresa) para
exponerlo en red.

**XSS almacenada en `attack-graph.html`**
Un hostname/credencial que contuviera literalmente `</script>` (dato
que el **objetivo** controla, vía un banner HTTP manipulado, por
ejemplo) rompía fuera del `<script>` tag y ejecutaba JavaScript
arbitrario al abrir el archivo. Confirmado con un payload real antes
del fix.
**Fix**: `modules/attack_graph_viz.py` escapa `</` como `<\/` en el
JSON embebido (sigue siendo JSON válido, ya no puede cerrar el tag).

### Alto

**CSV Formula Injection en `--export-tickets`**
Nota tras revisión más rigurosa: el campo `Summary` en la práctica
actual siempre viene prefijado con texto fijo (`"[ip] CVE en ..."`),
así que un valor malicioso no llega a ser el primer carácter de la
celda en el código tal como estaba. El riesgo real era menor de lo que
se pensó inicialmente. Aun así, se aplicó sanitización defensiva real
(`modules/ticket_export.py: _sanitizar_celda_csv()`, antepone `'` si la
celda resultante empieza con `=`, `+`, `-` o `@`) para que cualquier
export futuro que exponga un campo sin prefijo quede protegido por
diseño, no por casualidad.

**Contraseñas visibles en `ps aux` y en la consola**
`bloodhound_collect()` pasa la contraseña como argumento CLI a
`bloodhound-python`.
**Fix parcial real**: `run_command()` ahora soporta `mask_after=N` para
no imprimir la contraseña en la terminal/logs de la sesión (probado:
ya no aparece en stdout). **Limitación que NO se puede eliminar del
código**: la contraseña sigue siendo visible vía `ps aux` o
`/proc/<pid>/cmdline` para otros usuarios del mismo sistema operativo
mientras el comando corre — es una limitación de cómo funciona el paso
de argumentos por línea de comandos en general, no algo que este script
pueda arreglar del todo sin cambiar la herramienta externa
(`bloodhound-python`) para que acepte la contraseña por otro medio (ej.
variable de entorno o prompt interactivo), que no todas las versiones
soportan. **Mitigación recomendada**: no uses `--ad-domain` con
credenciales reales en máquinas compartidas/multiusuario.

### Medio

**Crash del reporte PDF con un banner de servicio malicioso**
Un "producto" detectado con pseudo-markup (ej. `<b><font size=99>`,
que `reportlab.Paragraph` interpreta como su propio lenguaje de
marcado) hacía crashear `--pdf-report` por completo con un
`ParseError`. Confirmado con una prueba real antes del fix.
**Fix**: `modules/pdf_report.py: _escapar_para_paragraph()` aplica
`html.escape()` a cualquier texto derivado de datos del objetivo antes
de pasarlo a `Paragraph`.

**`--auto-exploit` y typosquatting en GitHub**
"Más estrellas" no significa "repo legítimo" — GitHub search puede
devolver un repo malicioso con nombre similar al CVE real.
**Mitigación**: se reforzó la advertencia impresa al clonar, recordando
revisar el código (especialmente scripts de instalación) antes de
ejecutar nada. Esto sigue siendo, por diseño, solo un **clon**, nunca
una ejecución automática.

## Cosas ya bien hechas (verificado, no solo asumido)

- **Sin `shell=True`** en ningún `subprocess` de todo el proyecto — el
  vector de inyección de comandos "clásico" está cerrado.
- **Sin `eval`/`exec`/`pickle`** en ningún módulo.
- **`yaml.safe_load()`** correcto en `custom_templates.py` (nunca
  `yaml.load()` sin `Loader` seguro).
- **SQL parametrizado** (placeholders `?`, nunca f-strings en queries)
  en `history_db.py`, `team_server.py`, `offline_cve.py`.
- **`verify=False`** en las peticiones HTTP hacia el objetivo es
  intencional (los objetivos de HTB/CTF suelen tener certificados
  self-signed) — aceptable ahí porque el objetivo es *el sujeto que se
  está evaluando*, no un servicio de terceros de confianza.

## Cómo reportar un hallazgo nuevo

Si encuentras algo que no esté en esta lista, abre un issue con:
- El archivo y función exactos
- Un payload/entrada de prueba que demuestre el problema (no solo la
  teoría — este proyecto prioriza fixes verificados sobre suposiciones)
- Qué esperarías que pasara en vez de eso

No se aceptan PRs que solo agreguen "más seguridad" en abstracto sin un
caso de prueba concreto que la justifique — ver `CONTRIBUTING.md`.
