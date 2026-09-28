#!/usr/bin/env python3
"""Genera attack-graph.html: visualización interactiva del grafo con D3."""

import json
try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored

_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Attack Graph</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
  body {{ margin:0; background:#0f172a; color:#e2e8f0; font-family: -apple-system, sans-serif; }}
  h1 {{ padding: 16px 24px; color:#38bdf8; }}
  .puerto {{ fill:#38bdf8; }}
  .cve {{ fill:#f87171; }}
  .credencial {{ fill:#facc15; }}
  .hostname {{ fill:#4ade80; }}
  text {{ fill:#e2e8f0; font-size:11px; }}
  line {{ stroke:#475569; stroke-width:1.5px; }}
</style>
</head>
<body>
<h1>Attack Graph</h1>
<svg width="1100" height="700"></svg>
<script>
const data = {DATA_JSON};

const nodes = data.nodos.map(n => ({{...n}}));
const links = data.aristas.map(a => ({{source: a.origen, target: a.destino, relacion: a.relacion}}));

const svg = d3.select("svg");
const width = +svg.attr("width"), height = +svg.attr("height");

const simulation = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id).distance(120))
  .force("charge", d3.forceManyBody().strength(-300))
  .force("center", d3.forceCenter(width/2, height/2));

const link = svg.append("g").selectAll("line").data(links).join("line");

const node = svg.append("g").selectAll("circle").data(nodes).join("circle")
  .attr("r", 10)
  .attr("class", d => d.tipo)
  .call(d3.drag()
    .on("start", (event,d) => {{ if(!event.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on("drag", (event,d) => {{ d.fx=event.x; d.fy=event.y; }})
    .on("end", (event,d) => {{ if(!event.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; }}));

const label = svg.append("g").selectAll("text").data(nodes).join("text")
  .text(d => d.label).attr("dx", 14).attr("dy", 4);

simulation.on("tick", () => {{
  link.attr("x1", d=>d.source.x).attr("y1", d=>d.source.y)
      .attr("x2", d=>d.target.x).attr("y2", d=>d.target.y);
  node.attr("cx", d=>d.x).attr("cy", d=>d.y);
  label.attr("x", d=>d.x).attr("y", d=>d.y);
}});
</script>
</body>
</html>
"""


def generar_html_grafo(grafo, folder):
    output = folder / "06_vulnerabilities" / "attack-graph.html"

    # Fix de seguridad: json.dumps() NO escapa la secuencia "</" por
    # defecto. Si un nodo (hostname, credencial, etc. -- datos que el
    # OBJETIVO controla, vía un banner HTTP manipulado por ejemplo)
    # contiene literalmente "</script>", el JSON se rompe fuera del
    # <script> tag y cualquier JS que venga después se ejecuta -- XSS
    # almacenada real, confirmada con una prueba antes de este fix.
    # La mitigación estándar: escapar "</" como "<\/" dentro del JSON,
    # que sigue siendo JSON válido (\/ es un escape válido para '/')
    # pero ya no puede cerrar un tag HTML.
    datos_json = json.dumps(grafo, ensure_ascii=False).replace("</", "<\\/")

    html = _TEMPLATE.replace("{DATA_JSON}", datos_json)
    output.write_text(html, encoding="utf-8")
    print(colored(f"[+] Visualización del grafo en {output}", "green"))
    return output
