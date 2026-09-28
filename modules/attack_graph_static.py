#!/usr/bin/env python3
"""
Versión estática (PNG) del grafo de ataque, para embeber en el PDF --
la versión interactiva (attack_graph_viz.py, D3) no sirve ahí porque un
PDF no ejecuta JavaScript.
"""

try:
    import networkx as nx
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    DISPONIBLE = True
except ImportError:
    DISPONIBLE = False

try:
    from termcolor import colored
except ImportError:
    from modules._vendor_termcolor import colored


_COLOR_POR_TIPO = {
    "puerto": "#38bdf8",
    "cve": "#f87171",
    "credencial": "#facc15",
    "hostname": "#4ade80",
    "usuario": "#c084fc",
    "servicio": "#fb923c",
}


def generar_imagen_grafo(grafo, folder):
    if not DISPONIBLE:
        print(colored("[!] networkx/matplotlib no disponibles, se omite imagen del grafo.", "yellow"))
        return None

    if not grafo["nodos"]:
        return None

    g = nx.DiGraph()
    for n in grafo["nodos"]:
        g.add_node(n["id"], **n)
    for a in grafo["aristas"]:
        g.add_edge(a["origen"], a["destino"])

    pos = nx.spring_layout(g, seed=42, k=0.8)

    colores_nodos = [_COLOR_POR_TIPO.get(g.nodes[n].get("tipo"), "#94a3b8") for n in g.nodes]
    labels = {n: g.nodes[n].get("label", n) for n in g.nodes}

    plt.figure(figsize=(9, 6.5))
    nx.draw_networkx_edges(g, pos, edge_color="#94a3b8", arrows=True, arrowsize=12)
    nx.draw_networkx_nodes(g, pos, node_color=colores_nodos, node_size=900)
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=8)
    plt.axis("off")
    plt.tight_layout()

    output = folder / "06_vulnerabilities" / "attack-graph.png"
    plt.savefig(output, dpi=150)
    plt.close()

    print(colored(f"[+] Imagen estática del grafo guardada en {output}", "green"))
    return output
