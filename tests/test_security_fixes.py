import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.utils import sanitizar_nombre_workspace, RutaInseguraError
from modules import attack_graph, attack_graph_viz, ticket_export, pdf_report


def test_path_traversal_bloqueado_con_dotdot():
    try:
        sanitizar_nombre_workspace("../../../../tmp/pwned")
        assert False, "debería haber lanzado RutaInseguraError"
    except RutaInseguraError:
        pass


def test_path_traversal_bloqueado_con_ruta_absoluta():
    try:
        sanitizar_nombre_workspace("/etc/algo")
        assert False, "debería haber lanzado RutaInseguraError"
    except RutaInseguraError:
        pass


def test_nombre_normal_sigue_funcionando():
    ruta = sanitizar_nombre_workspace("ghostlink")
    assert str(ruta) == str(Path("workspaces") / "ghostlink")


def test_xss_en_grafo_neutralizada():
    context = {"puertos": [80], "hostnames": ["</script><script>alert(1)</script>"]}
    grafo = attack_graph.construir_grafo(context, [], [])

    datos_json = json.dumps(grafo, ensure_ascii=False).replace("</", "<\\/")
    html = attack_graph_viz._TEMPLATE.replace("{DATA_JSON}", datos_json)

    assert "</script><script>alert(1)</script>" not in html
    assert "<\\/script>" in html  # el payload sigue ahí, pero ya no rompe el tag


def test_csv_celda_maliciosa_se_neutraliza():
    assert ticket_export._sanitizar_celda_csv("=cmd|calc").startswith("'")
    assert ticket_export._sanitizar_celda_csv("+1+1").startswith("'")
    assert ticket_export._sanitizar_celda_csv("texto normal") == "texto normal"


def test_pdf_no_crashea_con_markup_malicioso(tmp_path):
    (tmp_path / "06_vulnerabilities").mkdir()
    findings = [{"cve": "CVE-FAKE", "severity": "HIGH", "product": "<b><font size=99>ROTO",
                 "version": "1.0", "port": "80", "confidence": "HIGH", "status": "POTENTIAL"}]
    (tmp_path / "06_vulnerabilities" / "findings.json").write_text(json.dumps({"findings": findings}))

    resultado = pdf_report.generar_pdf(tmp_path, ip="10.10.10.10")
    assert resultado.exists()


def test_escapar_para_paragraph_neutraliza_markup():
    escapado = pdf_report._escapar_para_paragraph("<b><font size=99>ROTO")
    assert "<b>" not in escapado
    assert "&lt;b&gt;" in escapado
