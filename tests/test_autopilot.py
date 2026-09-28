import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.autopilot import Decisiones, decidir_tras_puertos, decidir_tras_hostname, decidir_reportes_finales


def test_maquina_simple_no_escala():
    d = Decisiones()
    args = SimpleNamespace(deep=False, screenshots=False, custom_templates=False, ad_domain=None)
    args = decidir_tras_puertos(args, d, [22])
    assert args.deep is False
    assert args.screenshots is False


def test_maquina_compleja_escala_todo():
    d = Decisiones()
    args = SimpleNamespace(deep=False, screenshots=False, custom_templates=False, ad_domain=None)
    args = decidir_tras_puertos(args, d, [22, 80, 445, 8080, 3306])
    assert args.deep is True
    assert args.screenshots is True
    assert args.custom_templates is True


def test_no_activa_ad_sin_hostname_confirmado():
    d = Decisiones()
    args = SimpleNamespace(ad_domain=None)
    args = decidir_tras_hostname(args, d, set(), [88, 389, 445])
    assert args.ad_domain is None


def test_activa_ad_con_hostname_confirmado():
    d = Decisiones()
    args = SimpleNamespace(ad_domain=None)
    args = decidir_tras_hostname(args, d, {"corp.local"}, [88, 389, 445])
    assert args.ad_domain == "corp.local"


def test_reportes_finales_con_findings():
    d = Decisiones()
    args = SimpleNamespace(pdf_report=False, export_tickets=None, attack_graph=False)
    findings = [{"cve": "CVE-1"}, {"cve": "CVE-2"}]
    args = decidir_reportes_finales(args, d, findings, [80, 445])
    assert args.pdf_report is True
    assert args.export_tickets == "ambos"
    assert args.attack_graph is True


def test_reportes_finales_sin_nada_que_reportar():
    d = Decisiones()
    args = SimpleNamespace(pdf_report=False, export_tickets=None, attack_graph=False)
    args = decidir_reportes_finales(args, d, [], [22])
    assert args.pdf_report is False
    assert args.export_tickets is None
    assert args.attack_graph is False


def test_decisiones_se_escriben_a_archivo(tmp_path):
    d = Decisiones()
    d.decidir("deep", True, "razón de prueba")
    d.escribir(tmp_path)

    output = tmp_path / "01_target" / "decisiones-autopiloto.md"
    assert output.exists()
    contenido = output.read_text()
    assert "deep" in contenido
    assert "razón de prueba" in contenido
