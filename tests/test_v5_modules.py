import sys
import json
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import run_modes


def test_core_only_apaga_todo_lo_extendido():
    args = SimpleNamespace(
        core_only=True, ad_domain="algo", ad_userlist="x", assist=True,
        attack_graph=True, active_verify=True, team_server="url",
        webhook_url="url", pdf_report=True, export_tickets="csv",
        custom_templates=True, param_fuzz=True, auto_exploit=True,
        screenshots=True, html_report=True,
    )
    args = run_modes.aplicar_core_only(args)

    assert args.ad_domain is None
    assert args.assist is False
    assert args.pdf_report is False
    assert args.export_tickets is None


def test_core_only_no_hace_nada_si_no_se_pide():
    args = SimpleNamespace(core_only=False, pdf_report=True)
    args = run_modes.aplicar_core_only(args)
    assert args.pdf_report is True


def test_smart_activa_ad_solo_con_evidencia():
    args = SimpleNamespace(smart=True, ad_domain=None, pdf_report=False, screenshots=False)
    args = run_modes.aplicar_smart_mid_run(args, [88, 389, 445], {"corp.local"})
    assert args.ad_domain == "corp.local"


def test_smart_no_adivina_dominio_sin_hostname():
    args = SimpleNamespace(smart=True, ad_domain=None, pdf_report=False, screenshots=False)
    args = run_modes.aplicar_smart_mid_run(args, [88, 389, 445], set())
    assert args.ad_domain is None


def test_smart_sin_activar_no_hace_nada():
    args = SimpleNamespace(smart=False, ad_domain=None, pdf_report=False, screenshots=False)
    args = run_modes.aplicar_smart_mid_run(args, [88, 389, 445], {"corp.local"})
    assert args.ad_domain is None  # smart=False -> no debe tocar nada


def test_offline_cve_importa_y_consulta(tmp_path, monkeypatch):
    from modules import offline_cve

    # Aislar la DB en un HOME temporal para no tocar la real del sistema
    monkeypatch.setattr(offline_cve, "DB_PATH", tmp_path / "cve_offline.db")

    dump = tmp_path / "dump.json"
    dump.write_text(json.dumps([
        {"product": "Apache httpd", "version": "2.4.49", "cve_id": "CVE-2021-41773",
         "severity": "HIGH", "cvss": 7.5, "description": "Path traversal"},
    ]))

    total = offline_cve.importar_dump_json(dump)
    assert total == 1
    assert offline_cve.base_disponible() is True

    resultado = offline_cve.consultar_offline("Apache", "2.4.49")
    assert len(resultado) == 1
    assert resultado[0]["cve_id"] == "CVE-2021-41773"

    resultado_vacio = offline_cve.consultar_offline("nginx", "")
    assert resultado_vacio == []
