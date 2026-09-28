import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import final_assist


def test_recopila_solo_archivos_existentes(tmp_path):
    (tmp_path / "README.md").write_text("# Mi maquina")
    # attack-surface.md NO existe -- no debe aparecer en el resultado

    reporte = final_assist.recopilar_reporte_completo(tmp_path)

    assert "README" in reporte
    assert "Mi maquina" in reporte
    assert "Attack Surface" not in reporte


def test_reporte_vacio_sin_ningun_archivo(tmp_path):
    reporte = final_assist.recopilar_reporte_completo(tmp_path)
    assert reporte == ""


def test_trunca_archivos_muy_largos(tmp_path):
    (tmp_path / "README.md").write_text("A" * 10000)

    reporte = final_assist.recopilar_reporte_completo(tmp_path)

    assert "truncado" in reporte
    assert len(reporte) < 10000  # confirma que de verdad se truncó, no solo se marcó


def test_construir_prompt_incluye_la_ip_y_el_reporte():
    prompt = final_assist._construir_prompt("contenido de prueba", "10.10.10.28")
    assert "10.10.10.28" in prompt
    assert "contenido de prueba" in prompt
