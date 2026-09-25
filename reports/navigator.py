"""
Layer do ATT&CK Navigator.

Um arquivo JSON que o Navigator (mitre-attack.github.io/attack-navigator)
abre direto: as tecnicas observadas aparecem pintadas na matriz, com o
procedimento e a evidencia no comentario de cada uma. E o jeito padrao de
mostrar a cobertura de um incidente numa reuniao ou de somar varios
incidentes numa matriz so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERSAO_DA_LAYER = "4.5"
VERSAO_DO_NAVIGATOR = "5.1.0"
COR = "#8b7cf6"


def layer(nome: str, ttps: list[Any], descricao: str = "", versao_attack: str = "") -> dict:
    """ttps: itens com tecnica, tatica, procedimento e evidencias (core.diamante.TTP)."""
    tecnicas: dict[tuple[str, str], dict] = {}
    for t in ttps:
        tatica = t.tatica if t.tatica != "stealth" else "defense-evasion"
        comentario = t.procedimento
        if t.evidencias:
            comentario += " Evidência: " + " | ".join(t.evidencias[:3])
        tecnicas[(t.tecnica, tatica)] = {
            "techniqueID": t.tecnica,
            "tactic": tatica,
            "score": 1,
            "color": COR,
            "comment": comentario[:900],
            "enabled": True,
            "showSubtechniques": True,
        }
    versoes = {"navigator": VERSAO_DO_NAVIGATOR, "layer": VERSAO_DA_LAYER}
    if versao_attack:
        # Sem a versao, o Navigator usa a mais recente; com uma versao errada, recusa.
        versoes["attack"] = versao_attack
    return {
        "name": nome[:80],
        "versions": versoes,
        "domain": "enterprise-attack",
        "description": descricao[:900] or "Gerada pelo Nut-Shell Mapper",
        "sorting": 0,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": list(tecnicas.values()),
        "gradient": {"colors": ["#ffffff", COR], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "observada nesta análise", "color": COR}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def salvar_layer(nome: str, ttps: list[Any], destino: str | Path, descricao: str = "") -> Path:
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(layer(nome, ttps, descricao), ensure_ascii=False, indent=2), encoding="utf-8")
    return destino
