"""
Fixtures compartilhadas dos testes.

A principal e o bundle STIX sintetico: o bundle real do ATT&CK tem ~50 MB e
exige rede, o que tornaria os testes lentos, frageis e dependentes de estar
online. O sintetico reproduz a estrutura que o mitre_mapper realmente
consome - external_references, kill_chain_phases, intrusion-set e
relationship "uses" - com objetos suficientes para exercitar o codigo.

Ele imita o bundle real tambem nos detalhes que ja causaram bug:

  - Sub-tecnica tem o nome CURTO ("Web Protocols"), sem o da tecnica-pai,
    e a tecnica-pai existe como objeto separado. E assim no STIX de
    verdade, e foi o que fez o nome da sub-tecnica perder contexto no
    relatorio.
  - A tatica de evasao se chama "stealth", como no ATT&CK v19, e nao
    "defense-evasion". Quando o sintetico usava o nome antigo, o mapa da
    Kill Chain parecia correto nos testes e descartava silenciosamente as
    tecnicas de evasao com o bundle real.

Um duble que nao imita a fonte da falsa confianca em vez de cobertura.
"""

from __future__ import annotations

import json
import os

import pytest

# O Qt precisa saber que nao ha tela ANTES de ser importado. Definir aqui,
# no conftest, faz valer para a suite inteira: sem isso os testes da
# interface abririam janelas de verdade, roubando o foco de quem esta
# trabalhando, e quebrariam em CI, que nao tem servidor grafico.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _tecnica(attack_id: str, nome: str, taticas: list[str], stix_id: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": nome,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": t} for t in taticas
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
            }
        ],
    }


def _grupo(attack_id: str, nome: str, aliases: list[str], stix_id: str) -> dict:
    return {
        "type": "intrusion-set",
        "id": stix_id,
        "name": nome,
        "aliases": aliases,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": f"https://attack.mitre.org/groups/{attack_id}/",
            }
        ],
    }


def _usa(origem: str, alvo: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{origem[-4:]}-{alvo[-4:]}",
        "relationship_type": "uses",
        "source_ref": origem,
        "target_ref": alvo,
    }


# IDs STIX estaveis, para as relacoes poderem referencia-los.
AP_T1055 = "attack-pattern--0001"
AP_T1071 = "attack-pattern--0007"  # pai de T1071.001
AP_T1071_001 = "attack-pattern--0002"
AP_T1486 = "attack-pattern--0003"
AP_T1547_001 = "attack-pattern--0004"
AP_T1057 = "attack-pattern--0005"
AP_DESCONTINUADA = "attack-pattern--0006"

IS_G0016 = "intrusion-set--0016"  # APT29
IS_G0046 = "intrusion-set--0046"  # FIN7
IS_G0032 = "intrusion-set--0032"  # Lazarus


@pytest.fixture(scope="session")
def bundle_stix() -> dict:
    """Bundle STIX sintetico, com a mesma forma do bundle real."""
    return {
        "type": "bundle",
        "id": "bundle--teste",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--teste",
                "name": "Enterprise ATT&CK (sintetico)",
                "x_mitre_version": "99.0",
            },
            _tecnica("T1055", "Process Injection",
                     ["stealth", "privilege-escalation"], AP_T1055),
            # A tecnica-pai existe como objeto proprio, e a sub-tecnica traz
            # apenas o nome curto - exatamente como no bundle real.
            _tecnica("T1071", "Application Layer Protocol",
                     ["command-and-control"], AP_T1071),
            _tecnica("T1071.001", "Web Protocols",
                     ["command-and-control"], AP_T1071_001),
            _tecnica("T1486", "Data Encrypted for Impact", ["impact"], AP_T1486),
            _tecnica("T1547.001", "Registry Run Keys / Startup Folder",
                     ["persistence", "privilege-escalation"], AP_T1547_001),
            _tecnica("T1057", "Process Discovery", ["discovery"], AP_T1057),
            # Tecnica marcada como descontinuada, para exercitar esse caminho.
            {
                **_tecnica("T1099", "Timestomp", ["stealth"], AP_DESCONTINUADA),
                "x_mitre_deprecated": True,
            },
            _grupo("G0016", "APT29", ["APT29", "Cozy Bear", "Nobelium"], IS_G0016),
            _grupo("G0046", "FIN7", ["FIN7", "Carbanak"], IS_G0046),
            _grupo("G0032", "Lazarus Group", ["Lazarus Group", "HIDDEN COBRA"], IS_G0032),
            # APT29: injecao + C2 web + persistencia por Run key
            _usa(IS_G0016, AP_T1055),
            _usa(IS_G0016, AP_T1071_001),
            _usa(IS_G0016, AP_T1547_001),
            # FIN7: injecao + C2 web
            _usa(IS_G0046, AP_T1055),
            _usa(IS_G0046, AP_T1071_001),
            # Lazarus: so ransomware
            _usa(IS_G0032, AP_T1486),
        ],
    }


@pytest.fixture
def cache_stix(tmp_path, bundle_stix):
    """Grava o bundle sintetico em disco, como se fosse o cache real."""
    caminho = tmp_path / "mitre_cache" / "enterprise-attack.json"
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(json.dumps(bundle_stix), encoding="utf-8")
    return caminho


@pytest.fixture
def attack(cache_stix):
    """Instancia de MitreAttack carregada do bundle sintetico, sem rede."""
    from core.mitre_mapper import MitreAttack

    return MitreAttack(cache_stix).carregar(baixar_se_faltar=False)
