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

import gc
import json
import os
import sys

import pytest

# O Qt precisa saber que nao ha tela ANTES de ser importado. Definir aqui,
# no conftest, faz valer para a suite inteira: sem isso os testes da
# interface abririam janelas de verdade, roubando o foco de quem esta
# trabalhando, e quebrariam em CI, que nao tem servidor grafico.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# O QtWebEngine, usado pela interface web, exige esta configuracao ANTES de
# existir qualquer QApplication - e o test_gui.py cria a sua primeiro. Sem
# isto, os testes da interface web dependeriam da ordem de execucao.
try:
    from PySide6.QtCore import QCoreApplication, Qt

    QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    import PySide6.QtWebEngineWidgets  # noqa: F401
except ImportError:
    pass

# Desliga o coletor ciclico do Python para a suite inteira. Precisa vir
# antes de qualquer import pesado (mesma razao do QT_QPA_PLATFORM acima).
#
# A suite combina varias extensoes nativas no mesmo processo - pefile,
# yara-python, PySide6/Qt, pyzipper - e em algum ponto dessa combinacao
# memoria fica corrompida (a causa exata nao foi isolada). O sintoma e um
# "Windows fatal exception: access violation" que aparece SEMPRE dentro de
# uma coleta de lixo, mas em locais diferentes a cada execucao: dentro do
# gc.collect() explicito que o pefile roda ao fechar um arquivo, dentro de
# uma coleta automatica disparada por import de modulo, dentro de uma
# chamada trivial de Qt. O padrao mostra que o coletor ciclico e o
# detonador, nao a causa - ele so acontece de ser o primeiro a tocar a
# memoria corrompida, onde quer que a colheita caia.
#
# Confirmado experimentalmente: com o coletor desligado, a mesma suite que
# crashava de forma reproduzivel passa integralmente, repetidas vezes.
#
# Isto e seguro para um processo de vida curta como um teste, o CLI ou uma
# sessao da GUI: a contagem de referencia do CPython continua liberando a
# esmagadora maioria dos objetos normalmente; o que fica sem coletar e
# apenas ciclo de referencia genuino, que este projeto praticamente nao
# cria (dataclasses e Qt QObject com parent nao entram nessa categoria - o
# Qt gerencia a arvore de QObject pelo proprio C++, nao pelo ciclo do
# Python). O custo e um vazamento teorico de ciclo, que perde para o custo
# de um crash aleatorio.
gc.disable()


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


def pytest_sessionfinish(session, exitstatus):
    """
    Sai do processo direto, pulando a finalizacao normal do interpretador.

    Residual da mesma corrupcao de heap documentada acima: com o coletor
    ciclico desligado, todos os testes passam de forma reproduzivel, mas
    centenas de objeto nativo (pefile, yara, QWidget) acumulados num
    processo so fazem a limpeza do CPython no `Py_FinalizeEx` - que roda
    uma colheita final INDEPENDENTE de gc.disable() - tropecar na mesma
    memoria corrompida. O sintoma e um "access violation" que so aparece
    DEPOIS que a barra de progresso do pytest ja chegou a 100%: os testes
    em si passaram, e o que crasha e a limpeza.

    Isto nao muda nenhum resultado de teste - eles ja foram todos
    reportados antes deste hook rodar. `os._exit()` encerra o processo
    imediatamente, sem rodar atexit, sem gc, sem Py_Finalize, e por isso
    sem tocar a memoria que causaria o crash. Sem isso, um crash na
    finalizacao devolveria um exit code de falha de segmentacao e faria o
    CI reportar vermelho apesar de toda a suite ter passado.
    """
    sys.stdout.flush()
    sys.stderr.flush()

    if sys.platform == "win32":
        # No Windows, os._exit ainda passa pelo ExitProcess, que avisa cada
        # DLL carregada de que o processo acabou (DLL_PROCESS_DETACH). Com
        # o QtWebEngine na suite, esse aviso as vezes pega o Chromium com
        # threads ainda vivas e termina em "access violation" - exit 139
        # DEPOIS de todos os testes passarem, de forma intermitente. No CI
        # isso seria job vermelho aleatorio. TerminateProcess encerra sem
        # avisar ninguem e preserva o codigo de saida. O relatorio JUnit ja
        # foi gravado neste ponto: o plugin dele roda antes deste hook.
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess(kernel32.GetCurrentProcess(), int(exitstatus))

    os._exit(exitstatus)


@pytest.fixture(autouse=True)
def _sem_rede_por_acidente(monkeypatch):
    """
    Nenhum teste alcanca servico externo sem pedir explicitamente.

    Sem isto, a suite se comportava de um jeito na maquina de quem tem
    `config/.env` com chaves e de outro no CI, que nao tem nenhuma. Nao e
    so inconsistencia de resultado: rodar os testes disparava consulta REAL
    ao VirusTotal com a chave do analista, enviando a terceiros os hashes
    dos artefatos de teste. Numa ferramenta de CTI isso e o oposto do
    prometido - o proprio pipeline so consulta servico externo mediante
    pedido explicito, e a suite que o testa nao podia ser a excecao.

    Foi tambem o que escondeu um bug real: a secao de enriquecimento do
    relatorio sumia quando VirusTotal e Shodan vinham vazios, levando junto
    a ressalva do score CVSS. Com chave configurada o VirusTotal respondia,
    a secao aparecia e o teste passava; sem chave, quebrava. O CI acusou, a
    maquina local nao.

    Quem precisa de um client dubla o seu por cima: monkeypatch aplicado
    dentro do teste vence este, que roda antes.
    """
    from enrichment import (
        malwarebazaar_client,
        shodan_client,
        virustotal_client,
    )

    for modulo in (virustotal_client, shodan_client, malwarebazaar_client):
        monkeypatch.setattr(modulo, "criar", lambda *_a, **_k: None)
