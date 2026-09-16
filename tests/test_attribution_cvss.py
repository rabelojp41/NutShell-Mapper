"""
Testes do group_attribution e do cvss_calculator.

No group_attribution, o que se testa nao e "acertou o grupo" - isso nao e
verificavel - e sim que a pontuacao se comporta corretamente: grupo grande
nao vence por tamanho, tecnica comum nao discrimina, e a ressalva sobre o
resultado nao ser atribuicao esta sempre presente.

No cvss_calculator, o calculo vem da biblioteca oficial, entao os testes se
concentram nos vetores de referencia da propria especificacao e no que o
modulo acrescenta em volta.
"""

from __future__ import annotations

import json

import pytest

from core.cvss_calculator import (
    ErroCVSS,
    Severidade,
    calcular,
    calcular_de_componentes,
    montar_vetor,
    resumir_em_texto as cvss_em_texto,
)
from core.group_attribution import (
    MINIMO_DE_TECNICAS_EM_COMUM,
    ResultadoAtribuicao,
    atribuir,
    resumir_em_texto as atribuicao_em_texto,
)
from core.mitre_mapper import ResultadoMapeamento, TecnicaMapeada
from core.string_extractor import Confianca


def _mapeamento(*ids: str) -> ResultadoMapeamento:
    return ResultadoMapeamento(
        tecnicas=[TecnicaMapeada(i, f"Tecnica {i}", ["execution"]) for i in ids]
    )


def _nomes(resultado: ResultadoAtribuicao) -> list[str]:
    return [c.nome for c in resultado.candidatos]


# ============================================================
# Atribuicao: comportamento basico
# ============================================================


def test_sem_stix_nao_atribui():
    """Sem o bundle nao ha intrusion-set para cruzar."""
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack=None)
    assert resultado.candidatos == []
    assert any("STIX" in a for a in resultado.avisos)


def test_sem_tecnica_nao_atribui(attack):
    resultado = atribuir(ResultadoMapeamento(), attack)
    assert resultado.candidatos == []
    assert any("nenhuma tecnica" in a for a in resultado.avisos)


def test_encontra_grupos_com_sobreposicao(attack):
    """APT29 e FIN7 usam T1055 e T1071.001 no bundle de teste."""
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack)
    assert set(_nomes(resultado)) == {"APT29", "FIN7"}


def test_uma_tecnica_em_comum_nao_basta(attack):
    """Coincidencia de uma tecnica so nao significa nada."""
    resultado = atribuir(_mapeamento("T1486"), attack)
    assert resultado.candidatos == []


def test_minimo_de_tecnicas_e_respeitado(attack):
    resultado = atribuir(_mapeamento("T1486", "T1055", "T1071.001"), attack)
    for c in resultado.candidatos:
        assert len(c.tecnicas_em_comum) >= MINIMO_DE_TECNICAS_EM_COMUM


def test_grupo_com_repertorio_mais_compativel_vence(attack):
    """
    FIN7 tem 2 tecnicas no bundle e ambas foram observadas; APT29 tem 3 e
    so 2 casaram. FIN7 deve pontuar mais: seu repertorio inteiro e
    compativel, o de APT29 nao.
    """
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack)
    assert resultado.melhor.nome == "FIN7"
    assert resultado.melhor.especificidade == 1.0

    apt29 = next(c for c in resultado.candidatos if c.nome == "APT29")
    assert apt29.especificidade < 1.0
    assert resultado.melhor.pontuacao > apt29.pontuacao


def test_cobertura_e_especificidade_sao_distintas(attack):
    resultado = atribuir(_mapeamento("T1055", "T1071.001", "T1547.001"), attack)
    apt29 = next(c for c in resultado.candidatos if c.nome == "APT29")
    # APT29 cobre as 3 observadas e as 3 sao todo o seu repertorio aqui.
    assert apt29.cobertura == pytest.approx(1.0)
    assert apt29.especificidade == pytest.approx(1.0)

    fin7 = next(c for c in resultado.candidatos if c.nome == "FIN7")
    # FIN7 cobre 2 das 3 observadas, mas essas 2 sao todo o seu repertorio.
    assert fin7.cobertura < 1.0
    assert fin7.especificidade == pytest.approx(1.0)


def test_aliases_sao_reportados(attack):
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack)
    apt29 = next(c for c in resultado.candidatos if c.nome == "APT29")
    assert "Cozy Bear" in apt29.aliases


def test_casamento_por_tecnica_pai(attack):
    """
    O ATT&CK documenta APT29 em T1055; a analise identificou T1055.012.
    Ignorar isso perderia sobreposicao real, mas o casamento vale menos.
    """
    resultado = atribuir(_mapeamento("T1055.012", "T1071.001"), attack)
    assert resultado.candidatos

    candidato = resultado.candidatos[0]
    parcial = next(t for t in candidato.tecnicas_em_comum if t.tecnica_id == "T1055.012")
    exato = next(t for t in candidato.tecnicas_em_comum if t.tecnica_id == "T1071.001")
    assert parcial.exato is False
    assert exato.exato is True
    assert parcial.peso < exato.peso


def test_tecnica_rara_pesa_mais_que_comum(attack):
    """
    T1055 e usada por 2 dos 3 grupos; T1547.001 por apenas 1. A mais rara
    discrimina mais e precisa pesar mais.
    """
    resultado = atribuir(_mapeamento("T1055", "T1071.001", "T1547.001"), attack)
    apt29 = next(c for c in resultado.candidatos if c.nome == "APT29")

    pesos = {t.tecnica_id: t.peso for t in apt29.tecnicas_em_comum}
    assert pesos["T1547.001"] > pesos["T1055"]


# ============================================================
# Atribuicao: honestidade do resultado
# ============================================================


def test_confianca_nunca_e_alta(attack):
    """
    Sobreposicao de tecnicas nao sustenta confianca alta, por melhor que
    seja a pontuacao. Isso exigiria evidencia de outra natureza.
    """
    resultado = atribuir(_mapeamento("T1055", "T1071.001", "T1547.001"), attack)
    for c in resultado.candidatos:
        assert c.confianca is not Confianca.ALTA


def test_ressalva_sempre_presente(attack):
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack)
    assert "nao e atribuicao" in resultado.ressalva
    assert "nao e atribuicao" in atribuicao_em_texto(resultado)


def test_base_estreita_gera_aviso(attack):
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack)
    assert any("base estreita" in a for a in resultado.avisos)


def test_tecnica_sem_grupo_e_reportada(attack):
    """T1622 nao esta no bundle de teste: isso precisa aparecer."""
    resultado = atribuir(_mapeamento("T1055", "T1071.001", "T1622"), attack)
    assert "T1622" in resultado.tecnicas_sem_grupo
    assert any("nenhum grupo" in a for a in resultado.avisos)


def test_texto_sem_candidato_e_util(attack):
    texto = atribuicao_em_texto(atribuir(ResultadoMapeamento(), attack))
    assert "Nenhum grupo" in texto


def test_atribuicao_serializavel(attack):
    resultado = atribuir(_mapeamento("T1055", "T1071.001"), attack)
    assert json.dumps(resultado.to_dict(), default=str)


# ============================================================
# CVSS: vetores de referencia
# ============================================================


@pytest.mark.parametrize(
    "vetor,esperado,severidade",
    [
        # CVE-2021-44228 (Log4Shell)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severidade.CRITICA),
        # CVE-2017-0144 (EternalBlue)
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, Severidade.ALTA),
        # Falha local com interacao do usuario.
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, Severidade.ALTA),
        # Impacto apenas de disponibilidade.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, Severidade.ALTA),
        # Sem impacto nenhum.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severidade.NENHUMA),
    ],
)
def test_scores_de_referencia(vetor, esperado, severidade):
    resultado = calcular(vetor)
    assert resultado.score_base == pytest.approx(esperado)
    assert resultado.severidade_base is severidade


def test_faixas_de_severidade():
    assert Severidade.de_score(0.0) is Severidade.NENHUMA
    assert Severidade.de_score(3.9) is Severidade.BAIXA
    assert Severidade.de_score(4.0) is Severidade.MEDIA
    assert Severidade.de_score(6.9) is Severidade.MEDIA
    assert Severidade.de_score(7.0) is Severidade.ALTA
    assert Severidade.de_score(8.9) is Severidade.ALTA
    assert Severidade.de_score(9.0) is Severidade.CRITICA
    assert Severidade.de_score(10.0) is Severidade.CRITICA


def test_vetor_sem_prefixo_de_versao():
    """Fonte publica frequentemente publica so as metricas."""
    com = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    sem = calcular("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert com.score_base == sem.score_base


# ============================================================
# CVSS: os tres scores
# ============================================================


def test_sem_metricas_temporais_nao_inventa_score():
    """
    A biblioteca sempre devolve os tres scores. Reportar o temporal quando
    ele apenas repete o base daria falsa impressao de refinamento.
    """
    resultado = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert resultado.score_temporal is None
    assert resultado.score_ambiental is None
    assert resultado.score_efetivo == resultado.score_base
    assert any("apenas o score base" in a for a in resultado.avisos)


def test_metricas_temporais_reduzem_o_score():
    """Exploit nao comprovado e correcao oficial reduzem a severidade."""
    base = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    temporal = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C")

    assert temporal.score_temporal is not None
    assert temporal.score_temporal < base.score_base
    assert temporal.score_efetivo == temporal.score_temporal


def test_metricas_ambientais_sao_detectadas():
    resultado = calcular(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:L"
    )
    assert resultado.score_ambiental is not None
    assert resultado.score_efetivo == resultado.score_ambiental


# ============================================================
# CVSS: construcao e validacao
# ============================================================


def test_montar_vetor():
    assert montar_vetor("N", "L", "N", "N", "U", "H", "H", "H") == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )


def test_montar_vetor_aceita_minuscula():
    assert montar_vetor("n", "l", "n", "n", "u", "h", "h", "h").endswith("A:H")


def test_montar_vetor_rejeita_valor_invalido():
    with pytest.raises(ErroCVSS, match="Complexidade do Ataque"):
        montar_vetor("N", "X", "N", "N", "U", "H", "H", "H")


def test_mensagem_de_erro_lista_os_aceitos():
    with pytest.raises(ErroCVSS) as erro:
        montar_vetor("Z", "L", "N", "N", "U", "H", "H", "H")
    assert "Rede" in str(erro.value)


def test_calcular_de_componentes():
    resultado = calcular_de_componentes(
        "N", "L", "N", "N", "C", "H", "H", "H", cve="CVE-2021-44228"
    )
    assert resultado.score_base == pytest.approx(10.0)
    assert resultado.cve == "CVE-2021-44228"


@pytest.mark.parametrize(
    "ruim", ["", "   ", "nao e um vetor", "AV:N", "CVSS:3.1/AV:Z/AC:L"]
)
def test_vetor_invalido_levanta_erro(ruim):
    with pytest.raises(ErroCVSS):
        calcular(ruim)


def test_cve_malformada_gera_aviso():
    resultado = calcular(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cve="2021-44228"
    )
    assert any("formato CVE" in a for a in resultado.avisos)


def test_cve_valida_nao_gera_aviso():
    resultado = calcular(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cve="cve-2021-44228"
    )
    assert resultado.cve == "CVE-2021-44228"
    assert not any("formato CVE" in a for a in resultado.avisos)


# ============================================================
# CVSS: leitura do vetor
# ============================================================


def test_metricas_sao_traduzidas():
    resultado = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N")
    por_sigla = {m.sigla: m for m in resultado.metricas}

    assert por_sigla["AV"].valor_legivel == "Rede"
    assert por_sigla["AV"].nome == "Vetor de Ataque"
    assert por_sigla["UI"].valor_legivel == "Necessaria"
    assert por_sigla["S"].valor_legivel == "Alterado"
    assert por_sigla["A"].valor_legivel == "Nenhum"


def test_todas_as_metricas_base_traduzidas():
    resultado = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert len(resultado.metricas) == 8


def test_texto_traz_score_e_metricas():
    texto = cvss_em_texto(
        calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cve="CVE-2021-44228")
    )
    assert "CVE-2021-44228" in texto
    assert "10.0" in texto
    assert "Critica" in texto
    assert "Vetor de Ataque" in texto


def test_cvss_serializavel():
    resultado = calcular("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert json.dumps(resultado.to_dict(), default=str)
