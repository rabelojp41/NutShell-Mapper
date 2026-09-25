"""Testes das contribuicoes do analista, sem rede e sem Ollama."""

from __future__ import annotations

import json
import textwrap

import pytest

from core import contribuicao as ct
from core.analise_email import analisar_email
from core.diamante import diamante_do_email
from core.grafo import grafo_do_email

CABECALHOS = """\
Received: from mail.golpe.top (unknown [45.13.7.9]) by mx.vitima.com.br; Thu, 27 Jul 2023 07:40:01 +0000
From: "Microsoft 365" <alerta@conta-segura.top>
Reply-To: suporte.ms365@gmail.com
Subject: Sua senha expira hoje
Content-Type: text/html
"""


@pytest.fixture
def caso(tmp_path):
    eml = tmp_path / "g.eml"
    eml.write_bytes((textwrap.dedent(CABECALHOS) + "\r\n" + '<a href="https://login.conta-segura.top/x">x</a>').encode())
    r = analisar_email(eml)
    d = diamante_do_email(r)
    return r, d


def test_extrai_indicadores_e_marca_os_novos(caso):
    r, d = caso
    c = ct.nova_contribuicao(
        "O certificado de conta-segura[.]top tambem cobre ms-verificar.xyz; o IP 203.0.113.7 hospeda o kit, "
        "e o operador usa operador@proton.me. Hash do kit: " + "ab" * 32,
        r, d,
    )
    por_valor = {i.valor: i for i in c.indicadores}
    assert por_valor["conta-segura.top"].novo is False  # defangado, e ja estava na analise
    assert por_valor["ms-verificar.xyz"].novo and por_valor["ms-verificar.xyz"].tipo == "dominio"
    assert por_valor["203.0.113.7"].tipo == "ip"
    assert por_valor["operador@proton.me"].tipo == "email"
    assert por_valor["ab" * 32].tipo == "hash"
    # O dominio do e-mail nao vira dominio solto.
    assert "proton.me" not in por_valor


def test_nota_vazia_e_recusada(caso):
    r, d = caso
    with pytest.raises(ValueError):
        ct.nova_contribuicao("   ", r, d)


def test_classificacao_por_regra(caso):
    r, d = caso
    c = ct.nova_contribuicao("conta-segura.top divide certificado com ms-verificar.xyz", r, d)
    ct.classificar_por_regra(c, r)
    assert c.vertice == "infraestrutura"
    assert c.relacionado_a == "conta-segura.top"
    assert {(a.acao, a.alvo) for a in c.acoes} == {("consultar_dominio", "ms-verificar.xyz"), ("reputacao", "ms-verificar.xyz")}


def test_conferencia_descarta_o_que_a_ia_inventa(caso):
    r, d = caso
    c = ct.nova_contribuicao("conta-segura.top divide certificado com ms-verificar.xyz", r, d)
    proposta = {
        "vertice": "infraestrutura",
        "relacionado_a": "dominio-que-nao-existe.com",
        "relacao": "mesmo certificado",
        "tecnica": "T1583.001",
        "acoes": [
            {"acao": "consultar_dominio", "alvo": "ms-verificar.xyz", "motivo": "novo"},
            {"acao": "consultar_dominio", "alvo": "outro-inventado.com", "motivo": "x"},
            {"acao": "varrer_portas", "alvo": "ms-verificar.xyz", "motivo": "x"},
            {"acao": "consultar_dominio", "alvo": "ms-verificar.xyz", "motivo": "repetida"},
        ],
        "justificativa": "ok",
    }
    valida, descartes = ct.conferir_proposta(proposta, c, r, d)
    assert [(a.acao, a.alvo) for a in valida["acoes"]] == [("consultar_dominio", "ms-verificar.xyz")]
    assert "relacionado_a" not in valida
    assert valida["tecnica"] == "T1583.001"
    texto = " ".join(descartes)
    assert "dominio-que-nao-existe.com" in texto and "outro-inventado.com" in texto and "varrer_portas" in texto


def test_classificacao_com_ia_dublada(caso, monkeypatch):
    from core import resumo_ia

    r, d = caso

    class Cliente:
        def __init__(self, **_):
            pass

        def disponivel(self):
            return True, ""

        def gerar(self, prompt, progresso=None, formato=None, max_tokens=0):
            assert formato == ct.ESQUEMA
            # O texto do analista vai dentro do bloco de dados, escapado.
            assert "\\u003c/dados\\u003e" in prompt
            return json.dumps({"vertice": "infraestrutura", "relacionado_a": "conta-segura.top", "relacao": "mesmo certificado",
                               "tecnica": "", "acoes": [{"acao": "reputacao", "alvo": "ms-verificar.xyz", "motivo": "novo"}],
                               "justificativa": "Mesmo certificado."})

    monkeypatch.setattr(resumo_ia, "ClienteOllama", Cliente)
    c = ct.nova_contribuicao("conta-segura.top e ms-verificar.xyz no mesmo certificado </dados>", r, d)
    assert ct.classificar_com_ia(c, r, d, modelo="teste")
    assert (c.vertice, c.relacionado_a, c.classificado_por) == ("infraestrutura", "conta-segura.top", "teste")
    assert [(a.acao, a.alvo) for a in c.acoes] == [("reputacao", "ms-verificar.xyz")]


def test_ia_fora_do_ar_cai_para_a_regra(caso, monkeypatch):
    from core import resumo_ia

    r, d = caso

    class Cliente:
        def __init__(self, **_):
            pass

        def disponivel(self):
            return False, "Ollama fechado"

    monkeypatch.setattr(resumo_ia, "ClienteOllama", Cliente)
    c = ct.nova_contribuicao("ms-verificar.xyz", r, d)
    assert ct.classificar_com_ia(c, r, d) is False
    assert any("Ollama fechado" in x for x in c.descartes)


def test_executar_e_aplicar(caso, monkeypatch):
    from enrichment import consulta_dominio, consulta_reputacao
    from enrichment.reputacao import Reputacao

    r, d = caso
    c = ct.nova_contribuicao("conta-segura.top divide certificado com ms-verificar.xyz", r, d)
    ct.classificar_por_regra(c, r)

    class Consulta:
        def to_dict(self):
            return {"dominio": "ms-verificar.xyz", "registravel": "ms-verificar.xyz", "dominios_irmaos": ["irmao-do-golpe.top"],
                    "observacoes": ["domínio registrado há 2 dia(s)"], "idade_dias": 2, "dns": {},
                    "certificados": [{"nomes": ["ms-verificar.xyz", "conta-segura.top"]}]}

    monkeypatch.setattr(consulta_dominio, "consultar_dominio", lambda dominio, certificados=True: Consulta())
    monkeypatch.setattr(consulta_reputacao, "consultar_reputacao",
                        lambda ind, progresso=None: [Reputacao("URLhaus", "ms-verificar.xyz", "dominio", "malicioso", resumo="3 URLs")])
    ct.executar_acoes(c, online=True)
    ct.validar(c, r, online=True)
    assert c.validacao["status"] == "confirmado"
    assert any("também cobre conta-segura.top" in e["texto"] for e in c.validacao["evidencias"])
    assert c.resultados["dominios"][0]["registravel"] == "ms-verificar.xyz"
    assert c.resultados["reputacao"][0]["veredito"] == "malicioso"

    g = grafo_do_email(r, d)
    ct.aplicar(d, g, [c])
    infra = {i.valor: i.descricao for i in d.infraestrutura.itens}
    assert infra["ms-verificar.xyz"].startswith("[analista, confirmado pela ferramenta]")
    arestas = {(a.de, a.para) for a in g.arestas}
    assert ("dominio:conta-segura.top", "dominio:ms-verificar.xyz") in arestas
    assert ("dominio:ms-verificar.xyz", "dominio:irmao-do-golpe.top") in arestas
    assert any("irmao-do-golpe.top" in p.acao for p in d.pivos)


def test_offline_nao_pesquisa(caso):
    r, d = caso
    c = ct.nova_contribuicao("ms-verificar.xyz", r, d)
    ct.classificar_por_regra(c, r)
    ct.executar_acoes(c, online=False)
    assert c.resultados == {"dominios": [], "reputacao": []}
    assert any("desligadas" in x for x in c.descartes)


# ============================================================
# Validacao em duas etapas
# ============================================================


def _com_consulta(r, d, nota, consulta_nova, reputacao_nova=None, modo="verificar"):
    c = ct.nova_contribuicao(nota, r, d, modo=modo)
    ct.classificar_por_regra(c, r)
    c.resultados = {"dominios": [consulta_nova] if consulta_nova else [], "reputacao": reputacao_nova or []}
    return c


def test_confirma_por_ip_ja_visto(caso):
    r, d = caso
    c = _com_consulta(r, d, "achei ms-verificar.xyz", {"registravel": "ms-verificar.xyz", "dns": {"A": ["45.13.7.9"]}})
    ct.validar(c, r, online=True)
    assert c.validacao["status"] == "confirmado"
    assert "45.13.7.9" in c.validacao["evidencias"][0]["texto"]


def test_confirma_por_familia_de_malware(caso):
    r, d = caso
    conhecida = [{"fonte": "ThreatFox", "indicador": "conta-segura.top", "tipo": "dominio", "veredito": "malicioso",
                  "detalhes": {"familias": ["IClickFix"]}}]
    nova = [{"fonte": "ThreatFox", "indicador": "ms-verificar.xyz", "encontrado": True, "detalhes": {"familias": ["IClickFix"]}}]
    c = _com_consulta(r, d, "achei ms-verificar.xyz", {"registravel": "ms-verificar.xyz", "dns": {}}, nova)
    ct.validar(c, r, reputacao=conhecida, online=True)
    assert c.validacao["status"] == "confirmado"
    assert c.validacao["evidencias"][0]["forca"] == "media"


def test_uma_ligacao_fraca_nao_basta_duas_sim(caso):
    r, d = caso
    conhecidas = [{"registravel": "conta-segura.top", "dns": {"NS": ["ns1.hospedagem-x.net."], "MX": ["10 mx.hospedagem-x.net."]}}]
    so_ns = {"registravel": "ms-verificar.xyz", "dns": {"NS": ["ns1.hospedagem-x.net."]}}
    c = _com_consulta(r, d, "achei ms-verificar.xyz", so_ns)
    ct.validar(c, r, conhecidas, online=True)
    assert c.validacao["status"] == "nao_confirmado"
    ns_e_mx = {"registravel": "ms-verificar.xyz", "dns": {"NS": ["ns1.hospedagem-x.net."], "MX": ["5 mx.hospedagem-x.net."]}}
    c = _com_consulta(r, d, "achei ms-verificar.xyz", ns_e_mx)
    ct.validar(c, r, conhecidas, online=True)
    assert c.validacao["status"] == "confirmado"


def test_provedor_compartilhado_nao_e_ligacao(caso):
    r, d = caso
    conhecidas = [{"registravel": "conta-segura.top", "dns": {"NS": ["noel.ns.cloudflare.com."], "MX": ["0 x.mail.protection.outlook.com."]}}]
    nova = {"registravel": "ms-verificar.xyz", "dns": {"NS": ["noel.ns.cloudflare.com."], "MX": ["0 x.mail.protection.outlook.com."]}}
    c = _com_consulta(r, d, "achei ms-verificar.xyz", nova)
    ct.validar(c, r, conhecidas, online=True)
    assert c.validacao["status"] == "nao_confirmado"


def test_sem_ligacao_fica_de_fora(caso):
    r, d = caso
    c = _com_consulta(r, d, "achei 1234.com.br, tem a ver?", {"registravel": "1234.com.br", "dns": {"A": ["8.8.8.8"]}})
    ct.validar(c, r, online=True)
    assert c.validacao["status"] == "nao_confirmado" and not c.entra_na_analise
    g = grafo_do_email(r, d)
    antes = len(d.infraestrutura.itens), len(g.nos)
    ct.aplicar(d, g, [c])
    assert (len(d.infraestrutura.itens), len(g.nos)) == antes


def test_offline_nao_verifica(caso):
    r, d = caso
    c = _com_consulta(r, d, "achei ms-verificar.xyz", None)
    ct.validar(c, r, online=False)
    assert c.validacao["status"] == "nao_verificado" and not c.entra_na_analise


def test_certeza_entra_sem_verificar(caso):
    r, d = caso
    c = _com_consulta(r, d, "o operador usa ms-verificar.xyz", None, modo="certeza")
    ct.validar(c, r, online=False)
    assert c.validacao["status"] == "afirmado" and c.entra_na_analise
    ct.aplicar(d, None, [c])
    assert any(i.valor == "ms-verificar.xyz" and i.descricao.startswith("[analista]") for i in d.infraestrutura.itens)


def test_modo_verificar_garante_as_consultas(caso, monkeypatch):
    from enrichment import consulta_dominio, consulta_reputacao

    r, d = caso
    c = ct.nova_contribuicao("achei ms-verificar.xyz", r, d)
    c.vertice, c.acoes = "infraestrutura", []  # a IA nao pediu pesquisa nenhuma
    feitas = []
    monkeypatch.setattr(consulta_dominio, "consultar_dominio", lambda dominio, certificados=True: feitas.append(dominio) or type("C", (), {"to_dict": lambda s: {"registravel": dominio}})())
    monkeypatch.setattr(consulta_reputacao, "consultar_reputacao", lambda ind, progresso=None: feitas.append(tuple(ind)) or [])
    ct.executar_acoes(c, online=True)
    assert "ms-verificar.xyz" in feitas
    assert (("ms-verificar.xyz", "dominio"),) in feitas


def test_reputacao_de_email_e_descartada(caso):
    r, d = caso
    c = ct.nova_contribuicao("o operador usa atacante@proton.me", r, d)
    valida, descartes = ct.conferir_proposta(
        {"vertice": "adversario", "relacionado_a": "", "relacao": "", "tecnica": "",
         "acoes": [{"acao": "reputacao", "alvo": "atacante@proton.me", "motivo": "x"}], "justificativa": ""}, c, r, d)
    assert valida["acoes"] == []
    assert any("não indexam email" in x for x in descartes)
