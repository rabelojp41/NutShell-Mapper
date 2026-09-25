"""Testes das fontes de reputacao e do orquestrador, sem rede."""

from __future__ import annotations

import textwrap

import pytest

from enrichment.abusech_client import ThreatFoxClient, URLhausClient
from enrichment.base import RespostaEnriquecimento
from enrichment.consulta_reputacao import Fonte, consultar_reputacao, indicadores_do_email
from enrichment.reputacao import Reputacao


def _respondendo(cliente, dados=None, erro=""):
    pedidos = []

    def falso(caminho, **kw):
        pedidos.append((caminho, kw))
        return RespostaEnriquecimento(consultado=not erro, encontrado=bool(dados), dados=dados or {}, erro=erro)

    cliente._requisitar = falso
    return pedidos


# ============================================================
# URLhaus
# ============================================================


def test_urlhaus_host_com_registro():
    c = URLhausClient("chave")
    pedidos = _respondendo(c, {
        "query_status": "ok", "url_count": "3", "firstseen": "2026-09-01 10:00:00 UTC",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/1.2.3.4/",
        "urls": [
            {"url": "http://1.2.3.4/a", "url_status": "online", "threat": "malware_download", "tags": ["Mozi", "elf"]},
            {"url": "http://1.2.3.4/b", "url_status": "offline", "threat": "malware_download", "tags": ["Mozi"]},
        ],
    })
    r = c.consultar("1.2.3.4")
    assert pedidos[0][0] == "/host/" and pedidos[0][1]["formulario"] == {"host": "1.2.3.4"}
    assert (r.veredito, r.tipo) == ("malicioso", "ip")
    assert "3 URL(s)" in r.resumo and "1 ainda no ar" in r.resumo
    assert r.tags == ["Mozi", "elf"]
    assert r.referencia.startswith("https://urlhaus.abuse.ch/")


def test_urlhaus_url_e_sem_registro():
    c = URLhausClient("chave")
    pedidos = _respondendo(c, {"query_status": "no_results"})
    r = c.consultar("https://golpe.top/x")
    assert pedidos[0][0] == "/url/"
    assert r.veredito == "sem_registro" and not r.encontrado


def test_falha_de_rede_nao_e_sem_registro():
    c = URLhausClient("chave")
    _respondendo(c, erro="falha de rede: Timeout")
    r = c.consultar("golpe.top")
    assert r.veredito == "erro" and "Timeout" in r.erro


# ============================================================
# ThreatFox
# ============================================================


def test_threatfox_encontrado_manda_json():
    c = ThreatFoxClient("chave")
    pedidos = _respondendo(c, {"query_status": "ok", "data": [
        {"id": "9", "ioc": "golpe.top", "malware_printable": "IClickFix", "threat_type": "payload_delivery",
         "threat_type_desc": "entrega de payload", "confidence_level": 100, "first_seen": "2026-09-25 14:46:08 UTC",
         "tags": ["ClickFix"], "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/js.iclickfix"},
    ]})
    r = c.consultar("golpe.top")
    assert pedidos[0][1]["corpo_json"] == {"query": "search_ioc", "search_term": "golpe.top", "exact_match": True}
    assert r.veredito == "malicioso"
    assert r.detalhes["familias"] == ["IClickFix"]
    assert "confiança até 100%" in r.resumo
    assert r.referencia == "https://threatfox.abuse.ch/ioc/9/"


def test_threatfox_confianca_baixa_e_suspeito_e_hash_usa_search_hash():
    c = ThreatFoxClient("chave")
    pedidos = _respondendo(c, {"query_status": "ok", "data": [{"id": "1", "confidence_level": 25, "threat_type": "botnet_cc"}]})
    r = c.consultar("a" * 64)
    assert pedidos[0][1]["corpo_json"] == {"query": "search_hash", "hash": "a" * 64}
    assert r.veredito == "suspeito"


def test_threatfox_sem_registro():
    c = ThreatFoxClient("chave")
    _respondendo(c, {"query_status": "no_result", "data": "Your search did not yield any results"})
    assert c.consultar("x.top").veredito == "sem_registro"


# ============================================================
# Orquestrador
# ============================================================


class _Falso:
    def __init__(self, nome, veredito="malicioso", explode=False):
        self.nome, self.veredito, self.explode, self.vistos = nome, veredito, explode, []

    def consultar(self, valor):
        self.vistos.append(valor)
        if self.explode:
            raise RuntimeError("quebrou")
        return Reputacao(self.nome, valor, "dominio", self.veredito, resumo="x")


def test_orquestrador_so_pergunta_o_que_a_fonte_entende():
    so_ip = _Falso("SoIP")
    tudo = _Falso("Tudo", veredito="sem_registro")
    quebra = _Falso("Quebra", explode=True)
    sem_chave = Fonte("SemChave", frozenset({"ip"}), lambda: None)
    fontes = [Fonte("SoIP", frozenset({"ip"}), lambda: so_ip), Fonte("Tudo", frozenset({"ip", "dominio"}), lambda: tudo),
              Fonte("Quebra", frozenset({"dominio"}), lambda: quebra), sem_chave]
    r = consultar_reputacao([("1.2.3.4", "ip"), ("golpe.top", "dominio")], fontes)
    assert so_ip.vistos == ["1.2.3.4"]
    assert tudo.vistos == ["1.2.3.4", "golpe.top"]
    # Fonte que quebra vira "erro", e as outras seguem.
    assert any(x.fonte == "Quebra" and x.veredito == "erro" for x in r)
    # Encontrados primeiro.
    assert r[0].veredito == "malicioso"
    assert not any(x.fonte == "SemChave" for x in r)


def test_sem_nenhuma_fonte_devolve_vazio():
    assert consultar_reputacao([("1.2.3.4", "ip")], [Fonte("X", frozenset({"ip"}), lambda: None)]) == []


def test_indicadores_do_email(tmp_path):
    from core.analise_email import analisar_email
    from core.diamante import diamante_do_email

    eml = tmp_path / "g.eml"
    eml.write_bytes((textwrap.dedent("""\
        Received: from mail.golpe.top (unknown [45.13.7.9]) by mx.vitima.com.br; Thu, 27 Jul 2023 07:40:01 +0000
        From: X <alerta@conta-segura.top>
        Reply-To: golpista@gmail.com
        Subject: s
        Content-Type: text/html
        """) + "\r\n" + '<a href="https://login.golpe.top/l">x</a>').encode())
    r = analisar_email(eml)
    ind = indicadores_do_email(r, diamante_do_email(r))
    assert ("45.13.7.9", "ip") in ind
    assert ("conta-segura.top", "dominio") in ind
    assert ("https://login.golpe.top/l", "url") in ind
    # Webmail e endereco de e-mail nao vao para fonte de reputacao.
    assert not any("gmail" in v for v, _ in ind)


def test_ia_aceita_familia_vinda_da_reputacao(tmp_path):
    from core.analise_email import analisar_email
    from core.ia_email import conferir

    eml = tmp_path / "g.eml"
    eml.write_bytes(b"From: X <a@golpe.top>\r\nSubject: s\r\n\r\nx")
    r = analisar_email(eml)
    texto = "O dominio golpe.top aparece no ThreatFox ligado ao Emotet."
    assert any(i.tipo == "familia" for i in conferir(texto, r))
    rep = [Reputacao("ThreatFox", "golpe.top", "dominio", "malicioso", detalhes={"familias": ["Emotet"]})]
    assert not any(i.tipo == "familia" for i in conferir(texto, r, reputacao=rep))


def test_diamante_mostra_a_reputacao(tmp_path):
    from core.analise_email import analisar_email
    from core.diamante import diamante_do_email

    eml = tmp_path / "g.eml"
    eml.write_bytes(b"Received: from x (unknown [45.13.7.9]) by mx.v.com; Thu, 27 Jul 2023 07:40:01 +0000\r\n"
                    b"From: X <a@golpe.top>\r\nSubject: s\r\n\r\nx")
    r = analisar_email(eml)
    rep = [Reputacao("URLhaus", "45.13.7.9", "ip", "malicioso"),
           Reputacao("ThreatFox", "golpe.top", "dominio", "malicioso", detalhes={"familias": ["IClickFix"]})]
    d = diamante_do_email(r, reputacao=rep)
    infra = {i.valor: i.descricao for i in d.infraestrutura.itens}
    assert "URLhaus: malicioso" in infra["45.13.7.9"]
    assert "ThreatFox: malicioso" in infra["golpe.top"]
    assert any("IClickFix" in p.acao for p in d.pivos)


# ============================================================
# AbuseIPDB
# ============================================================


def _abuseipdb(dados):
    from enrichment.abuseipdb_client import AbuseIPDBClient

    c = AbuseIPDBClient("chave")
    pedidos = _respondendo(c, {"data": dados} if dados is not None else None)
    return c, pedidos


def test_abuseipdb_malicioso_com_categorias():
    c, pedidos = _abuseipdb({
        "abuseConfidenceScore": 100, "totalReports": 505, "numDistinctUsers": 154, "countryName": "Germany",
        "countryCode": "DE", "isp": "Tor Exit", "usageType": "Data Center/Web Hosting/Transit", "isTor": True,
        "reports": [{"categories": [18, 22]}, {"categories": [18]}, {"categories": [7]}],
    })
    r = c.consultar("185.220.101.44")
    assert pedidos[0][0] == "/check"
    assert pedidos[0][1]["parametros"]["ipAddress"] == "185.220.101.44"
    assert r.veredito == "malicioso"
    assert r.tags[0] == "Brute-Force"
    assert "nó de saída Tor" in r.resumo and "data center" in r.resumo
    assert r.referencia == "https://www.abuseipdb.com/check/185.220.101.44"


def test_abuseipdb_permitido_nao_e_suspeito():
    c, _ = _abuseipdb({"abuseConfidenceScore": 0, "totalReports": 348, "numDistinctUsers": 147, "isWhitelisted": True,
                       "countryName": "United States", "isp": "Google LLC", "usageType": "Content Delivery Network"})
    r = c.consultar("8.8.8.8")
    assert r.veredito == "sem_registro"
    assert "lista de permissões" in r.resumo


def test_abuseipdb_pontuacao_media_e_sem_relato():
    c, _ = _abuseipdb({"abuseConfidenceScore": 40, "totalReports": 3, "numDistinctUsers": 2, "isp": "X"})
    assert c.consultar("45.13.7.9").veredito == "suspeito"
    c, _ = _abuseipdb({"abuseConfidenceScore": 0, "totalReports": 0, "lastReportedAt": "2023-12-16T02:11:53+00:00",
                       "countryName": "Germany", "isp": "GHOSTnet GmbH", "usageType": "Data Center/Web Hosting/Transit"})
    r = c.consultar("89.144.9.87")
    assert r.veredito == "sem_registro"
    assert "último em 2023-12-16" in r.resumo and "GHOSTnet" in r.resumo


def test_abuseipdb_so_consulta_ip_publico():
    c, pedidos = _abuseipdb({})
    assert c.consultar("golpe.top").veredito == "erro"
    assert c.consultar("10.0.0.5").veredito == "sem_registro"
    assert pedidos == []


def test_diamante_mostra_o_provedor_da_origem(tmp_path):
    from core.analise_email import analisar_email
    from core.diamante import diamante_do_email

    eml = tmp_path / "g.eml"
    eml.write_bytes(b"Received: from x (unknown [89.144.9.87]) by mx.v.com; Thu, 27 Jul 2023 07:40:01 +0000\r\n"
                    b"From: X <a@golpe.top>\r\nSubject: s\r\n\r\nx")
    r = analisar_email(eml)
    rep = [Reputacao("AbuseIPDB", "89.144.9.87", "ip", "sem_registro", detalhes={"provedor": "GHOSTnet GmbH", "pais": "DE"})]
    d = diamante_do_email(r, reputacao=rep)
    origem = next(i for i in d.infraestrutura.itens if i.valor == "89.144.9.87")
    assert "GHOSTnet GmbH (DE)" in origem.descricao
