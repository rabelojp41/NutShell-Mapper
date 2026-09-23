"""
Testes de configuracao e dos clients de enriquecimento.

Nenhum teste faz requisicao real: as respostas HTTP sao simuladas. Teste que
depende de API externa e lento, quebra sem rede, consome cota e falha por
motivo alheio ao codigo.

O que mais importa aqui e a nao-divulgacao da chave de API. Um timeout de
rede embute a URL completa na excecao, e o Shodan autentica por query
string - sem sanitizacao, um erro comum vazaria a credencial para o log.
"""

from __future__ import annotations

import json

import pytest
import requests

from config.settings import Configuracoes, _mascarar, carregar
from enrichment.base import ClienteBase, LimitadorDeTaxa, _limpar_segredo
from enrichment.shodan_client import (
    PORTAS_DE_INTERESSE,
    ShodanClient,
    ip_e_consultavel,
)
from enrichment.virustotal_client import VirusTotalClient

CHAVE_FALSA = "chave_de_teste_1234567890abcdef"


# ============================================================
# Simulacao de HTTP
# ============================================================


class RespostaFalsa:
    """Imita requests.Response no que os clients usam."""

    def __init__(self, status=200, payload=None, texto="", cabecalhos=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = texto or json.dumps(self._payload)
        self.headers = cabecalhos or {}

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        if self._payload is None:
            raise ValueError("nao e JSON")
        return self._payload


@pytest.fixture
def sem_espera(monkeypatch):
    """Anula sleeps para os testes nao levarem minutos."""
    monkeypatch.setattr("enrichment.base.time.sleep", lambda _s: None)
    monkeypatch.setattr(
        "enrichment.base.LimitadorDeTaxa.aguardar", lambda self: 0.0
    )


def _responder(cliente, resposta):
    """Substitui o GET da sessao do cliente por uma resposta fixa."""
    chamadas = []

    def falso_get(url, **kwargs):
        chamadas.append((url, kwargs))
        if isinstance(resposta, Exception):
            raise resposta
        return resposta

    cliente.sessao.get = falso_get
    return chamadas


# ============================================================
# Configuracao
# ============================================================


def test_placeholder_conta_como_chave_ausente(monkeypatch, tmp_path):
    """
    Quem copia o .env.example e esquece de preencher precisa receber "chave
    nao configurada", e nao um 401 confuso da API.
    """
    env = tmp_path / ".env"
    env.write_text(
        "VIRUSTOTAL_API_KEY=coloque_sua_chave_aqui\nSHODAN_API_KEY=\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    cfg = carregar(env, sobrescrever_ambiente=True)
    assert cfg.virustotal_api_key == ""
    assert cfg.virustotal_habilitado is False


def test_chave_real_habilita(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text(f"VIRUSTOTAL_API_KEY={CHAVE_FALSA}\n", encoding="utf-8")
    cfg = carregar(env, sobrescrever_ambiente=True)
    assert cfg.virustotal_habilitado is True


def test_enriquecimento_desligado_vence_a_chave(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        f"VIRUSTOTAL_API_KEY={CHAVE_FALSA}\nENABLE_ENRICHMENT=false\n",
        encoding="utf-8",
    )
    cfg = carregar(env, sobrescrever_ambiente=True)
    assert cfg.virustotal_habilitado is False
    assert any("ENABLE_ENRICHMENT" in a for a in cfg.avisos)


def test_env_ausente_nao_quebra(tmp_path):
    """Analise estatica precisa funcionar sem nenhuma configuracao."""
    cfg = carregar(tmp_path / "nao_existe.env")
    assert isinstance(cfg, Configuracoes)
    assert cfg.env_encontrado is False
    assert any("nao encontrado" in a for a in cfg.avisos)


def test_valor_invalido_cai_no_padrao(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text("HTTP_TIMEOUT=nao_e_numero\nLOG_LEVEL=BANANA\n", encoding="utf-8")
    cfg = carregar(env, sobrescrever_ambiente=True)
    assert cfg.http_timeout == 30
    assert cfg.log_level == "INFO"
    assert any("LOG_LEVEL" in a for a in cfg.avisos)


def test_repr_nunca_mostra_a_chave():
    """Despejar a config num log de depuracao e a forma mais comum de vazar."""
    cfg = Configuracoes(virustotal_api_key=CHAVE_FALSA, shodan_api_key=CHAVE_FALSA)
    texto = repr(cfg)
    assert CHAVE_FALSA not in texto
    assert "chav" in texto  # o mascaramento mostra so o inicio


def test_diagnostico_mascara():
    cfg = Configuracoes(virustotal_api_key=CHAVE_FALSA)
    diag = cfg.diagnostico()
    assert CHAVE_FALSA not in json.dumps(diag)
    assert diag["Shodan"] == "<nao configurada>"


def test_mascarar():
    assert _mascarar("") == "<nao configurada>"
    assert _mascarar("curta") == "<configurada>"
    assert CHAVE_FALSA not in _mascarar(CHAVE_FALSA)


# ============================================================
# Nao-divulgacao da chave
# ============================================================


def test_sanitizador_remove_chave():
    texto = f"erro ao acessar https://api.shodan.io/x?key={CHAVE_FALSA}&minify=false"
    limpo = _limpar_segredo(texto, (CHAVE_FALSA,))
    assert CHAVE_FALSA not in limpo
    assert "CHAVE_REMOVIDA" in limpo


def test_sanitizador_pega_query_string_desconhecida():
    """Rede de seguranca: funciona mesmo sem conhecer o valor da chave."""
    texto = "falhou em https://exemplo.com/a?api_key=SegredoQualquer123&b=1"
    limpo = _limpar_segredo(texto, ())
    assert "SegredoQualquer123" not in limpo


def test_erro_de_rede_nao_vaza_a_chave(sem_espera):
    """
    Regressao critica: a excecao do requests embute a URL completa, e o
    Shodan leva a chave na query string.
    """
    cliente = ShodanClient(CHAVE_FALSA, tentativas=1)
    _responder(
        cliente,
        requests.ConnectionError(
            f"falha em https://api.shodan.io/shodan/host/1.2.3.4?key={CHAVE_FALSA}"
        ),
    )

    resultado = cliente.consultar_ip("8.8.8.8")
    assert CHAVE_FALSA not in resultado.erro
    assert CHAVE_FALSA not in json.dumps(resultado.to_dict())


def test_repr_do_cliente_nao_vaza():
    assert CHAVE_FALSA not in repr(ShodanClient(CHAVE_FALSA))
    assert CHAVE_FALSA not in repr(VirusTotalClient(CHAVE_FALSA))


# ============================================================
# Limitador de taxa
# ============================================================


def test_limitador_deixa_passar_dentro_da_cota():
    limitador = LimitadorDeTaxa(por_minuto=4)
    for _ in range(4):
        assert limitador.aguardar() == 0.0


def test_limitador_bloqueia_ao_estourar(monkeypatch):
    dormidas = []
    monkeypatch.setattr("enrichment.base.time.sleep", dormidas.append)

    limitador = LimitadorDeTaxa(por_minuto=2)
    limitador.aguardar()
    limitador.aguardar()
    espera = limitador.aguardar()

    assert espera > 0
    assert dormidas


# ============================================================
# Comportamento comum dos clients
# ============================================================


def test_sem_chave_nao_faz_requisicao():
    cliente = ClienteBase("")
    assert cliente.habilitado is False
    resposta = cliente._requisitar("/x")
    assert resposta.consultado is False
    assert "não configurada" in resposta.erro


def test_404_e_consulta_bem_sucedida(sem_espera):
    """
    "Nao encontrado" e informacao sobre o indicador. "Nao consegui
    consultar" nao e. Confundir os dois leva a conclusao errada.
    """
    cliente = VirusTotalClient(CHAVE_FALSA)
    _responder(cliente, RespostaFalsa(status=404))

    resultado = cliente.consultar_hash("a" * 64)
    assert resultado.consultado is True
    assert resultado.encontrado is False
    assert resultado.erro == ""


def test_chave_rejeitada_da_mensagem_clara(sem_espera):
    cliente = VirusTotalClient(CHAVE_FALSA)
    _responder(cliente, RespostaFalsa(status=401))

    resultado = cliente.consultar_hash("a" * 64)
    assert resultado.consultado is False
    assert "rejeitada" in resultado.erro
    assert CHAVE_FALSA not in resultado.erro


def test_429_e_repetido(monkeypatch):
    monkeypatch.setattr("enrichment.base.time.sleep", lambda _s: None)
    monkeypatch.setattr("enrichment.base.LimitadorDeTaxa.aguardar", lambda self: 0.0)

    cliente = VirusTotalClient(CHAVE_FALSA, rate_limit_por_minuto=100)
    respostas = [
        RespostaFalsa(status=429, cabecalhos={"Retry-After": "1"}),
        RespostaFalsa(status=200, payload={"data": {"attributes": {}}}),
    ]
    cliente.sessao.get = lambda url, **kw: respostas.pop(0)

    resultado = cliente.consultar_hash("a" * 64)
    assert resultado.consultado is True
    assert respostas == []


# ============================================================
# VirusTotal
# ============================================================


def test_hash_invalido_e_rejeitado_antes_da_rede():
    cliente = VirusTotalClient(CHAVE_FALSA)
    cliente.sessao.get = lambda *a, **k: pytest.fail("nao deveria ter feito requisicao")

    resultado = cliente.consultar_hash("nao_e_hash")
    assert "não é um hash" in resultado.erro


def test_consulta_de_hash_nao_envia_arquivo(sem_espera):
    """
    Decisao de privacidade: enviar amostra ao VT a publica para os
    assinantes, de forma irreversivel. O modulo so pergunta pelo hash.
    """
    cliente = VirusTotalClient(CHAVE_FALSA)
    chamadas = _responder(cliente, RespostaFalsa(payload={"data": {"attributes": {}}}))

    resultado = cliente.consultar_hash("a" * 64)

    url, kwargs = chamadas[0]
    assert url.endswith("/files/" + "a" * 64)
    assert "data" not in kwargs and "files" not in kwargs
    assert any("não foi enviado" in o for o in resultado.observacoes)


def test_nao_existe_funcao_de_upload():
    """Se alguem adicionar upload no futuro, este teste avisa."""
    proibidos = {"enviar", "upload", "submit", "scan_file", "enviar_arquivo"}
    assert not proibidos & set(dir(VirusTotalClient))


def test_interpreta_deteccoes(sem_espera):
    cliente = VirusTotalClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 45, "suspicious": 3,
                            "harmless": 0, "undetected": 20,
                        },
                        "last_analysis_results": {
                            "Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Agent"},
                            "ESET": {"category": "malicious", "result": "Win32/Emotet"},
                            "Limpo": {"category": "undetected", "result": None},
                        },
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.emotet/agent"
                        },
                        "first_submission_date": 1609459200,
                        "tags": ["peexe", "packed"],
                    }
                }
            }
        ),
    )

    r = cliente.consultar_hash("b" * 64)
    assert r.maliciosos == 45
    assert r.total_de_motores == 68
    assert r.familia_sugerida == "trojan.emotet/agent"
    assert r.deteccoes["ESET"] == "Win32/Emotet"
    assert "Limpo" not in r.deteccoes
    assert r.primeira_vez_visto.startswith("2021-01-01")
    assert r.consenso_forte is True
    assert "peexe" in r.tags


def test_deteccao_isolada_e_contextualizada(sem_espera):
    """1 motor de 70 e quase sempre falso positivo heuristico."""
    cliente = VirusTotalClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1, "suspicious": 0,
                            "harmless": 0, "undetected": 69,
                        }
                    }
                }
            }
        ),
    )

    r = cliente.consultar_hash("c" * 64)
    assert r.consenso_forte is False
    assert any("falso positivo" in o for o in r.observacoes)


def test_zero_deteccoes_e_contextualizado(sem_espera):
    cliente = VirusTotalClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0, "suspicious": 0,
                            "harmless": 0, "undetected": 70,
                        }
                    }
                }
            }
        ),
    )
    r = cliente.consultar_hash("d" * 64)
    assert any("Malware recente" in o for o in r.observacoes)


def test_hash_desconhecido_e_contextualizado(sem_espera):
    cliente = VirusTotalClient(CHAVE_FALSA)
    _responder(cliente, RespostaFalsa(status=404))
    r = cliente.consultar_hash("e" * 64)
    assert any("ausência não indica nada" in o for o in r.observacoes)


def test_taxa_de_deteccao_sem_divisao_por_zero():
    from enrichment.virustotal_client import ResultadoVirusTotal

    assert ResultadoVirusTotal("x", "arquivo").taxa_de_deteccao == 0.0


# ============================================================
# Shodan
# ============================================================


@pytest.mark.parametrize(
    "ip,esperado",
    [
        ("8.8.8.8", True),
        ("185.220.101.44", True),
        ("192.168.1.1", False),
        ("10.0.0.5", False),
        ("172.16.0.1", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("224.0.0.1", False),
        ("nao_e_ip", False),
    ],
)
def test_filtro_de_ip_consultavel(ip, esperado):
    """Consultar IP privado gasta cota e nao devolve nada util."""
    assert ip_e_consultavel(ip)[0] is esperado


def test_ip_privado_nao_chega_a_rede():
    cliente = ShodanClient(CHAVE_FALSA)
    cliente.sessao.get = lambda *a, **k: pytest.fail("nao deveria ter consultado")

    resultado = cliente.consultar_ip("192.168.1.1")
    assert "privado" in resultado.erro
    assert resultado.consultado is False


def test_interpreta_host(sem_espera):
    cliente = ShodanClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(
            payload={
                "country_name": "Netherlands",
                "city": "Amsterdam",
                "org": "Provedor Obscuro BV",
                "isp": "Provedor Obscuro BV",
                "asn": "AS12345",
                "hostnames": ["c2.exemplo.top"],
                "ports": [8443, 50050, 22],
                "vulns": ["CVE-2021-44228"],
                "tags": ["c2"],
                "last_update": "2026-08-01T10:00:00.000000",
                "data": [
                    {"port": 50050, "transport": "tcp", "product": "Java",
                     "data": "HTTP/1.1 404\nServer: Java\nlinha3\nlinha4"},
                    {"port": 22, "transport": "tcp", "product": "OpenSSH",
                     "version": "8.9", "data": "SSH-2.0-OpenSSH_8.9"},
                ],
            }
        ),
    )

    r = cliente.consultar_ip("185.220.101.44")

    assert r.encontrado is True
    assert r.pais == "Netherlands"
    assert r.portas == [22, 8443, 50050]
    assert r.vulnerabilidades == ["CVE-2021-44228"]
    assert r.infraestrutura_compartilhada is False

    # Banner truncado em 3 linhas, para nao poluir o relatorio.
    java = next(s for s in r.servicos if s.porta == 50050)
    assert len(java.banner.splitlines()) == 3


def test_porta_de_cobalt_strike_e_sinalizada(sem_espera):
    cliente = ShodanClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(payload={"ports": [50050], "data": [{"port": 50050}]}),
    )

    r = cliente.consultar_ip("185.220.101.44")
    assert r.portas_de_interesse
    assert "Cobalt Strike" in r.portas_de_interesse[0].observacao
    # Indicio, nunca prova.
    assert any("não prova" in o for o in r.observacoes)


def test_infraestrutura_compartilhada_e_sinalizada(sem_espera):
    """O que se observa num IP da Cloudflare descreve a Cloudflare."""
    cliente = ShodanClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(payload={"org": "Cloudflare, Inc.", "isp": "Cloudflare",
                               "ports": [443], "data": []}),
    )

    r = cliente.consultar_ip("104.16.0.1")
    assert r.infraestrutura_compartilhada is True
    assert any("infraestrutura compartilhada" in o for o in r.observacoes)


def test_data_da_varredura_e_sinalizada(sem_espera):
    cliente = ShodanClient(CHAVE_FALSA)
    _responder(
        cliente,
        RespostaFalsa(payload={"ports": [80], "data": [],
                               "last_update": "2026-01-15T00:00:00"}),
    )
    r = cliente.consultar_ip("8.8.8.8")
    assert any("varre periodicamente" in o for o in r.observacoes)


def test_host_ausente_e_contextualizado(sem_espera):
    cliente = ShodanClient(CHAVE_FALSA)
    _responder(cliente, RespostaFalsa(status=404))
    r = cliente.consultar_ip("8.8.8.8")
    assert r.consultado is True
    assert any("ainda" in o for o in r.observacoes)


def test_portas_de_interesse_documentadas():
    """Toda porta sinalizada precisa explicar por que chamou atencao."""
    for porta, motivo in PORTAS_DE_INTERESSE.items():
        assert 0 < porta < 65536
        assert motivo


def test_resultados_serializaveis(sem_espera):
    cliente = ShodanClient(CHAVE_FALSA)
    _responder(cliente, RespostaFalsa(payload={"ports": [80], "data": []}))
    assert json.dumps(cliente.consultar_ip("8.8.8.8").to_dict(), default=str)


# ============================================================
# Autenticacao: o que e ENVIADO
#
# Estes testes existem por causa de um bug real. O VirusTotalClient nunca
# definia o cabecalho x-apikey, entao toda consulta voltava 401 - e ainda
# assim a suite passava inteira, porque todos os testes verificavam apenas
# como a RESPOSTA era interpretada, nunca o que a requisicao levava.
# Duble de resposta nao prova que a requisicao esta certa.
# ============================================================


def test_virustotal_envia_a_chave_no_cabecalho(sem_espera):
    """
    Regressao: a API v3 do VirusTotal autentica por `x-apikey`. Sem esse
    cabecalho tudo devolve 401, e nenhum teste de resposta simulada pega.
    """
    cliente = VirusTotalClient(CHAVE_FALSA)
    assert cliente.sessao.headers.get("x-apikey") == CHAVE_FALSA

    chamadas = _responder(cliente, RespostaFalsa(payload={"data": {"attributes": {}}}))
    cliente.consultar_hash("a" * 64)

    # A chave viaja na sessao, entao vale para toda requisicao.
    assert chamadas
    assert cliente.sessao.headers["x-apikey"] == CHAVE_FALSA


def test_virustotal_sem_chave_nao_define_cabecalho():
    """Cabecalho vazio confundiria o servidor; melhor nao enviar nada."""
    assert "x-apikey" not in VirusTotalClient("").sessao.headers


def test_shodan_envia_a_chave_na_query(sem_espera):
    """O Shodan autentica por query string, e nao por cabecalho."""
    cliente = ShodanClient(CHAVE_FALSA)
    chamadas = _responder(cliente, RespostaFalsa(payload={"ports": [], "data": []}))

    cliente.consultar_ip("8.8.8.8")

    _url, kwargs = chamadas[0]
    assert kwargs["params"]["key"] == CHAVE_FALSA


def test_chave_nao_vai_para_o_lugar_errado(sem_espera):
    """
    Cada servico tem seu esquema. Mandar a chave do Shodan num cabecalho, ou
    a do VT numa query string, falharia de forma silenciosa.
    """
    vt = VirusTotalClient(CHAVE_FALSA)
    chamadas = _responder(vt, RespostaFalsa(payload={"data": {"attributes": {}}}))
    vt.consultar_hash("a" * 64)
    _url, kwargs = chamadas[0]
    assert not (kwargs.get("params") or {}).get("key")

    sh = ShodanClient(CHAVE_FALSA)
    assert "x-apikey" not in sh.sessao.headers
