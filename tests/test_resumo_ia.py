"""
Testes do resumo por LLM local.

Nenhum teste chama o Ollama de verdade: o modelo tem 4,9 GB, a geracao
varia entre execucoes e depender dele tornaria a suite lenta e
nao-deterministica. As respostas sao simuladas.

O que realmente se testa aqui e a VERIFICACAO. Um resumo gerado por LLM so
e utilizavel neste projeto porque cada afirmacao dele e conferida contra os
achados; se o verificador deixar passar invencao, o modulo inteiro perde a
razao de existir. Por isso a maior parte dos testes alimenta texto
deliberadamente falsificado e exige que ele seja pego.
"""

from __future__ import annotations

import base64
import json

import pytest

from core.pipeline import OpcoesAnalise, ResultadoAnalise, analisar
from core.resumo_ia import (
    MODELO_PADRAO,
    ClienteOllama,
    ErroResumoIA,
    ResumoIA,
    _montar_contexto,
    gerar_resumo,
    resumir_em_texto,
    verificar,
)


@pytest.fixture
def artefato(tmp_path):
    """Artefato sintetico com achados conhecidos, para conferir contra."""
    caminho = tmp_path / "amostra_ia.bin"
    caminho.write_bytes(
        "\n".join(
            [
                r"Software\Microsoft\Windows\CurrentVersion\Run\WinDefendUpdate",
                "vssadmin.exe delete shadows /all /quiet",
                "Seus arquivos foram criptografados com AES-256",
                "http://185.220.101.44:8443/gate.php",
                base64.b64encode(b"http://backup-c2.top/beacon").decode(),
                "powershell.exe -nop -w hidden -enc SQBFAFgA",
            ]
        ).encode()
    )
    return caminho


@pytest.fixture
def resultado(artefato):
    return analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))


# ============================================================
# Verificacao: o mecanismo de seguranca do modulo
# ============================================================


def test_texto_fiel_nao_gera_invencao(resultado):
    """Resumo que so cita o observado passa limpo."""
    ids = [t.tecnica_id for t in resultado.mapeamento.tecnicas[:3]]
    texto = (
        "O artefato apresenta as tecnicas " + ", ".join(ids) + ". "
        "Um indicador de rede foi observado em http://185.220.101.44:8443/gate.php."
    )
    assert verificar(texto, resultado) == []


def test_tecnica_inventada_e_detectada(resultado):
    """
    O erro mais comum: o modelo cita uma tecnica plausivel que a analise
    nao mapeou. Num relatorio de CTI isso vira conclusao falsa.
    """
    observadas = {t.tecnica_id for t in resultado.mapeamento.tecnicas}
    assert "T1055.012" not in observadas  # premissa do teste

    invencoes = verificar("O binario usa T1055.012 para se esconder.", resultado)

    assert len(invencoes) == 1
    assert invencoes[0].tipo == "tecnica"
    assert invencoes[0].valor == "T1055.012"


def test_ioc_inventado_e_detectado(resultado):
    invencoes = verificar(
        "O C2 primario e 45.142.212.61 e ha outro em http://evil-panel.ru/gate",
        resultado,
    )
    valores = {i.valor for i in invencoes}
    assert "45.142.212.61" in valores
    assert "http://evil-panel.ru/gate" in valores
    assert all(i.tipo == "ioc" for i in invencoes)


def test_pontuacao_final_nao_entra_no_ioc(resultado):
    """
    Regressao: quando a URL termina a frase, o ponto final vinha junto e o
    indicador aparecia como "http://exemplo.com/a." no relatorio.
    """
    invencoes = verificar("O painel fica em http://evil-panel.ru/gate.", resultado)
    assert invencoes[0].valor == "http://evil-panel.ru/gate"


def test_familia_inventada_e_detectada(resultado):
    """
    A invencao mais perigosa: um nome de familia errado no topo do
    relatorio contamina toda a leitura que vem depois.
    """
    invencoes = verificar(
        "Esta amostra e o Emotet, identificado com alta confianca.", resultado
    )
    assert any(i.tipo == "familia" and i.valor == "emotet" for i in invencoes)


def test_grupo_inventado_e_detectado(resultado):
    invencoes = verificar(
        "A infraestrutura e consistente com o grupo G0016.", resultado
    )
    assert any(i.tipo == "grupo" and i.valor == "G0016" for i in invencoes)


def test_varias_invencoes_de_uma_vez(resultado):
    """Texto com os erros tipicos de um LLM solto num relatorio de CTI."""
    falso = (
        "Esta amostra e o Emotet. O binario usa T1055.012 e T1003.001. "
        "O C2 e 45.142.212.61. A campanha e do grupo G0016 (APT29), "
        "com Cobalt Strike no estagio seguinte."
    )
    invencoes = verificar(falso, resultado)

    tipos = {i.tipo for i in invencoes}
    assert tipos == {"tecnica", "ioc", "familia", "grupo"}

    valores = {i.valor for i in invencoes}
    assert {"T1055.012", "T1003.001", "45.142.212.61", "G0016", "emotet"} <= valores


def test_familia_confirmada_por_fonte_nao_e_invencao(resultado):
    """
    Se o VirusTotal ou o MalwareBazaar identificaram a familia, cita-la e
    correto - o verificador nao pode acusar o que tem respaldo.
    """
    from enrichment.virustotal_client import ResultadoVirusTotal

    vt = ResultadoVirusTotal(indicador="x", tipo="arquivo")
    vt.familia_sugerida = "trojan.emotet/agent"
    resultado.virustotal = [vt]

    assert verificar("A amostra e o Emotet.", resultado) == []


def test_tecnica_observada_nao_e_invencao(resultado):
    observada = resultado.mapeamento.tecnicas[0].tecnica_id
    assert verificar(f"Foi observada a tecnica {observada}.", resultado) == []


def test_ioc_dentro_de_outro_conta_como_observado(resultado):
    """
    O IP aparece sozinho e tambem dentro da URL. Citar qualquer um dos dois
    e legitimo; exigir igualdade exata acusaria falso positivo.
    """
    assert verificar("O endereco 185.220.101.44 foi visto.", resultado) == []


def test_verificacao_funciona_com_analise_vazia():
    """Resultado sem etapa nenhuma nao pode quebrar o verificador."""
    vazio = ResultadoAnalise(caminho="nada.bin")
    invencoes = verificar("Usa T1055 e o C2 e 1.2.3.4.", vazio)
    assert len(invencoes) == 2


# ============================================================
# Prompt
# ============================================================


def test_prompt_nao_leva_strings_cruas(resultado):
    """
    O modelo recebe achados estruturados, nunca o conteudo bruto: alem de
    inflar o prompt, strings cruas podem conter dado sensivel da amostra.
    """
    contexto = _montar_contexto(resultado)

    # O contexto cita os achados...
    assert "Indicadores" in contexto
    assert "Tecnicas ATT&CK" in contexto

    # ...mas nao despeja a lista de strings extraidas.
    assert len(contexto) < 6000
    brutas = [s.valor for s in resultado.extracao.strings]
    assert not all(b in contexto for b in brutas)


def test_prompt_declara_a_natureza_estatica(resultado):
    assert "ESTATICA" in _montar_contexto(resultado)


def test_prompt_marca_grupos_como_nao_atribuicao(resultado, cache_stix):
    r = analisar(
        resultado.caminho,
        OpcoesAnalise(
            usar_floss=False,
            usar_stix=True,
            baixar_stix_se_faltar=False,
            caminho_cache_stix=str(cache_stix),
        ),
    )
    contexto = _montar_contexto(r)
    if r.atribuicao and r.atribuicao.candidatos:
        assert "NAO e atribuicao" in contexto


def test_prompt_registra_etapa_que_falhou(artefato, monkeypatch):
    from core import pipeline

    monkeypatch.setattr(
        pipeline.pe_analyzer,
        "analisar",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("falha simulada")),
    )
    r = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))
    assert "Etapas que falharam" in _montar_contexto(r)


# ============================================================
# Cliente
# ============================================================


class _RespostaFalsa:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_servidor_fora_do_ar_da_instrucao_util(monkeypatch):
    import requests

    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("recusado")),
    )
    ok, motivo = ClienteOllama().disponivel()
    assert ok is False
    assert "aplicativo esta aberto" in motivo


def test_sem_modelo_instalado_da_o_comando(monkeypatch):
    import requests

    monkeypatch.setattr(
        requests, "get", lambda *a, **k: _RespostaFalsa({"models": []})
    )
    ok, motivo = ClienteOllama().disponivel()
    assert ok is False
    assert "ollama pull" in motivo


def test_modelo_diferente_do_pedido_e_reportado(monkeypatch):
    import requests

    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: _RespostaFalsa({"models": [{"name": "mistral:7b"}]}),
    )
    ok, motivo = ClienteOllama(modelo="llama3.1:8b").disponivel()
    assert ok is False
    assert "mistral:7b" in motivo


def test_modelo_sem_tag_e_aceito(monkeypatch):
    """"llama3.1" no servidor atende um pedido por "llama3.1:8b"."""
    import requests

    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: _RespostaFalsa({"models": [{"name": "llama3.1"}]}),
    )
    assert ClienteOllama(modelo="llama3.1:8b").disponivel()[0] is True


def test_temperatura_zero_e_keep_alive(monkeypatch):
    """
    Temperatura zero porque o resumo precisa ser literal em relacao aos
    achados; keep_alive para nao repagar o carregamento do modelo a cada
    artefato analisado.
    """
    import requests

    enviado = {}

    def falso_post(url, json=None, timeout=None):
        enviado.update(json)
        return _RespostaFalsa({"response": "texto"})

    monkeypatch.setattr(requests, "post", falso_post)

    ClienteOllama().gerar("prompt")
    assert enviado["options"]["temperature"] == 0
    assert enviado["keep_alive"]
    assert enviado["stream"] is False


def test_resposta_vazia_vira_erro(monkeypatch):
    import requests

    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _RespostaFalsa({"response": "   "})
    )
    with pytest.raises(ErroResumoIA, match="vazia"):
        ClienteOllama().gerar("prompt")


# ============================================================
# Fluxo completo
# ============================================================


def _simular(monkeypatch, texto: str):
    """Faz o Ollama responder um texto fixo."""
    import requests

    monkeypatch.setattr(
        requests, "get", lambda *a, **k: _RespostaFalsa({"models": [{"name": MODELO_PADRAO}]})
    )
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _RespostaFalsa({"response": texto})
    )


def test_fluxo_com_resumo_fiel(resultado, monkeypatch):
    ids = [t.tecnica_id for t in resultado.mapeamento.tecnicas[:2]]
    _simular(monkeypatch, f"O artefato apresenta {', '.join(ids)}.")

    resumo = gerar_resumo(resultado)

    assert resumo.gerado is True
    assert resumo.confiavel is True
    assert resumo.invencoes == []
    assert "modelo de linguagem local" in resumo.ressalva


def test_fluxo_com_invencao_marca_nao_confiavel(resultado, monkeypatch):
    _simular(monkeypatch, "Esta amostra e o Emotet e usa T1055.012.")

    resumo = gerar_resumo(resultado)

    assert resumo.gerado is True
    assert resumo.confiavel is False
    assert len(resumo.invencoes) == 2
    assert "ATENCAO" in resumo.ressalva
    assert resumo.avisos


def test_texto_inventado_nao_e_escondido(resultado, monkeypatch):
    """
    O resumo com invencao continua visivel - escondido, o analista nao
    veria o erro. Mas nunca aparece sem o aviso do que foi inventado.
    """
    _simular(monkeypatch, "Esta amostra e o Emotet.")
    resumo = gerar_resumo(resultado)

    texto = resumir_em_texto(resumo)
    assert "Emotet" in texto
    assert "sem respaldo" in texto
    assert "emotet" in texto.lower()


def test_falha_nao_levanta_excecao(resultado, monkeypatch):
    """O resumo e um adicional: a analise nao pode depender dele."""
    import requests

    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("fora do ar")),
    )

    resumo = gerar_resumo(resultado)
    assert resumo.gerado is False
    assert resumo.erro
    assert resumo.confiavel is False


def test_resumo_serializavel(resultado, monkeypatch):
    _simular(monkeypatch, "Texto qualquer com T9999 inventada.")
    assert json.dumps(gerar_resumo(resultado).to_dict(), default=str)


def test_texto_quando_nao_foi_gerado():
    saida = resumir_em_texto(ResumoIA(erro="Ollama nao respondeu"))
    assert "nao gerado" in saida
    assert "Ollama nao respondeu" in saida
