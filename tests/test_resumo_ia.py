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
    """
    Dubla uma resposta do Ollama.

    O /api/tags responde JSON de uma vez; o /api/generate responde em
    streaming, uma linha de JSON por token. O duble precisa falar os dois,
    e o fluxo precisa ser fiel ao formato real - inclusive o ultimo pedaco
    trazendo "done": true, que e o que encerra a leitura.
    """

    def __init__(self, payload, status=200, pedacos=None):
        self._payload = payload
        self.status_code = status
        self._pedacos = pedacos

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload

    def iter_lines(self, decode_unicode=False):
        if self._pedacos is not None:
            for linha in self._pedacos:
                yield linha
            return

        # Sem fluxo explicito: entrega o texto inteiro num pedaco so, como
        # faria um modelo que respondeu de primeira.
        texto = self._payload.get("response", "")
        yield json.dumps({"response": texto, "done": True}).encode("utf-8")


def _fluxo(texto: str, por_pedaco: int = 5):
    """Quebra um texto em pedacos, como o Ollama faz token a token."""
    fatias = [texto[i : i + por_pedaco] for i in range(0, len(texto), por_pedaco)] or [""]
    linhas = [
        json.dumps({"response": f, "done": False}).encode("utf-8") for f in fatias
    ]
    linhas.append(json.dumps({"response": "", "done": True}).encode("utf-8"))
    return linhas


@pytest.mark.parametrize(
    "executavel, esperado",
    [
        # Nao respondeu e nao esta no disco: instalar.
        ("", "ollama.com/download"),
        # Nao respondeu mas esta no disco: so abrir.
        (r"C:\ollama\ollama.exe", "Abra o aplicativo Ollama"),
    ],
)
def test_servidor_fora_do_ar_da_instrucao_util(monkeypatch, executavel, esperado):
    """
    "Nao respondeu" era uma mensagem so para dois problemas com remedios
    diferentes. O executavel e forcado aqui: o teste nao pode depender de o
    Ollama estar instalado na maquina que roda a suite.
    """
    import requests

    from core import resumo_ia

    monkeypatch.setattr(resumo_ia, "_executavel_ollama", lambda: executavel)
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("recusado")),
    )
    ok, motivo = ClienteOllama().disponivel()
    assert ok is False
    assert esperado in motivo


def _respostas_ollama(monkeypatch, versao=None, modelos=None):
    """Dubla /api/version e /api/tags. versao=None: servidor fora do ar."""
    import requests

    def falso_get(url, *a, **k):
        if versao is None:
            raise requests.ConnectionError("recusado")
        if url.endswith("/api/version"):
            return _RespostaFalsa({"version": versao})
        return _RespostaFalsa({"models": [{"name": m} for m in (modelos or [])]})

    monkeypatch.setattr(requests, "get", falso_get)


def test_diagnostico_pronto(monkeypatch):
    from core.resumo_ia import diagnosticar_ollama

    _respostas_ollama(monkeypatch, versao="0.34.2", modelos=["llama3.1:8b", "qwen2.5:7b"])
    d = diagnosticar_ollama("llama3.1:8b")
    assert d.estado == "pronto"
    assert d.versao == "0.34.2"
    assert d.modelos == ["llama3.1:8b", "qwen2.5:7b"]
    assert d.orientacao == ""


def test_diagnostico_sem_modelo_da_o_comando_exato(monkeypatch):
    from core.resumo_ia import diagnosticar_ollama

    _respostas_ollama(monkeypatch, versao="0.34.2", modelos=["qwen2.5:7b"])
    d = diagnosticar_ollama("llama3.1:8b")
    assert d.estado == "sem_modelo"
    assert "ollama pull llama3.1:8b" in d.orientacao


def test_diagnostico_parado_le_a_versao_do_executavel(monkeypatch):
    from core import resumo_ia

    _respostas_ollama(monkeypatch, versao=None)
    monkeypatch.setattr(resumo_ia, "_executavel_ollama", lambda: r"C:\ollama\ollama.exe")
    monkeypatch.setattr(resumo_ia, "_versao_pelo_executavel", lambda _e: "0.34.2")
    d = resumo_ia.diagnosticar_ollama()
    assert d.estado == "parado"
    assert d.instalado is True
    assert d.versao == "0.34.2"


def test_diagnostico_nao_instalado(monkeypatch):
    from core import resumo_ia

    _respostas_ollama(monkeypatch, versao=None)
    monkeypatch.setattr(resumo_ia, "_executavel_ollama", lambda: "")
    d = resumo_ia.diagnosticar_ollama()
    assert d.estado == "nao_instalado"
    assert "ollama.com/download" in d.orientacao


def test_sem_modelo_instalado_da_o_comando(monkeypatch):
    import requests

    monkeypatch.setattr(
        requests, "get", lambda *a, **k: _RespostaFalsa({"models": []})
    )
    ok, motivo = ClienteOllama().disponivel()
    assert ok is False
    # O padrao vem do Hugging Face: instala pelo nosso comando, nao pelo pull.
    assert "python main.py instalar-ia" in motivo
    ok, motivo = ClienteOllama(modelo="llama3.1:8b").disponivel()
    assert "ollama pull llama3.1:8b" in motivo


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

    def falso_post(url, json=None, timeout=None, stream=None):
        enviado.update(json)
        enviado["_stream_kwarg"] = stream
        return _RespostaFalsa({"response": "texto"})

    monkeypatch.setattr(requests, "post", falso_post)

    ClienteOllama().gerar("prompt")
    assert enviado["options"]["temperature"] == 0
    assert enviado["keep_alive"]

    # O streaming nao e preferencia de apresentacao: sem ele a conexao fica
    # muda durante toda a geracao, que em um modelo 8B passa de um minuto, e
    # quem espera nao distingue "gerando" de "travou". Precisa estar ligado
    # nos dois lugares - no corpo, para o Ollama mandar aos poucos, e no
    # kwarg do requests, para a resposta nao ser bufferizada inteira antes
    # de chegar aqui.
    assert enviado["stream"] is True
    assert enviado["_stream_kwarg"] is True


def test_progresso_chega_durante_a_geracao(monkeypatch):
    """
    O callback precisa ser chamado ENQUANTO o modelo gera, nao so no fim.
    Chamar uma vez no final seria inutil: o problema que ele resolve e
    justamente o silencio durante a espera.
    """
    import requests

    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: _RespostaFalsa({}, pedacos=_fluxo("cmd.exe /c whoami", 4)),
    )

    estados = []
    texto = ClienteOllama().gerar("prompt", progresso=estados.append)

    assert texto == "cmd.exe /c whoami"
    # Um estado por pedaco, e nenhum deles e o texto completo exceto o fim.
    assert len(estados) > 1
    assert estados[0].texto_parcial != texto
    assert estados[0].concluido is False
    assert estados[-1].concluido is True
    assert estados[-1].texto_parcial == texto

    # O texto so cresce: um estado nunca "desfaz" o anterior.
    tamanhos = [len(e.texto_parcial) for e in estados]
    assert tamanhos == sorted(tamanhos)


def test_progresso_e_opcional(monkeypatch):
    """Quem nao passa callback nao paga nada por ele."""
    import requests

    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _RespostaFalsa({}, pedacos=_fluxo("ok"))
    )
    assert ClienteOllama().gerar("prompt") == "ok"


def test_resumo_do_estado_e_legivel():
    """A linha vai para barra de status: precisa caber e dizer algo."""
    from core.resumo_ia import EstadoGeracao

    gerando = EstadoGeracao(texto_parcial="abc", pedacos=40, segundos=10.0)
    assert "40" in gerando.resumo() and "10s" in gerando.resumo()
    assert gerando.por_segundo == 4.0

    pronto = EstadoGeracao(
        texto_parcial="abc", pedacos=40, segundos=10.0, concluido=True
    )
    assert "gerado" in pronto.resumo()

    # Nos primeiros instantes nao da para estimar ritmo sem mentir.
    cedo = EstadoGeracao(texto_parcial="a", pedacos=1, segundos=0.1)
    assert cedo.por_segundo == 0.0
    assert "/s" not in cedo.resumo()


def test_linha_malformada_no_fluxo_nao_derruba_a_geracao(monkeypatch):
    """
    Uma linha que nao e JSON no meio do fluxo nao justifica descartar tudo
    que ja chegou.
    """
    import requests

    pedacos = _fluxo("cmd.exe")
    pedacos.insert(2, b"{lixo nao json")

    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _RespostaFalsa({}, pedacos=pedacos)
    )
    assert ClienteOllama().gerar("prompt") == "cmd.exe"


def test_erro_no_meio_do_fluxo_vira_excecao(monkeypatch):
    """
    Resumo cortado no meio e pior que nenhum: parece completo. Se o Ollama
    reclama no meio do fluxo, o que chegou nao se aproveita.
    """
    import requests

    pedacos = [
        json.dumps({"response": "come", "done": False}).encode("utf-8"),
        json.dumps({"error": "modelo descarregado"}).encode("utf-8"),
    ]
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _RespostaFalsa({}, pedacos=pedacos)
    )
    with pytest.raises(ErroResumoIA, match="descarregado"):
        ClienteOllama().gerar("prompt")


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
    assert "ATENÇÃO" in resumo.ressalva
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
    assert "não gerado" in saida
    assert "Ollama nao respondeu" in saida
