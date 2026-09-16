"""
Testes do pipeline e do gerador de relatorio.

O comportamento mais importante do pipeline e o isolamento de falha: uma
etapa que quebra nao pode derrubar as outras, e a falha precisa aparecer no
relatorio em vez de virar silencio.

No relatorio, o que se testa e que a ressalva sobrevive: nenhuma tecnica sem
evidencia, nenhum grupo sem o aviso de que aquilo nao e atribuicao, e a
secao de limitacoes sempre presente.
"""

from __future__ import annotations

import json

import pytest
import yara

from core import pipeline
from core.pipeline import Estagio, OpcoesAnalise, ResultadoAnalise, analisar
from reports import report_generator as rg


@pytest.fixture
def artefato(tmp_path):
    """
    Artefato sintetico com sinais reconheciveis, sem malware real.

    Traz um C2 em Base64, chave de persistencia, comando de destruicao de
    shadow copies e strings distintivas - o suficiente para exercitar todas
    as etapas do pipeline.
    """
    import base64

    c2_oculto = base64.b64encode(b"http://c2-sintetico.xyz:8443/gate.php").decode()

    conteudo = "\n".join(
        [
            "MZ",  # so para parecer um cabecalho; nao e PE valido
            r"Software\Microsoft\Windows\CurrentVersion\Run\AtualizadorSeguro",
            "vssadmin.exe delete shadows /all /quiet",
            "Seus arquivos foram criptografados com AES-256",
            "POST /gate.php HTTP/1.1",
            "http://185.220.101.44:8443/gate.php",
            c2_oculto,
            "Mutex_RabTeste_2026_v7",
            "X-Sessao-Token: qWe123Rty",
            "operador@protonmail.com",
            "kernel32.dll",
            "GetProcAddress",
        ]
    ).encode()

    caminho = tmp_path / "artefato_sintetico.bin"
    caminho.write_bytes(conteudo)
    return caminho


@pytest.fixture
def resultado(artefato):
    """Pipeline completo, offline e sem FLOSS (mais rapido e determinista)."""
    return analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=False),
    )


# ============================================================
# Pipeline: caminho feliz
# ============================================================


def test_pipeline_executa_todas_as_etapas(resultado):
    assert resultado.extracao is not None
    assert resultado.info_pe is not None
    assert resultado.desofuscacao is not None
    assert resultado.regra_yara is not None
    assert resultado.mapeamento is not None
    assert resultado.kill_chain is not None
    assert resultado.concluido is True
    assert resultado.erros == []


def test_pipeline_encontra_os_sinais_plantados(resultado):
    ids = {t.tecnica_id for t in resultado.mapeamento.tecnicas}
    assert "T1547.001" in ids  # chave Run
    assert "T1490" in ids      # shadow copies
    assert "T1486" in ids      # nota de resgate


def test_ioc_atras_de_ofuscacao_entra_na_lista_final(resultado):
    """
    O ponto do pipeline: o C2 em Base64 nao aparece na varredura de string,
    so depois da desofuscacao - e precisa chegar a lista consolidada.
    """
    valores = {i.valor for i in resultado.iocs}
    assert "http://c2-sintetico.xyz:8443/gate.php" in valores


def test_iocs_sao_deduplicados_entre_as_fontes(resultado):
    chaves = [(i.valor, i.tipo) for i in resultado.iocs]
    assert len(chaves) == len(set(chaves))


def test_progresso_e_reportado_em_ordem(artefato):
    eventos = []
    analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False),
        progresso=lambda e, m, f: eventos.append((e, f)),
    )

    assert eventos
    assert eventos[0][0] is Estagio.EXTRACAO
    assert eventos[-1][0] is Estagio.CONCLUIDO
    assert eventos[-1][1] == pytest.approx(1.0)
    # A fracao nunca retrocede.
    fracoes = [f for _, f in eventos]
    assert fracoes == sorted(fracoes)


def test_resultado_serializavel(resultado):
    texto = json.dumps(resultado.to_dict(), default=str)
    assert resultado.sha256 in texto


# ============================================================
# Pipeline: isolamento de falha
# ============================================================


def test_falha_de_etapa_nao_derruba_as_demais(artefato, monkeypatch):
    """
    Se o parsing do PE explode, o mapeamento ATT&CK ainda precisa rodar com
    as strings. E a garantia central do pipeline.
    """
    def explodir(*_a, **_k):
        raise RuntimeError("falha simulada no parsing do PE")

    monkeypatch.setattr(pipeline.pe_analyzer, "analisar", explodir)

    r = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))

    assert r.info_pe is None
    assert any(e.estagio is Estagio.PE for e in r.erros)
    assert not any(e.fatal for e in r.erros)
    # O resto seguiu.
    assert r.extracao is not None
    assert r.mapeamento is not None
    assert r.mapeamento.tecnicas


def test_erro_registra_o_estagio_e_a_mensagem(artefato, monkeypatch):
    monkeypatch.setattr(
        pipeline.deobfuscator, "desofuscar",
        lambda *_a, **_k: (_ for _ in ()).throw(ValueError("erro de teste")),
    )
    r = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))

    erro = next(e for e in r.erros if e.estagio is Estagio.DESOFUSCACAO)
    assert "ValueError" in erro.mensagem
    assert "erro de teste" in erro.mensagem


def test_arquivo_ilegivel_encerra_com_erro_fatal(tmp_path):
    r = analisar(
        tmp_path / "nao_existe.bin", OpcoesAnalise(usar_floss=False, usar_stix=False)
    )
    assert r.extracao is None
    assert any(e.fatal for e in r.erros)
    assert r.concluido is False


def test_cancelamento_interrompe(artefato):
    """Cancelar devolve o que ja foi feito, sem excecao."""
    chamadas = {"n": 0}

    def cancelar():
        chamadas["n"] += 1
        return chamadas["n"] > 2

    r = analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False),
        cancelado=cancelar,
    )
    assert r.cancelado is True
    assert r.extracao is not None  # o que rodou antes continua valendo


# ============================================================
# Pipeline: nada sai sem pedido
# ============================================================


def test_enriquecimento_e_desligado_por_padrao():
    """
    Consulta externa revela a terceiros o que esta sendo investigado. O
    padrao precisa ser nao consultar.
    """
    assert OpcoesAnalise().enriquecer is False


def test_sem_enriquecimento_nenhum_client_e_criado(artefato, monkeypatch):
    import enrichment.virustotal_client as vt
    import enrichment.shodan_client as sh

    monkeypatch.setattr(
        vt, "criar", lambda *_a, **_k: pytest.fail("VirusTotal nao deveria ser criado")
    )
    monkeypatch.setattr(
        sh, "criar", lambda *_a, **_k: pytest.fail("Shodan nao deveria ser criado")
    )

    r = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))
    assert r.virustotal == []
    assert any("nenhum dado foi enviado" in a for a in r.avisos)


def test_enriquecimento_sem_chave_e_pulado_com_aviso(artefato, monkeypatch):
    from config.settings import Configuracoes

    r = analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True),
        config=Configuracoes(),  # sem chave nenhuma
    )
    assert r.virustotal == []
    assert r.shodan == []
    assert any("VirusTotal pulado" in a for a in r.avisos)
    assert any("Shodan pulado" in a for a in r.avisos)


def test_stix_indisponivel_gera_aviso(artefato, tmp_path):
    r = analisar(
        artefato,
        OpcoesAnalise(
            usar_floss=False,
            usar_stix=True,
            baixar_stix_se_faltar=False,
            caminho_cache_stix=str(tmp_path / "ausente.json"),
        ),
    )
    assert any("STIX do ATT&CK indisponivel" in a for a in r.avisos)
    assert r.mapeamento is not None  # o catalogo local salvou a etapa


def test_pipeline_com_stix_faz_atribuicao(artefato, cache_stix):
    r = analisar(
        artefato,
        OpcoesAnalise(
            usar_floss=False,
            usar_stix=True,
            baixar_stix_se_faltar=False,
            caminho_cache_stix=str(cache_stix),
        ),
    )
    assert r.mapeamento.fonte == "stix"
    assert r.atribuicao is not None


# ============================================================
# Relatorio: conteudo
# ============================================================


def test_markdown_tem_todas_as_secoes(resultado):
    texto = rg.montar_markdown(resultado)
    for titulo in (
        "Sumario", "Artefato", "Indicadores de comprometimento",
        "Tecnicas MITRE ATT&CK", "Cyber Kill Chain", "Regra YARA",
        "Limitacoes desta analise",
    ):
        assert titulo in texto, f"secao ausente: {titulo}"


def test_secao_de_limitacoes_e_obrigatoria(resultado):
    """Relatorio que omite o que faltou passa falsa impressao de completude."""
    texto = rg.montar_markdown(resultado)
    assert "Limitacoes desta analise" in texto
    assert "analise **estatica**" in texto
    assert "nao foi executado" in texto


def test_falha_de_etapa_aparece_no_relatorio(artefato, monkeypatch):
    monkeypatch.setattr(
        pipeline.pe_analyzer, "analisar",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    r = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))
    texto = rg.montar_markdown(r)

    assert "Etapas que falharam" in texto
    assert "Analise do PE" in texto


def test_tecnica_nunca_aparece_sem_evidencia(resultado):
    texto = rg.montar_markdown(resultado)
    for t in resultado.mapeamento.tecnicas:
        posicao = texto.find(t.tecnica_id)
        assert posicao > 0
        # A evidencia vem logo depois do bloco da tecnica.
        assert "Evidencia" in texto[posicao : posicao + 900]


def test_ressalva_de_capacidade_esta_presente(resultado):
    texto = rg.montar_markdown(resultado)
    assert "capacidade" in texto
    assert "nao que ela e efetivamente usada" in texto


def test_ressalva_de_atribuicao_acompanha_os_grupos(artefato, cache_stix):
    r = analisar(
        artefato,
        OpcoesAnalise(
            usar_floss=False, usar_stix=True, baixar_stix_se_faltar=False,
            caminho_cache_stix=str(cache_stix),
        ),
    )
    texto = rg.montar_markdown(r)
    assert "nao e atribuicao" in texto


def test_relatorio_diz_quando_nao_houve_consulta_externa(resultado):
    texto = rg.montar_markdown(resultado)
    assert "Nenhum dado deste artefato foi enviado" in texto


def test_aviso_de_floss_ausente(resultado):
    """Sem FLOSS o relatorio precisa dizer o que deixou de ver."""
    texto = rg.montar_markdown(resultado)
    assert "O FLOSS nao foi usado" in texto


# ============================================================
# Relatorio: formatos
# ============================================================


def test_gera_markdown_e_json(resultado, tmp_path):
    saidas = rg.gerar(resultado, tmp_path, ["md", "json"])
    assert set(saidas) == {"md", "json"}
    for caminho in saidas.values():
        assert caminho.exists() and caminho.stat().st_size > 0

    dados = json.loads(saidas["json"].read_text(encoding="utf-8"))
    assert dados["extracao"]["sha256"] == resultado.sha256


def test_json_traz_tudo_sem_corte(resultado, tmp_path):
    """O Markdown corta listas longas; o JSON nao pode cortar."""
    saida = rg.salvar_json(resultado, tmp_path / "completo.json")
    dados = json.loads(saida.read_text(encoding="utf-8"))
    assert len(dados["extracao"]["strings"]) == len(resultado.extracao.strings)


def test_gera_pdf(resultado, tmp_path):
    caminho = rg.salvar_pdf(resultado, tmp_path / "r.pdf")
    conteudo = caminho.read_bytes()
    assert conteudo.startswith(b"%PDF")
    assert len(conteudo) > 3000


def test_gera_docx(resultado, tmp_path):
    from docx import Document

    caminho = rg.salvar_docx(resultado, tmp_path / "r.docx")
    documento = Document(str(caminho))
    texto = "\n".join(p.text for p in documento.paragraphs)
    assert "Limitacoes desta analise" in texto


def test_nome_inclui_prefixo_do_hash(resultado, tmp_path):
    """Evita sobrescrever a analise anterior de um arquivo homonimo."""
    saidas = rg.gerar(resultado, tmp_path, ["md"])
    assert resultado.sha256[:8] in saidas["md"].name


def test_formato_desconhecido_nao_quebra(resultado, tmp_path):
    saidas = rg.gerar(resultado, tmp_path, ["md", "formato_inventado"])
    assert "md" in saidas
    assert "formato_inventado" not in saidas
    assert any("desconhecido" in a for a in resultado.avisos)


def test_falha_de_um_formato_nao_impede_os_outros(resultado, tmp_path, monkeypatch):
    """Falta do ReportLab nao pode impedir a geracao do Markdown."""
    monkeypatch.setitem(
        rg.FORMATOS, "pdf",
        lambda *_a, **_k: (_ for _ in ()).throw(rg.ErroRelatorio("sem reportlab")),
    )
    saidas = rg.gerar(resultado, tmp_path, ["pdf", "md"])
    assert "md" in saidas
    assert "pdf" not in saidas


def test_regra_yara_do_relatorio_compila(resultado, tmp_path):
    """A regra embutida no relatorio precisa ser a regra real e valida."""
    assert resultado.regra_yara.valida
    yara.compile(source=resultado.regra_yara.texto)

    texto = rg.montar_markdown(resultado)
    assert "```yara" in texto
    assert resultado.regra_yara.nome in texto


def test_pipeline_vazio_ainda_gera_relatorio(tmp_path):
    """Resultado sem etapa nenhuma nao pode quebrar o gerador."""
    vazio = ResultadoAnalise(caminho="x.bin")
    texto = rg.montar_markdown(vazio)
    assert "Limitacoes desta analise" in texto
    assert rg.salvar_pdf(vazio, tmp_path / "vazio.pdf").exists()


def test_cancelamento_antes_da_extracao_e_distinguivel(artefato):
    """
    Regressao: cancelar antes da primeira etapa saia pelo caminho de
    "arquivo ilegivel" e devolvia cancelado=False sem erro registrado, o
    que era indistinguivel de uma analise vazia bem-sucedida.
    """
    r = analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False),
        cancelado=lambda: True,
    )
    assert r.extracao is None
    assert r.cancelado is True
    assert r.erros == []  # cancelar nao e erro
    assert any("cancelada antes da extracao" in a for a in r.avisos)
