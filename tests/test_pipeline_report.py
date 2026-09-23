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


# ============================================================
# CVSS automatico a partir de CVE citada
# ============================================================


@pytest.fixture
def artefato_com_cve(tmp_path):
    caminho = tmp_path / "exploit.bin"
    caminho.write_bytes(
        b"Exploit para CVE-2021-44228\ntambem tenta CVE-2017-0144\n"
    )
    return caminho


class _NVDFalso:
    """Duble do client da NVD, com vetores reais de CVEs conhecidas."""

    VETORES = {
        "CVE-2021-44228": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        "CVE-2017-0144": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    }

    def __init__(self):
        self.consultadas = []

    def consultar(self, cve):
        from enrichment.nvd_client import ResultadoNVD

        self.consultadas.append(cve)
        r = ResultadoNVD(cve=cve, consultado=True)
        if cve in self.VETORES:
            r.encontrado = True
            r.vetor, r.score_base = self.VETORES[cve]
            r.versao_cvss = "3.1"
        return r

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_cve_citada_preenche_o_cvss_sozinha(artefato_com_cve, monkeypatch):
    """
    CVSS descreve uma vulnerabilidade, nao um artefato - nao ha como
    derivar um vetor de um binario. O que da para fazer e notar que o
    artefato REFERENCIA uma CVE e buscar o vetor oficial dela.
    """
    from enrichment import nvd_client

    falso = _NVDFalso()
    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: falso)

    r = analisar(
        artefato_com_cve,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True),
    )

    assert r.cvss is not None
    assert r.cvss.score_base == pytest.approx(10.0)
    assert r.cvss.cve == "CVE-2021-44228"


def test_entre_varias_cves_vale_a_mais_severa(artefato_com_cve, monkeypatch):
    """A mais severa define o pior caso, que e o que o relatorio destaca."""
    from enrichment import nvd_client

    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: _NVDFalso())

    r = analisar(
        artefato_com_cve,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True),
    )

    assert r.cvss.cve == "CVE-2021-44228"  # 10.0, e nao a de 8.8
    assert any("mais severa" in a for a in r.avisos)
    # As duas continuam registradas.
    assert len(r.nvd) == 2


def test_vetor_informado_pelo_analista_tem_precedencia(artefato_com_cve, monkeypatch):
    """
    Se o analista digitou um vetor, e porque sabe algo que a ferramenta nao
    sabe. Sobrescrever seria arrogancia da ferramenta.
    """
    from enrichment import nvd_client

    monkeypatch.setattr(
        nvd_client, "criar",
        lambda *_a, **_k: pytest.fail("NVD nao deveria ser consultada"),
    )

    r = analisar(
        artefato_com_cve,
        OpcoesAnalise(
            usar_floss=False, usar_stix=False, enriquecer=True,
            vetor_cvss="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
        ),
    )
    assert r.cvss.score_base < 5.0  # o vetor manual, nao o 10.0 da NVD


def test_sem_enriquecimento_nao_consulta_a_nvd(artefato_com_cve, monkeypatch):
    from enrichment import nvd_client

    monkeypatch.setattr(
        nvd_client, "criar",
        lambda *_a, **_k: pytest.fail("NVD nao deveria ser consultada"),
    )

    r = analisar(artefato_com_cve, OpcoesAnalise(usar_floss=False, usar_stix=False))
    assert r.cvss is None
    assert r.nvd == []


def test_artefato_sem_cve_nao_gera_consulta(artefato, monkeypatch):
    from enrichment import nvd_client

    falso = _NVDFalso()
    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: falso)

    analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True))
    assert falso.consultadas == []


def test_score_da_nvd_vem_com_a_ressalva(artefato_com_cve, monkeypatch):
    """
    O numero 10.0 no topo de um relatorio seria lido como "este arquivo e
    critico". Ele descreve a falha citada, nao o artefato.
    """
    from enrichment import nvd_client

    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: _NVDFalso())

    r = analisar(
        artefato_com_cve,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True),
    )
    assert any("nao este arquivo" in a for a in r.cvss.avisos)

    texto = rg.montar_markdown(r)
    assert "apenas REFERENCIA" in texto


def test_ressalva_da_nvd_sai_sem_chave_de_api(artefato_com_cve, monkeypatch):
    """
    A NVD nao exige chave, entao e comum ser a UNICA fonte com resultado.

    A secao de enriquecimento era descartada quando VirusTotal e Shodan
    vinham vazios, e levava junto a ressalva de que o score descreve a
    vulnerabilidade citada e nao o artefato. O relatorio saia com "10.0" em
    destaque e sem nada explicando o numero - exatamente para quem nao tem
    chave nenhuma configurada, que e o caso mais comum.
    """
    from enrichment import nvd_client

    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: _NVDFalso())

    r = analisar(
        artefato_com_cve,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True),
    )

    # A condicao do teste: nenhuma fonte com chave respondeu.
    assert r.virustotal == []
    assert r.shodan == []
    assert r.nvd, "a NVD deveria ter respondido mesmo sem chave"

    texto = rg.montar_markdown(r)
    assert "NVD (vulnerabilidades" in texto
    assert "apenas REFERENCIA" in texto
    # O score aparece; e justamente por isso que a ressalva precisa estar.
    assert "10.0" in texto


# ============================================================
# CVE informada pelo analista
# ============================================================


def test_cve_informada_sem_vetor_busca_na_nvd(artefato, monkeypatch):
    """
    O campo de CVE da tela existia e nao fazia nada quando vinha sem
    vetor: o pipeline so consultava as CVEs citadas nas strings.
    """
    from enrichment import nvd_client

    falso = _NVDFalso()
    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: falso)

    r = analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True, cve="CVE-2021-44228"),
    )
    assert falso.consultadas == ["CVE-2021-44228"]
    assert r.cvss is not None
    assert r.cvss.cve == "CVE-2021-44228"
    assert any("informada pelo analista" in a for a in r.cvss.avisos)


def test_cve_informada_vence_a_citada_mesmo_com_score_menor(tmp_path, monkeypatch):
    """
    O analista sabe, por fonte externa, qual falha a amostra explora. Uma
    referencia solta nas strings nao pode passar por cima disso so por ter
    score maior.
    """
    from enrichment import nvd_client

    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: _NVDFalso())
    amostra = tmp_path / "cita.bin"
    amostra.write_bytes(b"Exploit para CVE-2021-44228\n")

    r = analisar(
        amostra,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True, cve="cve-2017-0144"),
    )
    assert r.cvss.cve == "CVE-2017-0144"
    assert r.cvss.score_base == 8.8


def test_cve_informada_sem_consulta_externa_avisa(artefato, monkeypatch):
    """Sem vetor e sem NVD nao ha score, e isso precisa ser dito."""
    from enrichment import nvd_client

    monkeypatch.setattr(
        nvd_client, "criar", lambda *_a, **_k: pytest.fail("NVD nao deveria ser consultada")
    )
    r = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False, cve="CVE-2021-44228"))
    assert r.cvss is None
    assert any("score nao foi calculado" in a for a in r.avisos)


def test_cve_informada_com_formato_errado_e_ignorada_com_aviso(artefato, monkeypatch):
    from enrichment import nvd_client

    falso = _NVDFalso()
    monkeypatch.setattr(nvd_client, "criar", lambda *_a, **_k: falso)
    r = analisar(
        artefato,
        OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=True, cve="log4shell"),
    )
    assert falso.consultadas == []
    assert any("formato" in a for a in r.avisos)
