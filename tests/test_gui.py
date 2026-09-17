"""
Testes da interface grafica.

Rodam em modo offscreen: o Qt renderiza sem abrir janela, entao a suite
funciona em CI e nao rouba o foco de quem esta trabalhando.

O que se testa nao e aparencia, e sim que cada aba se monta sem excecao a
partir de resultados reais - inclusive dos casos degradados, que sao os que
quebram interface na pratica: analise que falhou no meio, resultado vazio,
etapa ausente. Uma aba que levanta excecao com resultado parcial deixaria o
usuario sem ver o que a analise conseguiu produzir.
"""

from __future__ import annotations

import os

import pytest

# Precisa vir antes de qualquer importacao do Qt.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="PySide6 nao instalado")

from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from core.pipeline import OpcoesAnalise, ResultadoAnalise, analisar  # noqa: E402
from gui import views  # noqa: E402
from gui.worker import ExecutorDeAnalise, TrabalhadorDeAnalise  # noqa: E402


@pytest.fixture(scope="session")
def aplicacao():
    """QApplication unica para a sessao: o Qt nao permite duas."""
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def artefato(tmp_path):
    import base64

    conteudo = "\n".join(
        [
            r"Software\Microsoft\Windows\CurrentVersion\Run\Atualizador",
            "vssadmin.exe delete shadows /all /quiet",
            "http://185.220.101.44:8443/gate.php",
            base64.b64encode(b"http://oculto-gui.xyz/a.php").decode(),
            "Mutex_GuiTeste_v1",
            "Seus arquivos foram criptografados",
        ]
    ).encode()
    caminho = tmp_path / "artefato_gui.bin"
    caminho.write_bytes(conteudo)
    return caminho


@pytest.fixture
def resultado(artefato):
    return analisar(
        artefato, OpcoesAnalise(usar_floss=False, usar_stix=False, enriquecer=False)
    )


# ============================================================
# Abas
# ============================================================


@pytest.mark.parametrize("titulo,construtor", views.ABAS, ids=[t for t, _ in views.ABAS])
def test_aba_monta_com_resultado_completo(aplicacao, resultado, titulo, construtor):
    widget = construtor(resultado)
    assert isinstance(widget, QWidget)


@pytest.mark.parametrize("titulo,construtor", views.ABAS, ids=[t for t, _ in views.ABAS])
def test_aba_monta_com_resultado_vazio(aplicacao, titulo, construtor):
    """
    Resultado sem etapa nenhuma. E o estado de uma analise que falhou logo
    no inicio, e nenhuma aba pode quebrar nele.
    """
    widget = construtor(ResultadoAnalise(caminho="nada.bin"))
    assert isinstance(widget, QWidget)


@pytest.mark.parametrize("titulo,construtor", views.ABAS, ids=[t for t, _ in views.ABAS])
def test_aba_monta_com_resultado_parcial(aplicacao, artefato, monkeypatch, titulo, construtor):
    """Analise em que varias etapas falharam."""
    from core import pipeline

    for modulo, funcao in (
        (pipeline.pe_analyzer, "analisar"),
        (pipeline.deobfuscator, "desofuscar"),
        (pipeline.yara_generator, "gerar"),
    ):
        monkeypatch.setattr(
            modulo, funcao,
            lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("falha simulada")),
        )

    parcial = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))
    assert parcial.erros

    assert isinstance(construtor(parcial), QWidget)


def test_aba_limitacoes_sempre_tem_conteudo(aplicacao, resultado):
    """
    A aba de limitacoes nunca fica vazia: interface que so mostra achado
    passa impressao de completude que a analise estatica nao tem.
    """
    from PySide6.QtWidgets import QPlainTextEdit

    widget = views.aba_limitacoes(resultado)
    campos = widget.findChildren(QPlainTextEdit)
    assert campos
    texto = campos[0].toPlainText()
    assert "ESTATICA" in texto
    assert "nao foi executado" in texto


def test_aba_mitre_mostra_a_evidencia(aplicacao, resultado):
    """Nenhuma tecnica pode aparecer sem o que a disparou."""
    from PySide6.QtWidgets import QTreeWidget

    assert resultado.mapeamento.tecnicas

    widget = views.aba_mitre(resultado)
    arvores = widget.findChildren(QTreeWidget)
    assert arvores

    arvore = arvores[0]
    for i in range(arvore.topLevelItemCount()):
        no = arvore.topLevelItem(i)
        filhos = [no.child(j).text(0) for j in range(no.childCount())]
        assert "Evidencia" in filhos, f"tecnica sem evidencia: {no.text(0)}"


def test_aba_enriquecimento_diz_que_nada_saiu(aplicacao, resultado):
    from PySide6.QtWidgets import QLabel

    widget = views.aba_enriquecimento(resultado)
    textos = " ".join(r.text() for r in widget.findChildren(QLabel))
    assert "Nenhum dado deste artefato foi enviado" in textos


def test_aba_atribuicao_traz_a_ressalva(aplicacao, artefato, cache_stix):
    from PySide6.QtWidgets import QLabel

    r = analisar(
        artefato,
        OpcoesAnalise(
            usar_floss=False, usar_stix=True, baixar_stix_se_faltar=False,
            caminho_cache_stix=str(cache_stix),
        ),
    )
    widget = views.aba_atribuicao(r)
    textos = " ".join(x.text() for x in widget.findChildren(QLabel))
    assert "nao e atribuicao" in textos


# ============================================================
# Thread de trabalho
# ============================================================


def test_trabalhador_executa_e_emite_resultado(aplicacao, artefato):
    trabalhador = TrabalhadorDeAnalise(
        artefato, OpcoesAnalise(usar_floss=False, usar_stix=False)
    )

    recebidos = []
    eventos = []
    trabalhador.concluido.connect(recebidos.append)
    trabalhador.progresso.connect(lambda e, m, f: eventos.append((e, f)))

    trabalhador.executar()  # na propria thread, para o teste ser determinista

    assert len(recebidos) == 1
    assert recebidos[0].extracao is not None
    assert eventos
    assert eventos[-1][1] == pytest.approx(1.0)


def test_cancelamento_e_propagado(aplicacao, artefato):
    trabalhador = TrabalhadorDeAnalise(
        artefato, OpcoesAnalise(usar_floss=False, usar_stix=False)
    )
    assert trabalhador.cancelado is False

    trabalhador.cancelar()
    assert trabalhador.cancelado is True

    recebidos = []
    trabalhador.concluido.connect(recebidos.append)
    trabalhador.executar()

    assert recebidos[0].cancelado is True


def test_falha_na_orquestracao_emite_sinal_de_erro(aplicacao, artefato, monkeypatch):
    import gui.worker as worker

    monkeypatch.setattr(
        worker, "analisar",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("explodiu")),
    )

    trabalhador = TrabalhadorDeAnalise(artefato, OpcoesAnalise())
    erros = []
    trabalhador.falhou.connect(erros.append)
    trabalhador.executar()

    assert erros and "explodiu" in erros[0]


def test_executor_recusa_analise_concorrente(aplicacao, artefato):
    executor = ExecutorDeAnalise()
    assert executor.rodando is False

    assert executor.iniciar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))
    # A segunda chamada precisa ser recusada enquanto a primeira roda.
    segunda = executor.iniciar(artefato, OpcoesAnalise())

    executor.aguardar_encerramento()
    assert segunda is False


# ============================================================
# Janela
# ============================================================


def test_janela_abre_e_fecha(aplicacao):
    from gui.app import JanelaPrincipal

    janela = JanelaPrincipal()
    try:
        assert janela.windowTitle().startswith("RabMapper")
        # Sem arquivo selecionado, nao da para analisar.
        assert janela.botao_analisar.isEnabled() is False
        # Enriquecimento comeca desligado, por design.
        assert janela.enriquecer.isChecked() is False
    finally:
        janela.close()


def test_janela_monta_as_abas(aplicacao, resultado):
    from gui.app import JanelaPrincipal

    janela = JanelaPrincipal()
    try:
        janela._ao_concluir(resultado)
        assert janela.abas.count() == len(views.ABAS)
        titulos = [janela.abas.tabText(i) for i in range(janela.abas.count())]
        assert "Limitacoes" in titulos
        assert janela.botao_exportar.isEnabled()
    finally:
        janela.close()


def test_janela_abre_limitacoes_quando_houve_falha(aplicacao, artefato, monkeypatch):
    """Etapa que falhou nao pode passar despercebida."""
    from core import pipeline
    from gui.app import JanelaPrincipal

    monkeypatch.setattr(
        pipeline.pe_analyzer, "analisar",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("falha simulada")),
    )
    parcial = analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))

    janela = JanelaPrincipal()
    try:
        janela._ao_concluir(parcial)
        assert janela.abas.tabText(janela.abas.currentIndex()) == "Limitacoes"
    finally:
        janela.close()


def test_aba_que_quebra_nao_derruba_as_outras(aplicacao, resultado, monkeypatch):
    from gui import app as modulo_app
    from gui.app import JanelaPrincipal

    abas_com_defeito = list(views.ABAS)
    abas_com_defeito[1] = (
        "Defeituosa",
        lambda _r: (_ for _ in ()).throw(RuntimeError("aba quebrada")),
    )
    monkeypatch.setattr(modulo_app, "ABAS", tuple(abas_com_defeito))

    janela = JanelaPrincipal()
    try:
        janela._ao_concluir(resultado)
        assert janela.abas.count() == len(abas_com_defeito)
        titulos = [janela.abas.tabText(i) for i in range(janela.abas.count())]
        assert "Defeituosa (erro)" in titulos
        assert "Resumo" in titulos
    finally:
        janela.close()


def test_janela_expoe_o_formato_do_artefato(aplicacao):
    """
    O suporte a shellcode so serve se a interface deixar escolher. Sao dois
    combos diferentes na janela - formato do artefato e formato do
    relatorio - e trocar um pelo outro passaria despercebido.
    """
    from gui.app import JanelaPrincipal

    janela = JanelaPrincipal()
    try:
        opcoes_de_entrada = [
            janela.formato.itemText(i) for i in range(janela.formato.count())
        ]
        assert opcoes_de_entrada == ["auto", "pe", "sc32", "sc64"]

        opcoes_de_saida = [
            janela.formato_de_saida.itemText(i)
            for i in range(janela.formato_de_saida.count())
        ]
        assert opcoes_de_saida == ["md", "json", "pdf", "docx"]

        janela.formato.setCurrentText("sc64")
        assert janela.formato.currentText() == "sc64"
    finally:
        janela.close()


def test_janela_expoe_o_painel_do_malwarebazaar(aplicacao):
    """
    O painel fica separado do enriquecimento de proposito: baixar amostra
    nao e enriquecer uma analise, e trazer malware para a maquina.
    """
    from gui.app import JanelaPrincipal

    janela = JanelaPrincipal()
    try:
        assert janela.campo_hash_bazaar.text() == ""
        assert janela.botao_consultar_bazaar.isEnabled()
        assert janela.botao_baixar_amostra.isEnabled()
        # O aviso sobre o risco precisa estar visivel, nao escondido em tooltip.
        assert "isolado" in janela.rotulo_bazaar.text()
    finally:
        janela.close()


def test_download_exige_hash(aplicacao, monkeypatch):
    """Sem hash, nao pode nem chegar a pedir confirmacao de download."""
    from PySide6.QtWidgets import QMessageBox

    from gui.app import JanelaPrincipal

    avisos = []
    monkeypatch.setattr(
        QMessageBox, "information", lambda *a, **k: avisos.append(a[1:3])
    )
    monkeypatch.setattr(
        QMessageBox, "warning",
        lambda *a, **k: pytest.fail("nao deveria pedir confirmacao sem hash"),
    )

    janela = JanelaPrincipal()
    try:
        janela.campo_hash_bazaar.setText("   ")
        janela._baixar_amostra()
        assert avisos
    finally:
        janela.close()


def test_download_cancelado_nao_cria_cliente(aplicacao, monkeypatch):
    """Recusar a confirmacao precisa abortar antes de qualquer requisicao."""
    from PySide6.QtWidgets import QMessageBox

    from gui.app import JanelaPrincipal

    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.No)

    janela = JanelaPrincipal()
    try:
        monkeypatch.setattr(
            janela, "_cliente_bazaar",
            lambda: pytest.fail("nao deveria criar cliente apos cancelar"),
        )
        janela.campo_hash_bazaar.setText("a" * 64)
        janela._baixar_amostra()
    finally:
        janela.close()


# ============================================================
# Apresentacao: bugs que so apareceram rodando numa tela
# ============================================================


def test_e_comercial_nao_e_engolido_pelo_mnemonico(aplicacao):
    """
    Regressao: o Qt trata "&" como atalho de teclado em widget com
    mnemonico, entao "ATT&CK" era exibido como "ATTCK" com o C sublinhado.
    O texto precisa escapar o "&" duplicando-o.
    """
    from gui.app import JanelaPrincipal

    janela = JanelaPrincipal()
    try:
        # O texto cru guarda "&&"; o Qt exibe "&".
        assert "ATT&&CK" in janela.usar_stix.text()

        acoes = [
            a.text()
            for menu in janela.menuBar().findChildren(type(janela.menuBar()))
            for a in menu.actions()
        ]
        acoes += [a.text() for a in janela.menuBar().actions()]
        for texto in acoes:
            if "ATT" in texto and "CK" in texto:
                assert "&&" in texto, f"mnemonico nao escapado: {texto!r}"
    finally:
        janela.close()


def test_titulo_da_aba_escapa_o_e_comercial():
    """Titulo de aba tambem passa pelo processamento de mnemonico."""
    titulos = [t for t, _ in views.ABAS]
    for titulo in titulos:
        if "ATT" in titulo:
            assert titulo == "ATT&&CK"


def test_painel_de_opcoes_e_rolavel(aplicacao):
    """
    Regressao: o painel e mais alto do que cabe numa tela de notebook, e
    sem area rolavel os controles de baixo sumiam sem nenhum indicio.
    """
    from PySide6.QtWidgets import QScrollArea

    from gui.app import JanelaPrincipal

    janela = JanelaPrincipal()
    try:
        rolagens = janela.findChildren(QScrollArea)
        assert rolagens, "o painel de opcoes precisa estar numa area rolavel"
        assert rolagens[0].widgetResizable() is True
    finally:
        janela.close()


def test_cores_seguem_o_tema(aplicacao, monkeypatch):
    """
    Cor fixa clara some no tema escuro do Windows, e vice-versa. O
    vermelho #c0392b, por exemplo, quase desaparece sobre preto.
    """
    from core.string_extractor import Confianca

    monkeypatch.setattr(views, "tema_escuro", lambda: False)
    claro = views.cor_confianca(Confianca.ALTA)
    cinza_claro = views.cor_secundaria()

    monkeypatch.setattr(views, "tema_escuro", lambda: True)
    escuro = views.cor_confianca(Confianca.ALTA)
    cinza_escuro = views.cor_secundaria()

    assert claro != escuro
    assert cinza_claro != cinza_escuro
    # No escuro o texto precisa ser mais claro para ter contraste.
    assert escuro.lightness() > claro.lightness()


def test_fundo_de_nota_e_translucido():
    """Cinza translucido escurece fundo claro e clareia fundo escuro."""
    assert views.fundo_de_nota().startswith("rgba(")


def test_paletas_mantem_contraste_de_texto(aplicacao):
    """
    Tema cyberpunk nao pode custar legibilidade. O texto principal precisa
    contrastar com o fundo nos dois temas - neon bonito e ilegivel nao
    serve para uma ferramenta que se le por horas.
    """
    from gui.estilo import CLARO, ESCURO

    for nome, p in (("escuro", ESCURO), ("claro", CLARO)):
        fundo = views.QColor(p.fundo).lightness()
        texto = views.QColor(p.texto).lightness()
        assert abs(texto - fundo) > 120, f"contraste fraco no tema {nome}"


def test_niveis_de_confianca_sao_distinguiveis(aplicacao):
    """
    Alta, media e baixa precisam diferir em LUMINOSIDADE, nao so em matiz -
    caso contrario quem nao distingue vermelho de verde perde a informacao.
    """
    from gui.estilo import ESCURO

    luzes = sorted(
        views.QColor(c).lightness() for c in (ESCURO.alta, ESCURO.media, ESCURO.baixa)
    )
    for anterior, seguinte in zip(luzes, luzes[1:]):
        assert seguinte - anterior > 15, "niveis de confianca perto demais"
