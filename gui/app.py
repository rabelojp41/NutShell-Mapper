"""
Janela principal do RabMapper.

A interface e um analisador, nao um scanner: um artefato entra, e o
resultado sai distribuido em abas de evidencia. Nao ha lista de alvos nem
varredura em lote, porque analise de artefato nao funciona assim.

Duas decisoes de interface que refletem decisoes do framework:

  1. O enriquecimento externo comeca desligado e, quando ligado, abre uma
     confirmacao explicando o que sera enviado a terceiros. Consultar o
     VirusTotal revela quais hashes voce esta investigando, e isso nao pode
     ser efeito colateral de clicar em "Analisar".

  2. A aba "Limitacoes" existe sempre, mesmo quando tudo deu certo.
     Interface que so mostra achado passa impressao de completude que a
     analise estatica nao tem.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.pipeline import OpcoesAnalise
from gui.estilo import (
    AVISO,
    BOTAO_PERIGO,
    BOTAO_PRIMARIO,
    CABECALHO_SECAO,
    ESPACO,
    NOTA,
    RAIO,
    SUBTITULO,
    TITULO,
    paleta,
)
from gui.views import ABAS
from gui.worker import ExecutorDeAnalise

logger = logging.getLogger(__name__)


def _cinza() -> str:
    """Cinza de texto secundario adequado ao tema em vigor."""
    from gui.views import cor_secundaria

    return cor_secundaria()


def _centralizado(widget: QWidget) -> QHBoxLayout:
    """
    Centraliza um widget de largura limitada.

    Alinhamento central do QLabel centraliza o texto dentro do rotulo, mas
    o rotulo continua ocupando a largura toda. Para respeitar o
    setMaximumWidth e preciso o estica-dos-lados.
    """
    linha = QHBoxLayout()
    linha.addStretch(1)
    linha.addWidget(widget)
    linha.addStretch(1)
    return linha


class AreaDeArquivo(QLabel):
    """Area que aceita arquivo arrastado."""

    def __init__(self, ao_receber):
        super().__init__()
        self._ao_receber = ao_receber
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumHeight(64)
        self._limpar()

    def _limpar(self) -> None:
        p = paleta()
        self.setText("Arraste um artefato aqui\nou use Abrir")
        self.setStyleSheet(
            f"QLabel {{ border: 2px dashed {p.borda}; border-radius: {RAIO}px;"
            f" color: {p.texto_apagado}; background: {p.superficie};"
            f" padding: 16px; }}"
        )

    def mostrar_arquivo(self, caminho: Path) -> None:
        p = paleta()
        tamanho = caminho.stat().st_size if caminho.is_file() else 0
        self.setText(
            f"<b>{caminho.name}</b><br>"
            f"<span style='font-size:11px'>{tamanho:,} bytes</span>"
        )
        # O caminho completo cabe melhor na dica do que na caixa.
        self.setToolTip(str(caminho))

        # Fundo translucido funciona sobre claro e sobre escuro; azul-claro
        # fixo ficaria ilegivel no tema escuro.
        self.setStyleSheet(
            f"QLabel {{ border: 2px solid {p.destaque}; border-radius: {RAIO}px;"
            f" background: {p.destaque_fraco}; color: {p.texto};"
            f" padding: 16px; }}"
        )

    # --- Arrastar e soltar ---

    def dragEnterEvent(self, evento):
        if evento.mimeData().hasUrls():
            evento.acceptProposedAction()

    def dropEvent(self, evento):
        for url in evento.mimeData().urls():
            caminho = Path(url.toLocalFile())
            if caminho.is_file():
                self._ao_receber(caminho)
                evento.acceptProposedAction()
                return


class JanelaPrincipal(QMainWindow):
    """Janela principal."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("RabMapper — analise de artefatos")
        self.resize(1200, 800)

        self._arquivo: Path | None = None
        self._resultado = None
        self._executor = ExecutorDeAnalise(self)

        self._executor.progresso.connect(self._ao_progredir)
        self._executor.concluido.connect(self._ao_concluir)
        self._executor.falhou.connect(self._ao_falhar)

        self._montar()
        self._montar_menu()
        self._atualizar_estado()

    # ============================================================
    # Montagem
    # ============================================================

    def _montar(self) -> None:
        divisor = QSplitter(Qt.Horizontal)

        # O painel de opcoes e mais alto do que cabe numa tela de notebook.
        # Sem area rolavel, os controles de baixo - exportar relatorio,
        # salvar YARA - simplesmente somem, sem nenhum indicio de que
        # existem.
        painel = self._painel_esquerdo()
        rolagem = QScrollArea()
        rolagem.setWidget(painel)
        rolagem.setWidgetResizable(True)
        rolagem.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        divisor.addWidget(rolagem)

        # A largura vem do que o painel realmente pede, e nao de um numero
        # fixo. Fonte de sistema maior, outro idioma ou tema com mais
        # espacamento mudam essa necessidade - e como nao ha barra
        # horizontal, o que nao cabe some sem deixar rastro.
        self._largura_do_painel = max(340, min(painel.sizeHint().width() + 28, 460))
        rolagem.setMinimumWidth(self._largura_do_painel)

        self.abas = QTabWidget()
        self.abas.addTab(
            self._mensagem_inicial(), "Bem-vindo"
        )
        divisor.addWidget(self.abas)

        divisor.setStretchFactor(0, 0)
        divisor.setStretchFactor(1, 1)
        divisor.setSizes([self._largura_do_painel, 1200 - self._largura_do_painel])

        self.setCentralWidget(divisor)
        self.statusBar().showMessage("Pronto")

    def _mensagem_inicial(self) -> QWidget:
        """
        Tela inicial.

        Em vez de um paragrafo solto, lista o que o pipeline faz: quem abre
        a ferramenta pela primeira vez descobre o escopo sem precisar rodar
        uma analise para adivinhar.
        """
        pagina = QWidget()
        layout = QVBoxLayout(pagina)
        layout.setContentsMargins(48, 40, 48, 40)
        layout.setSpacing(ESPACO["md"])
        layout.addStretch(1)

        titulo = QLabel("RabMapper")
        titulo.setObjectName(TITULO)
        titulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(titulo)

        subtitulo = QLabel("Analise estatica de artefatos e threat intelligence")
        subtitulo.setObjectName(SUBTITULO)
        subtitulo.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitulo)

        layout.addSpacing(ESPACO["xl"])

        cabecalho = QLabel("O QUE A ANALISE FAZ")
        cabecalho.setObjectName(CABECALHO_SECAO)
        cabecalho.setAlignment(Qt.AlignCenter)
        layout.addWidget(cabecalho)

        descricao = QLabel(
            "Extrai strings com emulacao  •  reverte ofuscacao  •  "
            "identifica indicadores<br>"
            "gera e valida regra YARA  •  mapeia tecnicas MITRE ATT&amp;CK<br>"
            "monta a Cyber Kill Chain  •  cruza com grupos conhecidos<br>"
            "consulta fontes externas  •  exporta o relatorio"
        )
        descricao.setAlignment(Qt.AlignCenter)
        descricao.setWordWrap(True)
        # Linha longa cansa a leitura; 620px e a faixa confortavel.
        descricao.setMaximumWidth(620)
        descricao.setStyleSheet(f"QLabel {{ color: {_cinza()}; line-height: 175%; }}")
        layout.addLayout(_centralizado(descricao))

        layout.addSpacing(ESPACO["xl"])

        instrucao = QLabel(
            "Selecione um arquivo no painel a esquerda e clique em "
            "<b>Analisar artefato</b>."
        )
        instrucao.setAlignment(Qt.AlignCenter)
        layout.addWidget(instrucao)

        layout.addSpacing(ESPACO["md"])

        ressalva = QLabel(
            "O artefato nunca e executado — a analise e inteiramente "
            "estatica. Ainda assim, manipule amostras reais apenas em "
            "maquina virtual isolada, com snapshot."
        )
        ressalva.setObjectName(NOTA)
        ressalva.setWordWrap(True)
        ressalva.setMaximumWidth(620)
        layout.addLayout(_centralizado(ressalva))

        layout.addStretch(2)
        return pagina

    def _painel_esquerdo(self) -> QWidget:
        painel = QWidget()
        layout = QVBoxLayout(painel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(ESPACO["sm"])

        # --- Arquivo ---
        self.area_arquivo = AreaDeArquivo(self._definir_arquivo)
        layout.addWidget(self.area_arquivo)

        linha = QHBoxLayout()
        self.botao_abrir = QPushButton("Abrir...")
        self.botao_abrir.clicked.connect(self._escolher_arquivo)
        linha.addWidget(self.botao_abrir)
        layout.addLayout(linha)

        # --- Opcoes de analise ---
        grupo = QGroupBox("Analise")
        formulario = QFormLayout(grupo)

        self.usar_floss = QCheckBox("Usar FLOSS")
        self.usar_floss.setChecked(True)
        self.usar_floss.setToolTip(
            "Recupera strings montadas em runtime: stack, tight e decoded.\n"
            "Sem ele, so as strings literais do arquivo sao vistas."
        )
        formulario.addRow(self.usar_floss)

        self.gerar_yara = QCheckBox("Gerar regra YARA")
        self.gerar_yara.setChecked(True)
        formulario.addRow(self.gerar_yara)

        self.usar_stix = QCheckBox("STIX oficial do ATT&&CK")
        self.usar_stix.setChecked(True)
        self.usar_stix.setToolTip(
            "Baixa o bundle oficial (~45 MB) na primeira vez.\n"
            "Sem ele, o mapeamento usa o catalogo local e nao ha\n"
            "atribuicao de grupo."
        )
        formulario.addRow(self.usar_stix)

        self.formato = QComboBox()
        self.formato.addItems(["auto", "pe", "sc32", "sc64"])
        self.formato.setToolTip(
            "auto: detecta PE pelo cabecalho; artefato sem cabecalho e "
            "tentado como shellcode de 32 e de 64 bits. "
            "Use sc32/sc64 para forcar a arquitetura de um shellcode."
        )
        formulario.addRow("Formato:", self.formato)

        self.min_string = QSpinBox()
        self.min_string.setRange(3, 64)
        self.min_string.setValue(4)
        formulario.addRow("String minima:", self.min_string)

        layout.addWidget(grupo)

        # --- CVSS ---
        grupo_cvss = QGroupBox("CVSS (opcional)")
        formulario_cvss = QFormLayout(grupo_cvss)
        self.campo_cve = QLineEdit()
        self.campo_cve.setPlaceholderText("CVE-2021-44228")
        self.campo_cvss = QLineEdit()
        self.campo_cvss.setPlaceholderText("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        formulario_cvss.addRow("CVE:", self.campo_cve)
        formulario_cvss.addRow("Vetor:", self.campo_cvss)
        layout.addWidget(grupo_cvss)

        # --- Enriquecimento ---
        grupo_rede = QGroupBox("Enriquecimento externo")
        layout_rede = QVBoxLayout(grupo_rede)

        self.enriquecer = QCheckBox("Consultar fontes externas")
        self.enriquecer.setChecked(False)
        self.enriquecer.toggled.connect(self._confirmar_enriquecimento)
        layout_rede.addWidget(self.enriquecer)

        self.rotulo_chaves = QLabel()
        self.rotulo_chaves.setWordWrap(True)
        self.rotulo_chaves.setStyleSheet(
            f"QLabel {{ color: {_cinza()}; font-size: 11px; }}"
        )
        layout_rede.addWidget(self.rotulo_chaves)
        self._atualizar_rotulo_de_chaves()

        layout.addWidget(grupo_rede)

        # --- Resumo por IA ---
        #
        # Grupo separado do enriquecimento de proposito: o Ollama roda em
        # localhost e NAO envia nada para fora, ao contrario do VirusTotal
        # e do Shodan. Junta-los sugeriria que compartilham o mesmo risco.
        grupo_ia = QGroupBox("Leitura assistida por IA")
        layout_ia = QVBoxLayout(grupo_ia)

        self.resumo_ia = QCheckBox("Gerar resumo com LLM local")
        self.resumo_ia.setChecked(False)
        self.resumo_ia.setToolTip(
            """Escreve um resumo executivo a partir dos achados, usando o Ollama.

Roda inteiramente em localhost: nenhum dado sai desta maquina.
Toda afirmacao do texto e conferida contra os achados, e o que o
modelo inventar aparece sinalizado."""
        )
        layout_ia.addWidget(self.resumo_ia)

        self.campo_modelo_ia = QLineEdit("llama3.1:8b")
        self.campo_modelo_ia.setPlaceholderText("modelo do Ollama")
        layout_ia.addWidget(self.campo_modelo_ia)

        rotulo_ia = QLabel(
            "Local, via Ollama. A primeira geracao carrega o modelo e pode "
            "levar alguns minutos."
        )
        rotulo_ia.setWordWrap(True)
        rotulo_ia.setStyleSheet(
            f"QLabel {{ color: {_cinza()}; font-size: 11px; }}"
        )
        layout_ia.addWidget(rotulo_ia)

        layout.addWidget(grupo_ia)

        # --- MalwareBazaar ---
        #
        # Fica num grupo proprio, e nao junto do enriquecimento, porque
        # baixar amostra nao e enriquecer uma analise: e trazer malware
        # para a maquina. Separar deixa claro que sao acoes de naturezas
        # diferentes.
        grupo_bazaar = QGroupBox("MalwareBazaar")
        layout_bazaar = QVBoxLayout(grupo_bazaar)

        self.campo_hash_bazaar = QLineEdit()
        self.campo_hash_bazaar.setPlaceholderText("SHA256 da amostra")
        self.campo_hash_bazaar.setToolTip(
            "Hash a consultar no MalwareBazaar. O download exige SHA256; "
            "a consulta aceita MD5, SHA1 ou SHA256."
        )
        layout_bazaar.addWidget(self.campo_hash_bazaar)

        self.botao_consultar_bazaar = QPushButton("Consultar hash")
        self.botao_consultar_bazaar.clicked.connect(self._consultar_bazaar)
        layout_bazaar.addWidget(self.botao_consultar_bazaar)

        self.botao_baixar_amostra = QPushButton("Baixar amostra (ZIP cifrado)")
        self.botao_baixar_amostra.setObjectName(BOTAO_PERIGO)
        self.botao_baixar_amostra.clicked.connect(self._baixar_amostra)
        layout_bazaar.addWidget(self.botao_baixar_amostra)

        self.rotulo_bazaar = QLabel(
            "Baixar traz malware para esta maquina. Use apenas em ambiente "
            "isolado."
        )
        self.rotulo_bazaar.setWordWrap(True)
        self.rotulo_bazaar.setObjectName(AVISO)
        layout_bazaar.addWidget(self.rotulo_bazaar)

        layout.addWidget(grupo_bazaar)

        # --- Acao ---
        self.botao_analisar = QPushButton("Analisar artefato")
        self.botao_analisar.setObjectName(BOTAO_PRIMARIO)
        self.botao_analisar.setMinimumHeight(40)
        self.botao_analisar.clicked.connect(self._analisar)
        layout.addWidget(self.botao_analisar)

        self.botao_cancelar = QPushButton("Cancelar")
        self.botao_cancelar.clicked.connect(self._cancelar)
        layout.addWidget(self.botao_cancelar)

        self.progresso = QProgressBar()
        self.progresso.setRange(0, 100)
        layout.addWidget(self.progresso)

        self.rotulo_etapa = QLabel("")
        self.rotulo_etapa.setWordWrap(True)
        self.rotulo_etapa.setStyleSheet(
            f"QLabel {{ color: {_cinza()}; font-size: 11px; }}"
        )
        layout.addWidget(self.rotulo_etapa)

        # --- Exportacao ---
        grupo_saida = QGroupBox("Relatorio")
        layout_saida = QVBoxLayout(grupo_saida)

        self.formato_de_saida = QComboBox()
        self.formato_de_saida.addItems(["md", "json", "pdf", "docx"])
        layout_saida.addWidget(self.formato_de_saida)

        self.botao_exportar = QPushButton("Exportar relatorio...")
        self.botao_exportar.clicked.connect(self._exportar_relatorio)
        layout_saida.addWidget(self.botao_exportar)

        self.botao_salvar_yara = QPushButton("Salvar regra YARA...")
        self.botao_salvar_yara.clicked.connect(self._salvar_yara)
        layout_saida.addWidget(self.botao_salvar_yara)

        self.botao_exportar_iocs = QPushButton("Exportar indicadores...")
        self.botao_exportar_iocs.setToolTip(
            """Exporta os indicadores em CSV, STIX 2.1 e MISP, para alimentar
SIEM, plataforma de compartilhamento ou lista de bloqueio.

So confianca alta e media sao exportadas: as de baixa existem para o
analista julgar, e alimentariam bloqueio automatico com ruido."""
        )
        self.botao_exportar_iocs.clicked.connect(self._exportar_iocs)
        layout_saida.addWidget(self.botao_exportar_iocs)

        layout.addWidget(grupo_saida)
        layout.addStretch()

        return painel

    def _montar_menu(self) -> None:
        arquivo = self.menuBar().addMenu("&Arquivo")

        acao = QAction("&Abrir artefato...", self)
        acao.setShortcut("Ctrl+O")
        acao.triggered.connect(self._escolher_arquivo)
        arquivo.addAction(acao)

        acao = QAction("&Exportar relatorio...", self)
        acao.setShortcut("Ctrl+S")
        acao.triggered.connect(self._exportar_relatorio)
        arquivo.addAction(acao)

        arquivo.addSeparator()
        acao = QAction("Sai&r", self)
        acao.setShortcut("Ctrl+Q")
        acao.triggered.connect(self.close)
        arquivo.addAction(acao)

        ferramentas = self.menuBar().addMenu("&Ferramentas")

        acao = QAction("Atualizar o MITRE ATT&&CK", self)
        acao.triggered.connect(self._atualizar_attack)
        ferramentas.addAction(acao)

        acao = QAction("Ver configuracao", self)
        acao.triggered.connect(self._mostrar_configuracao)
        ferramentas.addAction(acao)

        ajuda = self.menuBar().addMenu("A&juda")
        acao = QAction("Sobre", self)
        acao.triggered.connect(self._sobre)
        ajuda.addAction(acao)

    # ============================================================
    # Estado
    # ============================================================

    def _atualizar_estado(self) -> None:
        rodando = self._executor.rodando
        tem_arquivo = self._arquivo is not None
        tem_resultado = self._resultado is not None

        self.botao_analisar.setEnabled(tem_arquivo and not rodando)
        self.botao_cancelar.setEnabled(rodando)
        self.botao_abrir.setEnabled(not rodando)
        self.botao_exportar.setEnabled(tem_resultado and not rodando)
        self.botao_exportar_iocs.setEnabled(
            tem_resultado and bool(self._resultado.iocs) and not rodando
        )
        self.botao_salvar_yara.setEnabled(
            tem_resultado
            and self._resultado.regra_yara is not None
            and not rodando
        )

    def _atualizar_rotulo_de_chaves(self) -> None:
        from config.settings import CONFIG

        disponiveis = []
        if CONFIG.virustotal_api_key:
            disponiveis.append("VirusTotal")
        if CONFIG.shodan_api_key:
            disponiveis.append("Shodan")

        if disponiveis:
            self.rotulo_chaves.setText(f"Chaves configuradas: {', '.join(disponiveis)}")
        else:
            self.rotulo_chaves.setText(
                "Nenhuma chave configurada em config/.env. "
                "As consultas externas serao puladas."
            )

    def _definir_arquivo(self, caminho: Path) -> None:
        self._arquivo = caminho
        self.area_arquivo.mostrar_arquivo(caminho)
        self.statusBar().showMessage(f"Selecionado: {caminho}")
        self._atualizar_estado()

    def _escolher_arquivo(self) -> None:
        caminho, _ = QFileDialog.getOpenFileName(
            self, "Selecionar artefato", "", "Todos os arquivos (*)"
        )
        if caminho:
            self._definir_arquivo(Path(caminho))

    def _confirmar_enriquecimento(self, marcado: bool) -> None:
        """
        Confirma antes de habilitar a consulta externa.

        Enviar hash ao VirusTotal revela a terceiros o que esta sendo
        investigado, e isso nao pode acontecer por descuido.
        """
        if not marcado:
            return

        resposta = QMessageBox.question(
            self,
            "Confirmar enriquecimento externo",
            "Os hashes e indicadores deste artefato serao enviados ao "
            "VirusTotal e ao Shodan.\n\n"
            "Quem opera esses servicos vera quais indicadores voce esta "
            "investigando e quando. Em investigacao sensivel, isso pode "
            "sinalizar ao adversario que ele foi detectado.\n\n"
            "O arquivo em si NAO e enviado — apenas o hash.\n\n"
            "Continuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resposta != QMessageBox.Yes:
            self.enriquecer.setChecked(False)

    # ============================================================
    # Analise
    # ============================================================

    def _analisar(self) -> None:
        if self._arquivo is None:
            return

        opcoes = OpcoesAnalise(
            usar_floss=self.usar_floss.isChecked(),
            formato=self.formato.currentText(),
            tamanho_minimo_de_string=self.min_string.value(),
            gerar_yara=self.gerar_yara.isChecked(),
            usar_stix=self.usar_stix.isChecked(),
            vetor_cvss=self.campo_cvss.text().strip(),
            cve=self.campo_cve.text().strip(),
            enriquecer=self.enriquecer.isChecked(),
            resumo_ia=self.resumo_ia.isChecked(),
            modelo_ia=self.campo_modelo_ia.text().strip() or "llama3.1:8b",
        )

        self.progresso.setValue(0)
        self.abas.clear()
        self._resultado = None

        if not self._executor.iniciar(self._arquivo, opcoes):
            return

        self.statusBar().showMessage("Analisando...")
        self._atualizar_estado()

    def _cancelar(self) -> None:
        self._executor.cancelar()
        self.statusBar().showMessage(
            "Cancelando... a etapa em andamento termina antes de parar."
        )

    def _ao_progredir(self, estagio: str, mensagem: str, fracao: float) -> None:
        self.progresso.setValue(int(fracao * 100))
        self.rotulo_etapa.setText(mensagem or estagio)

    def _ao_concluir(self, resultado) -> None:
        self._resultado = resultado
        self.progresso.setValue(100)
        self.rotulo_etapa.setText("")

        self.abas.clear()
        for titulo, construtor in ABAS:
            try:
                self.abas.addTab(construtor(resultado), titulo)
            except Exception as erro:
                # Uma aba que quebra nao pode custar as outras.
                logger.exception("falha ao montar a aba %s", titulo)
                rotulo = QLabel(f"Falha ao montar esta aba: {erro}")
                rotulo.setWordWrap(True)
                self.abas.addTab(rotulo, f"{titulo} (erro)")

        resumo = resultado.resumo()
        estado = "cancelada" if resultado.cancelado else "concluida"
        self.statusBar().showMessage(
            f"Analise {estado} em {resumo['duracao']}s — "
            f"{resumo['iocs']} IOCs, {resumo['tecnicas']} tecnicas, "
            f"{len(resultado.erros)} falha(s) de etapa"
        )

        if resultado.erros:
            # Etapa que falhou nao pode passar despercebida.
            self.abas.setCurrentIndex(len(ABAS) - 1)

        self._atualizar_estado()

    def _ao_falhar(self, mensagem: str) -> None:
        self.progresso.setValue(0)
        self.rotulo_etapa.setText("")
        self.statusBar().showMessage("A analise falhou")
        QMessageBox.critical(self, "Falha na analise", mensagem)
        self._atualizar_estado()

    # ============================================================
    # Exportacao
    # ============================================================

    def _exportar_relatorio(self) -> None:
        if self._resultado is None:
            return

        formato = self.formato_de_saida.currentText()
        sugestao = (
            f"{Path(self._resultado.caminho).stem}_"
            f"{self._resultado.sha256[:8]}.{formato}"
        )

        caminho, _ = QFileDialog.getSaveFileName(
            self, "Salvar relatorio", sugestao, f"{formato.upper()} (*.{formato})"
        )
        if not caminho:
            return

        from reports import report_generator

        funcao = report_generator.FORMATOS[formato]
        try:
            destino = funcao(self._resultado, caminho)
        except Exception as erro:
            QMessageBox.critical(self, "Falha ao exportar", str(erro))
            return

        self.statusBar().showMessage(f"Relatorio salvo em {destino}")
        self._perguntar_se_abre(destino)

    def _exportar_iocs(self) -> None:
        """
        Exporta os indicadores para alimentar SIEM, MISP ou bloqueio.

        Grava os tres formatos de uma vez: sao pequenos, e adivinhar qual
        o analista vai precisar custaria mais um dialogo.
        """
        if self._resultado is None:
            return

        from core.string_extractor import Confianca
        from reports import ioc_export

        destino = QFileDialog.getExistingDirectory(
            self, "Onde salvar os indicadores", str(Path(self._resultado.caminho).parent)
        )
        if not destino:
            return

        saidas = ioc_export.exportar(
            self._resultado,
            destino,
            ["csv", "stix", "misp"],
            confianca_minima=Confianca.MEDIA,
        )

        if not saidas:
            QMessageBox.warning(
                self, "Nada exportado", "Nenhum formato pode ser gravado."
            )
            return

        linhas = [f"{f.upper()}: {s.exportados} indicadores" for f, s in saidas.items()]

        descartados = next(iter(saidas.values())).descartados_por_confianca
        if descartados:
            linhas += [
                "",
                f"{descartados} indicador(es) de confianca BAIXA ficaram de "
                "fora. Eles existem para voce julgar, e alimentariam um "
                "bloqueio automatico com ruido.",
            ]

        sem_representacao = [
            item for s in saidas.values() for item in s.sem_representacao
        ]
        if sem_representacao:
            linhas += ["", "Sem representacao em algum formato:"]
            linhas += [f"  - {i}" for i in dict.fromkeys(sem_representacao)]

        corpo = destino + "\n\n" + "\n".join(linhas)
        QMessageBox.information(self, "Indicadores exportados", corpo)
        self.statusBar().showMessage(f"Indicadores exportados em {destino}")

    def _salvar_yara(self) -> None:
        if self._resultado is None or self._resultado.regra_yara is None:
            return

        regra = self._resultado.regra_yara

        if not regra.valida:
            resposta = QMessageBox.warning(
                self,
                "Regra invalida",
                "Esta regra nao compila ou nao casa com a propria amostra.\n\n"
                + "\n".join(f"• {a}" for a in regra.avisos)
                + "\n\nSalvar mesmo assim, para inspecao?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if resposta != QMessageBox.Yes:
                return

        caminho, _ = QFileDialog.getSaveFileName(
            self, "Salvar regra YARA", f"{regra.nome}.yar", "YARA (*.yar)"
        )
        if not caminho:
            return

        from core.yara_generator import salvar

        try:
            destino = salvar(regra, caminho, forcar=True)
        except Exception as erro:
            QMessageBox.critical(self, "Falha ao salvar", str(erro))
            return

        self.statusBar().showMessage(f"Regra salva em {destino}")

    def _perguntar_se_abre(self, caminho: Path) -> None:
        resposta = QMessageBox.question(
            self,
            "Relatorio salvo",
            f"Salvo em:\n{caminho}\n\nAbrir agora?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if resposta == QMessageBox.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(caminho)))

    # ============================================================
    # MalwareBazaar
    # ============================================================

    def _cliente_bazaar(self):
        """Cria o client, avisando quando a Auth-Key nao esta configurada."""
        from config.settings import CONFIG
        from enrichment import malwarebazaar_client

        cliente = malwarebazaar_client.criar(CONFIG)
        if cliente is None:
            QMessageBox.information(
                self,
                "MalwareBazaar indisponivel",
                "Auth-Key nao configurada, ou enriquecimento desabilitado no "
                ".env.\n\nA chave e obtida em auth.abuse.ch e vale para todos "
                "os servicos do abuse.ch.",
            )
        return cliente

    def _consultar_bazaar(self) -> None:
        """Consulta o hash. Nao baixa nada."""
        from enrichment.malwarebazaar_client import ErroMalwareBazaar

        valor = self.campo_hash_bazaar.text().strip()
        if not valor:
            QMessageBox.information(
                self, "Informe o hash", "Preencha o hash da amostra."
            )
            return

        cliente = self._cliente_bazaar()
        if cliente is None:
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            with cliente:
                r = cliente.consultar_hash(valor)
        except ErroMalwareBazaar as erro:
            QMessageBox.critical(self, "Falha na consulta", str(erro))
            return
        finally:
            QApplication.restoreOverrideCursor()

        if r.erro:
            QMessageBox.warning(self, "MalwareBazaar", r.erro)
            return

        if not r.encontrado:
            QMessageBox.information(
                self, "MalwareBazaar", f"{r.resumo}\n\n" + "\n".join(r.observacoes)
            )
            return

        linhas = [
            f"Familia      : {r.familia or '-'}",
            f"Tags         : {', '.join(r.tags) or '-'}",
            f"Tipo         : {r.tipo} {r.formato} {r.arquitetura}".strip(),
            f"Tamanho      : {r.tamanho_bytes:,} bytes",
            f"Entrega      : {r.metodo_de_entrega or '-'}",
            f"Visto em     : {r.primeira_vez_visto} por {r.reportado_por}",
            f"SHA256       : {r.sha256}",
            f"Regras YARA  : {len(r.regras_yara)} da comunidade",
            f"Fontes       : {', '.join(r.fontes_externas[:5]) or '-'}",
            f"Senha do ZIP : {r.senha_do_arquivo}",
        ]
        if r.regras_yara:
            linhas += ["", "Regras que casam:"]
            linhas += [f"  - {nome}" for nome in r.regras_yara[:8]]

        QMessageBox.information(
            self, f"MalwareBazaar — {r.resumo}", "\n".join(linhas)
        )

        # O SHA256 canonico facilita o download logo em seguida.
        if r.sha256:
            self.campo_hash_bazaar.setText(r.sha256)

    def _baixar_amostra(self) -> None:
        """
        Baixa a amostra como ZIP cifrado.

        Pede confirmacao antes e nao descompacta. A extracao e oferecida
        depois, como passo separado, porque e ela que produz o arquivo
        executavel.
        """
        from config.settings import CONFIG
        from enrichment.malwarebazaar_client import ErroMalwareBazaar

        valor = self.campo_hash_bazaar.text().strip()
        if not valor:
            QMessageBox.information(
                self, "Informe o hash", "Preencha o SHA256 da amostra."
            )
            return

        resposta = QMessageBox.warning(
            self,
            "Baixar amostra de malware",
            f"Voce vai baixar a amostra {valor[:16]}... do MalwareBazaar.\n\n"
            "O arquivo sera gravado como ZIP cifrado, sem descompactar — em "
            "repouso ele e inerte.\n\n"
            "Ainda assim, isto traz malware para esta maquina. Faca apenas em "
            "ambiente isolado, com snapshot.\n\nContinuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resposta != QMessageBox.Yes:
            return

        cliente = self._cliente_bazaar()
        if cliente is None:
            return

        destino = QFileDialog.getExistingDirectory(
            self, "Onde salvar a amostra", str(CONFIG.samples_dir)
        )
        if not destino:
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.statusBar().showMessage("Baixando amostra...")
        try:
            with cliente:
                amostra = cliente.baixar_amostra(valor, destino)
        except ErroMalwareBazaar as erro:
            QMessageBox.critical(self, "Falha no download", str(erro))
            self.statusBar().showMessage("Download falhou")
            return
        finally:
            QApplication.restoreOverrideCursor()

        self.statusBar().showMessage(f"Amostra salva em {amostra.caminho}")
        self._oferecer_extracao(amostra)

    def _oferecer_extracao(self, amostra) -> None:
        """
        Oferece descompactar, deixando claro o que muda.

        Zipado, o arquivo nao e executavel por nada. Extraido, passa a ser
        malware vivo em disco — e essa e a unica acao do RabMapper com esse
        efeito.
        """
        from enrichment.malwarebazaar_client import ErroMalwareBazaar

        resposta = QMessageBox.warning(
            self,
            "Amostra baixada",
            f"Salvo em:\n{amostra.caminho}\n\n"
            f"Senha do arquivo: {amostra.senha}\n\n"
            "O ZIP cifrado e inerte. Descompactar grava o MALWARE VIVO em "
            "disco.\n\nDescompactar agora?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resposta != QMessageBox.Yes:
            QMessageBox.information(
                self,
                "Amostra mantida zipada",
                "Para descompactar depois, use 7-Zip com a senha "
                f"'{amostra.senha}'.",
            )
            return

        confirmacao = QMessageBox.critical(
            self,
            "Confirmar extracao",
            "Confirme que esta em ambiente ISOLADO: maquina virtual, sem rede "
            "compartilhada, com snapshot.\n\n"
            "O arquivo sera gravado sem extensao, para nao ser executavel por "
            "duplo clique — mas continua sendo malware.\n\nExtrair?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirmacao != QMessageBox.Yes:
            return

        cliente = self._cliente_bazaar()
        if cliente is None:
            return

        try:
            extraida = cliente.extrair_amostra(
                amostra, confirmo_ambiente_isolado=True
            )
        except ErroMalwareBazaar as erro:
            QMessageBox.critical(self, "Falha ao extrair", str(erro))
            return

        self._definir_arquivo(extraida.caminho)
        QMessageBox.information(
            self,
            "Amostra extraida",
            f"{extraida.caminho}\n\n"
            f"SHA256 conferido: {'sim' if extraida.hash_confere else 'NAO'}\n\n"
            "A amostra foi selecionada para analise. Clique em Analisar.",
        )

    # ============================================================
    # Ferramentas
    # ============================================================

    def _atualizar_attack(self) -> None:
        from core.mitre_mapper import ErroMitre, MitreAttack

        resposta = QMessageBox.question(
            self,
            "Atualizar o MITRE ATT&CK",
            "O bundle STIX oficial tem cerca de 45 MB e sera baixado do "
            "repositorio da MITRE.\n\nA janela fica sem resposta durante o "
            "download.\n\nContinuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if resposta != QMessageBox.Yes:
            return

        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.statusBar().showMessage("Baixando o bundle do ATT&CK...")
        try:
            attack = MitreAttack()
            attack.baixar(forcar=True)
            attack.carregar(baixar_se_faltar=False)
        except ErroMitre as erro:
            QMessageBox.critical(self, "Falha ao atualizar", str(erro))
            return
        finally:
            QApplication.restoreOverrideCursor()

        QMessageBox.information(
            self,
            "ATT&CK atualizado",
            f"Versao: {attack.versao or 'desconhecida'}\n"
            f"Objetos indexados: {len(attack._por_id)}",
        )
        self.statusBar().showMessage("ATT&CK atualizado")

    def _mostrar_configuracao(self) -> None:
        from config.settings import CONFIG

        linhas = [f"{k}: {v}" for k, v in CONFIG.diagnostico().items()]
        if CONFIG.avisos:
            linhas.append("")
            linhas += [f"• {a}" for a in CONFIG.avisos]

        QMessageBox.information(self, "Configuracao", "\n".join(linhas))
        self._atualizar_rotulo_de_chaves()

    def _sobre(self) -> None:
        QMessageBox.about(
            self,
            "Sobre o RabMapper",
            "<h3>RabMapper</h3>"
            "<p>Framework de analise estatica de artefatos e "
            "Cyber Threat Intelligence.</p>"
            "<p>Extracao de strings com FLOSS, desofuscacao, geracao de regra "
            "YARA validada, mapeamento MITRE ATT&CK, Cyber Kill Chain, "
            "atribuicao de grupo, CVSS e enriquecimento via VirusTotal e "
            "Shodan.</p>"
            "<p style='color:#5f6368'>O artefato nunca e executado. Manipule "
            "amostras reais apenas em maquina virtual isolada.</p>",
        )

    # ============================================================
    # Encerramento
    # ============================================================

    def closeEvent(self, evento) -> None:
        """Encerra a thread de analise antes de fechar."""
        if self._executor.rodando:
            resposta = QMessageBox.question(
                self,
                "Analise em andamento",
                "Ha uma analise em andamento. Cancelar e sair?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if resposta != QMessageBox.Yes:
                evento.ignore()
                return

        self._executor.aguardar_encerramento()
        evento.accept()


def main() -> int:
    """Ponto de entrada da interface grafica."""
    from config.settings import configurar_logging

    configurar_logging()

    aplicacao = QApplication(sys.argv)
    aplicacao.setApplicationName("RabMapper")

    # A folha vale para a aplicacao inteira, inclusive para os widgets
    # criados depois - o que importa aqui, ja que as abas de resultado so
    # nascem quando a analise termina.
    from gui.estilo import aplicar

    aplicar(aplicacao)

    janela = JanelaPrincipal()
    janela.show()

    return aplicacao.exec()


if __name__ == "__main__":
    sys.exit(main())
