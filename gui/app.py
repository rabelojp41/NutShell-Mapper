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
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.pipeline import OpcoesAnalise
from gui.views import ABAS
from gui.worker import ExecutorDeAnalise

logger = logging.getLogger(__name__)


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
        self.setText("Arraste um artefato aqui, ou use Abrir")
        self.setStyleSheet(
            "QLabel { border: 2px dashed #9aa0a6; border-radius: 6px;"
            " color: #5f6368; padding: 12px; }"
        )

    def mostrar_arquivo(self, caminho: Path) -> None:
        tamanho = caminho.stat().st_size if caminho.is_file() else 0
        self.setText(f"{caminho.name}\n{tamanho:,} bytes\n{caminho.parent}")
        self.setStyleSheet(
            "QLabel { border: 2px solid #1a73e8; border-radius: 6px;"
            " background: #e8f0fe; color: #174ea6; padding: 12px; }"
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
        divisor.addWidget(self._painel_esquerdo())

        self.abas = QTabWidget()
        self.abas.addTab(
            self._mensagem_inicial(), "Bem-vindo"
        )
        divisor.addWidget(self.abas)

        divisor.setStretchFactor(0, 0)
        divisor.setStretchFactor(1, 1)
        divisor.setSizes([330, 870])

        self.setCentralWidget(divisor)
        self.statusBar().showMessage("Pronto")

    def _mensagem_inicial(self) -> QWidget:
        rotulo = QLabel(
            "<h2>RabMapper</h2>"
            "<p>Analise estatica de artefatos e threat intelligence.</p>"
            "<p>Selecione um arquivo a esquerda e clique em <b>Analisar</b>.</p>"
            "<p style='color:#5f6368'>O artefato nao e executado. Ainda assim, "
            "manipule amostras reais apenas em maquina virtual isolada.</p>"
        )
        rotulo.setAlignment(Qt.AlignCenter)
        rotulo.setWordWrap(True)

        pagina = QWidget()
        layout = QVBoxLayout(pagina)
        layout.addWidget(rotulo)
        return pagina

    def _painel_esquerdo(self) -> QWidget:
        painel = QWidget()
        layout = QVBoxLayout(painel)
        layout.setContentsMargins(10, 10, 10, 10)

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

        self.usar_floss = QCheckBox("Usar FLOSS (mais lento, muito melhor)")
        self.usar_floss.setChecked(True)
        self.usar_floss.setToolTip(
            "Recupera strings montadas em runtime: stack, tight e decoded.\n"
            "Sem ele, so as strings literais do arquivo sao vistas."
        )
        formulario.addRow(self.usar_floss)

        self.gerar_yara = QCheckBox("Gerar regra YARA")
        self.gerar_yara.setChecked(True)
        formulario.addRow(self.gerar_yara)

        self.usar_stix = QCheckBox("Usar o STIX oficial do ATT&CK")
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
        formulario.addRow("Tamanho minimo de string:", self.min_string)

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

        self.enriquecer = QCheckBox("Consultar VirusTotal e Shodan")
        self.enriquecer.setChecked(False)
        self.enriquecer.toggled.connect(self._confirmar_enriquecimento)
        layout_rede.addWidget(self.enriquecer)

        self.rotulo_chaves = QLabel()
        self.rotulo_chaves.setWordWrap(True)
        self.rotulo_chaves.setStyleSheet("QLabel { color: #5f6368; font-size: 11px; }")
        layout_rede.addWidget(self.rotulo_chaves)
        self._atualizar_rotulo_de_chaves()

        layout.addWidget(grupo_rede)

        # --- Acao ---
        self.botao_analisar = QPushButton("Analisar")
        self.botao_analisar.setMinimumHeight(36)
        fonte = QFont()
        fonte.setBold(True)
        self.botao_analisar.setFont(fonte)
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
        self.rotulo_etapa.setStyleSheet("QLabel { color: #5f6368; font-size: 11px; }")
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

        acao = QAction("Atualizar o MITRE ATT&CK", self)
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

    janela = JanelaPrincipal()
    janela.show()

    return aplicacao.exec()


if __name__ == "__main__":
    sys.exit(main())
