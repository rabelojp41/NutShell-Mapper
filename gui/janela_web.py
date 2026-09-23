"""
Janela da interface web.

Uma janela nativa com um QWebEngineView dentro. A pagina (gui/web/) e
local e fala com o Python pela Ponte, via QWebChannel - sem servidor e sem
porta aberta.

O que esta janela faz alem de mostrar a pagina:

  - Trava a navegacao. A pagina so pode ser ela mesma: nenhum link, nenhum
    redirecionamento e nenhuma janela nova carrega outra coisa dentro do
    processo que tem acesso a Ponte. Link externo sai pela Ponte, que so
    abre host conhecido, no navegador do sistema.

  - Recebe o arrastar-e-soltar. O navegador nunca revela o caminho real de
    um arquivo solto na pagina, por seguranca; o Qt revela. Entao o soltar
    e interceptado aqui, antes de chegar a pagina.

  - Deixa a barra de titulo escura no Windows 11. Uma barra branca em cima
    de uma interface escura e o primeiro detalhe que faz um programa
    parecer mal acabado.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QSettings, Qt, QUrl
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QApplication, QMainWindow

from gui.ponte import Ponte

logger = logging.getLogger(__name__)

PASTA_WEB = Path(__file__).resolve().parent / "web"
PAGINA = PASTA_WEB / "index.html"
COR_DE_FUNDO = "#0d0e12"
NOME = "Nut-Shell Mapper"


class PaginaTravada(QWebEnginePage):
    """Uma pagina que so aceita ser o index.html local."""

    def __init__(self, perfil_ou_pai=None):
        super().__init__(perfil_ou_pai)
        self._permitida = PAGINA.resolve()

    def acceptNavigationRequest(self, url: QUrl, tipo, principal: bool) -> bool:
        # A propria pagina (inclusive recarregar) e o unico destino aceito.
        # toLocalFile() ja descarta fragmento e consulta, que nao mudam de
        # documento. Qualquer coisa que nao seja arquivo local e recusada.
        try:
            if url.isLocalFile() and Path(url.toLocalFile()).resolve() == self._permitida:
                return True
        except OSError:
            pass
        logger.warning("navegacao bloqueada: %s", url.toString()[:200])
        return False

    def createWindow(self, _tipo):
        # window.open e target=_blank nao abrem nada.
        return None

    def javaScriptConsoleMessage(self, nivel, mensagem, linha, origem):
        # Erro de JavaScript vai para o log da ferramenta, onde da para ver.
        registrar = logger.warning if nivel >= QWebEnginePage.JavaScriptConsoleMessageLevel.WarningMessageLevel else logger.debug
        registrar("js %s:%s %s", Path(origem).name if origem else "?", linha, mensagem)


class FiltroDeArrasto(QObject):
    """
    Intercepta arrastar-e-soltar de arquivo sobre a visao.

    Instalado no proprio QWebEngineView e no widget interno que desenha a
    pagina, porque o Qt entrega os eventos de arrasto a este ultimo.
    """

    def __init__(self, ponte: Ponte, pai: QObject):
        super().__init__(pai)
        self._ponte = ponte

    @staticmethod
    def _arquivo(evento) -> Path | None:
        dados = evento.mimeData()
        if dados is None or not dados.hasUrls():
            return None
        locais = [u.toLocalFile() for u in dados.urls() if u.isLocalFile()]
        if len(locais) != 1 or not Path(locais[0]).is_file():
            return None
        return Path(locais[0])

    def eventFilter(self, objeto, evento) -> bool:
        tipo = evento.type()
        if tipo in (QEvent.DragEnter, QEvent.DragMove):
            if self._arquivo(evento) is not None:
                evento.acceptProposedAction()
                if tipo == QEvent.DragEnter:
                    self._ponte.arrastando.emit('{"ativo": true}')
                return True
            return False
        if tipo == QEvent.DragLeave:
            self._ponte.arrastando.emit('{"ativo": false}')
            return False
        if tipo == QEvent.Drop:
            caminho = self._arquivo(evento)
            self._ponte.arrastando.emit('{"ativo": false}')
            if caminho is not None:
                evento.acceptProposedAction()
                self._ponte.definir_arquivo(caminho)
                return True
        return False


class JanelaWeb(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(NOME)
        self.resize(1360, 880)
        self.setMinimumSize(1060, 680)

        icone = PASTA_WEB / "icone.svg"
        if icone.exists():
            self.setWindowIcon(QIcon(str(icone)))

        self.visao = QWebEngineView(self)
        self.visao.setContextMenuPolicy(Qt.NoContextMenu)
        self.visao.setAcceptDrops(True)

        pagina = PaginaTravada(self.visao)
        pagina.setBackgroundColor(QColor(COR_DE_FUNDO))
        self.visao.setPage(pagina)

        config = pagina.settings()
        # Pagina local nao alcanca a rede: nem fonte, nem imagem, nem fetch.
        config.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        config.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, False)
        config.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, False)
        config.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        config.setAttribute(QWebEngineSettings.PdfViewerEnabled, False)

        self.ponte = Ponte(self)
        self.canal = QWebChannel(pagina)
        self.canal.registerObject("ponte", self.ponte)
        pagina.setWebChannel(self.canal)

        self._filtro = FiltroDeArrasto(self.ponte, self)
        self.visao.installEventFilter(self._filtro)
        # O widget que desenha a pagina so existe depois do primeiro load.
        self.visao.loadFinished.connect(self._instalar_filtro_no_desenho)

        self.setCentralWidget(self.visao)
        self.visao.load(QUrl.fromLocalFile(str(PAGINA)))

        _barra_de_titulo_escura(self)

    def _instalar_filtro_no_desenho(self, _ok: bool) -> None:
        alvo = self.visao.focusProxy()
        if alvo is not None and not alvo.property("_nutshell_filtro"):
            alvo.setAcceptDrops(True)
            alvo.installEventFilter(self._filtro)
            alvo.setProperty("_nutshell_filtro", True)

    def closeEvent(self, evento) -> None:
        self.ponte.encerrar()
        super().closeEvent(evento)


def _barra_de_titulo_escura(janela: QMainWindow) -> None:
    """Pede ao Windows 11 a barra de titulo escura. Em outro sistema, nada."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        hwnd = int(janela.winId())
        valor = ctypes.c_int(1)
        # DWMWA_USE_IMMERSIVE_DARK_MODE: 20 no Windows 11, 19 em builds antigos do 10.
        for atributo in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, atributo, ctypes.byref(valor), ctypes.sizeof(valor)
            ) == 0:
                break
    except Exception:
        logger.debug("barra de titulo escura indisponivel", exc_info=True)


def main() -> int:
    """Ponto de entrada da interface."""
    from config.settings import configurar_logging

    configurar_logging()

    # Em maquina virtual sem aceleracao grafica, o Chromium do QtWebEngine
    # pode renderizar uma tela preta. NUTSHELL_SEM_GPU=1 forca o modo
    # de software - comum justamente no ambiente isolado de analise.
    if os.environ.get("NUTSHELL_SEM_GPU") == "1":
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
            os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " --disable-gpu"
        ).strip()

    QApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    aplicacao = QApplication.instance() or QApplication(sys.argv)
    aplicacao.setApplicationName(NOME)

    janela = JanelaWeb()
    janela.show()

    # O toca-discos volta de onde parou: mesmo album, mesma faixa, e
    # tocando, se estava tocando quando a janela fechou. Fica aqui, e nao
    # na janela, para os testes (que criam a janela direto) nunca lerem o
    # que ficou salvo nem sairem tocando musica.
    ajustes = QSettings("NutShellMapper", "interface")
    try:
        janela.ponte.toca_discos.restaurar(json.loads(ajustes.value("toca_discos", "") or "{}"))
    except (TypeError, ValueError):
        logger.debug("lembranca do toca-discos ilegivel; ignorada")
    aplicacao.aboutToQuit.connect(
        lambda: ajustes.setValue("toca_discos", json.dumps(janela.ponte.toca_discos.lembranca()))
    )
    return aplicacao.exec()


if __name__ == "__main__":
    sys.exit(main())
