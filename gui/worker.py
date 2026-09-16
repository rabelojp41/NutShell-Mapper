"""
Execucao da analise numa thread separada.

O pipeline leva dezenas de segundos - a emulacao do FLOSS sozinha pode levar
minutos. Rodar isso na thread da interface congelaria a janela inteira, e o
Windows marcaria o programa como "nao respondendo".

A regra do Qt que este modulo respeita: widget so pode ser tocado pela
thread da interface. A worker nao mexe em nada da tela; ela apenas emite
sinais, e o Qt entrega esses sinais na thread certa.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from core.pipeline import Estagio, OpcoesAnalise, ResultadoAnalise, analisar

logger = logging.getLogger(__name__)


class TrabalhadorDeAnalise(QObject):
    """
    Executa o pipeline e reporta o andamento por sinais.

    Sinais:
        progresso  : (nome do estagio, mensagem, fracao de 0.0 a 1.0)
        concluido  : o ResultadoAnalise, mesmo quando houve falha de etapa
        falhou     : mensagem, apenas para erro que impediu qualquer resultado
    """

    progresso = Signal(str, str, float)
    concluido = Signal(object)
    falhou = Signal(str)

    def __init__(self, caminho: str | Path, opcoes: OpcoesAnalise):
        super().__init__()
        self._caminho = Path(caminho)
        self._opcoes = opcoes
        # threading.Event, e nao um bool, porque a flag e lida pela thread da
        # analise e escrita pela thread da interface.
        self._cancelar = threading.Event()

    def cancelar(self) -> None:
        """
        Pede o cancelamento.

        Chamado pela thread da interface. O pipeline consulta a flag entre
        as etapas, entao o cancelamento nao e instantaneo: a etapa em
        andamento termina antes.
        """
        logger.info("cancelamento solicitado")
        self._cancelar.set()

    @property
    def cancelado(self) -> bool:
        return self._cancelar.is_set()

    def executar(self) -> None:
        """Ponto de entrada na thread de trabalho."""
        try:
            resultado = analisar(
                self._caminho,
                self._opcoes,
                progresso=self._reportar,
                cancelado=self._cancelar.is_set,
            )
        except Exception as erro:
            # O pipeline ja isola falha de etapa; chegar aqui significa erro
            # na propria orquestracao, que nao produz resultado nenhum.
            logger.exception("falha na analise")
            self.falhou.emit(f"{type(erro).__name__}: {erro}")
            return

        self.concluido.emit(resultado)

    def _reportar(self, estagio: Estagio, mensagem: str, fracao: float) -> None:
        self.progresso.emit(estagio.value, mensagem, fracao)


class ExecutorDeAnalise(QObject):
    """
    Dono da thread e do trabalhador.

    Existe para a janela nao precisar lidar com o ciclo de vida da QThread,
    que e a fonte mais comum de travamento e de crash no encerramento de
    aplicacao Qt.
    """

    progresso = Signal(str, str, float)
    concluido = Signal(object)
    falhou = Signal(str)
    finalizado = Signal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._thread: QThread | None = None
        self._trabalhador: TrabalhadorDeAnalise | None = None

    @property
    def rodando(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def iniciar(self, caminho: str | Path, opcoes: OpcoesAnalise) -> bool:
        """
        Comeca a analise.

        Returns:
            False se ja havia uma analise em andamento.
        """
        if self.rodando:
            return False

        self._thread = QThread()
        self._trabalhador = TrabalhadorDeAnalise(caminho, opcoes)
        self._trabalhador.moveToThread(self._thread)

        self._thread.started.connect(self._trabalhador.executar)
        self._trabalhador.progresso.connect(self.progresso)
        self._trabalhador.concluido.connect(self.concluido)
        self._trabalhador.falhou.connect(self.falhou)

        # Encerra a thread quando o trabalho acaba, de qualquer forma.
        self._trabalhador.concluido.connect(self._encerrar)
        self._trabalhador.falhou.connect(self._encerrar)

        self._thread.start()
        return True

    def cancelar(self) -> None:
        if self._trabalhador is not None:
            self._trabalhador.cancelar()

    def _encerrar(self, *_args) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
            self._thread.deleteLater()
        if self._trabalhador is not None:
            self._trabalhador.deleteLater()

        self._thread = None
        self._trabalhador = None
        self.finalizado.emit()

    def aguardar_encerramento(self, timeout_ms: int = 10000) -> None:
        """
        Encerra a thread ao fechar a janela.

        Sem isso, o Qt derruba o processo com uma QThread ainda viva e o
        programa termina com erro em vez de fechar limpo.
        """
        if not self.rodando:
            return
        self.cancelar()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(timeout_ms)
