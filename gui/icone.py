"""
Icone do aplicativo e atalho no Windows.

Sem isto, a janela aparece na barra de tarefas com o icone do python.exe e
agrupada junto de qualquer outro script Python aberto. Tres coisas mudam
isso:

  1. O icone da janela (QIcon), desenhado em gui/web/icone.svg.
  2. Um AppUserModelID proprio: e por ele que o Windows decide o icone e o
     agrupamento na barra de tarefas. Sem ele, vale o do python.exe.
  3. Um atalho (.lnk) na Area de Trabalho e no Menu Iniciar, com o .ico,
     para abrir a ferramenta como um programa, sem terminal.
"""

from __future__ import annotations

import io
import logging
import os
import struct
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

RAIZ = Path(__file__).resolve().parent.parent
CAMINHO_SVG = RAIZ / "gui" / "web" / "icone.svg"
CAMINHO_ICO = RAIZ / "gui" / "web" / "icone.ico"
ID_DO_APP = "NutShellMapper.Interface"
NOME_DO_ATALHO = "Nut-Shell Mapper"
TAMANHOS_DO_ICO = (16, 20, 24, 32, 48, 64, 256)


def icone_do_app():
    """O QIcon da janela, a partir do SVG (nitido em qualquer escala)."""
    from PySide6.QtGui import QIcon

    for caminho in (CAMINHO_SVG, CAMINHO_ICO):
        if caminho.exists():
            return QIcon(str(caminho))
    return QIcon()


def identificar_no_windows() -> None:
    """
    Da ao processo um AppUserModelID proprio, para a barra de tarefas usar
    o icone da janela. Precisa rodar antes de a primeira janela aparecer.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(ID_DO_APP)
    except Exception:
        logger.debug("AppUserModelID indisponivel", exc_info=True)


# ============================================================
# .ico
# ============================================================


def _png_do_svg(tamanho: int) -> bytes:
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer

    imagem = QImage(tamanho, tamanho, QImage.Format_ARGB32)
    imagem.fill(Qt.transparent)
    pintor = QPainter(imagem)
    pintor.setRenderHint(QPainter.Antialiasing)
    QSvgRenderer(str(CAMINHO_SVG)).render(pintor)
    pintor.end()

    dados = QByteArray()
    buffer = QBuffer(dados)
    buffer.open(QIODevice.WriteOnly)
    imagem.save(buffer, "PNG")
    buffer.close()
    return bytes(dados)


def montar_ico(imagens: dict[int, bytes]) -> bytes:
    """
    Um .ico com varias resolucoes, cada uma guardada como PNG.

    O formato e um cabecalho, uma entrada de diretorio por imagem e as
    imagens em seguida. PNG dentro de .ico e aceito desde o Windows Vista, e
    o escritor de .ico do Qt so grava uma resolucao - o Explorer escolheria
    a mesma imagem para 16 px e para 256 px.
    """
    saida = io.BytesIO()
    saida.write(struct.pack("<HHH", 0, 1, len(imagens)))
    deslocamento = 6 + 16 * len(imagens)
    for tamanho, png in sorted(imagens.items()):
        lado = 0 if tamanho >= 256 else tamanho  # 0 significa 256
        saida.write(struct.pack("<BBBBHHII", lado, lado, 0, 0, 1, 32, len(png), deslocamento))
        deslocamento += len(png)
    for _tamanho, png in sorted(imagens.items()):
        saida.write(png)
    return saida.getvalue()


def gerar_ico(destino: Path = CAMINHO_ICO) -> Path:
    """Gera o .ico a partir do SVG. Precisa de uma QGuiApplication viva."""
    destino.write_bytes(montar_ico({t: _png_do_svg(t) for t in TAMANHOS_DO_ICO}))
    return destino


# ============================================================
# Atalho
# ============================================================


def _pasta_especial(nome: str) -> Path | None:
    """Pasta especial do Windows ('Desktop', 'Programs'), onde quer que esteja."""
    try:
        saida = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             # Sem UTF-8, o "A" de "Area de Trabalho" chega corrompido
             # pela pagina de codigo do console, e a pasta "nao existe".
             "[Console]::OutputEncoding = [Text.Encoding]::UTF8;"
             f"[Environment]::GetFolderPath('{nome}')"],
            capture_output=True, encoding="utf-8", timeout=30, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return Path(saida) if saida else None


def _pastas_de_atalho() -> list[Path]:
    # O Windows sabe onde elas estao de verdade: a Area de Trabalho pode
    # estar no OneDrive, e com nome traduzido ("Area de Trabalho").
    pastas = [_pasta_especial("Desktop"), _pasta_especial("Programs")]
    return [p for p in pastas if p is not None and p.is_dir()]


def criar_atalhos() -> list[Path]:
    """
    Cria o atalho na Area de Trabalho e no Menu Iniciar.

    Aponta para o pythonw.exe do ambiente atual, que abre a janela sem
    terminal. Os caminhos chegam ao PowerShell por variavel de ambiente,
    nunca montados dentro do comando: uma pasta com aspas ou $ no nome nao
    vira codigo.
    """
    if sys.platform != "win32":
        raise OSError("atalho so e criado no Windows")
    if not CAMINHO_ICO.exists():
        raise FileNotFoundError(f"icone nao encontrado: {CAMINHO_ICO}")

    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = Path(sys.executable)

    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:NS_LNK);"
        "$s.TargetPath = $env:NS_ALVO;"
        "$s.Arguments = $env:NS_ARGS;"
        "$s.WorkingDirectory = $env:NS_PASTA;"
        "$s.IconLocation = $env:NS_ICONE;"
        "$s.Description = 'Analise estatica de artefatos e threat intelligence';"
        "$s.Save()"
    )
    criados = []
    for pasta in _pastas_de_atalho():
        pasta.mkdir(parents=True, exist_ok=True)
        lnk = pasta / f"{NOME_DO_ATALHO}.lnk"
        ambiente = {
            **os.environ,
            "NS_LNK": str(lnk),
            "NS_ALVO": str(pythonw),
            "NS_ARGS": f'"{RAIZ / "main.py"}" gui',
            "NS_PASTA": str(RAIZ),
            "NS_ICONE": f"{CAMINHO_ICO},0",
        }
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            env=ambiente,
            check=True,
            capture_output=True,
            timeout=30,
        )
        criados.append(lnk)
    return criados
