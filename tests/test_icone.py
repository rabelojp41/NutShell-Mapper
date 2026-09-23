"""Testes do icone do aplicativo: o .ico gerado e o QIcon da janela."""

from __future__ import annotations

import struct

import pytest

pytest.importorskip("PySide6.QtSvg")

from PySide6.QtCore import QBuffer, QByteArray, QIODevice  # noqa: E402
from PySide6.QtGui import QImageReader  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from gui import icone  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_ico_tem_todas_as_resolucoes(app, tmp_path):
    destino = icone.gerar_ico(tmp_path / "teste.ico")
    dados = destino.read_bytes()

    reservado, tipo, quantidade = struct.unpack_from("<HHH", dados, 0)
    assert (reservado, tipo, quantidade) == (0, 1, len(icone.TAMANHOS_DO_ICO))

    lados = []
    for i in range(quantidade):
        lado, _, _, _, _, _, tamanho, inicio = struct.unpack_from("<BBBBHHII", dados, 6 + 16 * i)
        # Cada entrada aponta para um PNG inteiro dentro do arquivo.
        assert dados[inicio:inicio + 8] == b"\x89PNG\r\n\x1a\n"
        assert inicio + tamanho <= len(dados)
        lados.append(lado or 256)
    assert lados == list(icone.TAMANHOS_DO_ICO)


def test_ico_e_legivel_por_um_leitor_de_verdade(app, tmp_path):
    dados = QByteArray(icone.gerar_ico(tmp_path / "teste.ico").read_bytes())
    buffer = QBuffer(dados)
    buffer.open(QIODevice.ReadOnly)
    leitor = QImageReader(buffer, b"ico")
    assert leitor.imageCount() == len(icone.TAMANHOS_DO_ICO)
    assert not leitor.read().isNull()


def test_ico_versionado_existe_e_tem_todas_as_resolucoes():
    """E ele que o atalho usa; sem ele, o atalho fica com icone em branco."""
    dados = icone.CAMINHO_ICO.read_bytes()
    assert struct.unpack_from("<HHH", dados, 0) == (0, 1, len(icone.TAMANHOS_DO_ICO))


def test_janela_tem_icone(app):
    assert not icone.icone_do_app().isNull()
