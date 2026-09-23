"""
Testes do toca-discos: catalogo da pasta de midia e controles.

A regra que importa aqui e a mesma da ponte: a pagina so manda indice, e
indice fora da lista e recusado. O resto garante que o nome que aparece no
deck e o da musica, e nao o do arquivo baixado.
"""

from __future__ import annotations

import json
import math
import struct
import wave
from pathlib import Path

import pytest

pytest.importorskip("PySide6.QtCore")

from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from gui import ponte as ponte_mod  # noqa: E402
from gui import toca_discos as td  # noqa: E402
from gui.toca_discos import TocaDiscos, capa_como_data_url, listar_albuns, titulo_da_faixa  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _wav(caminho: Path, segundos: float = 1.0) -> Path:
    with wave.open(str(caminho), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(
            b"".join(struct.pack("<h", int(200 * math.sin(t / 5))) for t in range(int(8000 * segundos)))
        )
    return caminho


@pytest.fixture
def midia(tmp_path):
    album = tmp_path / "Alice in Chains - Jar of Flies"
    album.mkdir()
    for nome in ("10 - Swing on This.mp3", "2 - Nutshell.mp3", "1 - Rotten Apple.mp3"):
        (album / nome).write_bytes(b"x")
    (album / "capa.webp").write_bytes(b"RIFF....WEBP")
    (album / "zzz.png").write_bytes(b"png")
    (album / "notas.txt").write_text("nao e audio")

    so_capa = tmp_path / "Nirvana - Nevermind"
    so_capa.mkdir()
    (so_capa / "cover.jpg").write_bytes(b"jpg")

    (tmp_path / "Pasta vazia").mkdir()
    (tmp_path / "solta.flac").write_bytes(b"x")
    return tmp_path


# ============================================================
# Catalogo
# ============================================================


@pytest.mark.parametrize(
    "arquivo, artista, esperado",
    [
        ("02 - Nutshell.mp3", "", "Nutshell"),
        ("02. Nutshell.mp3", "", "Nutshell"),
        ("02_Nutshell.flac", "", "Nutshell"),
        ("02 Nutshell.mp3", "", "Nutshell"),
        # Numero que e parte do titulo fica.
        ("7 Years.mp3", "", "7 Years"),
        ("Alice In Chains - Nutshell (Official Audio).mp3", "Alice in Chains", "Nutshell"),
        ("Nutshell [Official Video] (HD).mp3", "", "Nutshell"),
        # Parenteses que sao do titulo ficam.
        ("Whale & Wasp (Live).mp3", "", "Whale & Wasp (Live)"),
        # Outro artista no nome: nao e cortado.
        ("Nirvana - Something.mp3", "Alice in Chains", "Nirvana - Something"),
    ],
)
def test_titulo_da_faixa(arquivo, artista, esperado):
    assert titulo_da_faixa(arquivo, artista) == esperado


def test_lista_albuns_em_ordem_natural(midia):
    albuns = listar_albuns(midia)
    assert [a.nome for a in albuns] == ["Jar of Flies", "Nevermind", td.ALBUM_AVULSO]

    jar = albuns[0]
    assert jar.artista == "Alice in Chains"
    # 2 antes de 10, e o .txt nao entra.
    assert jar.titulos == ["Rotten Apple", "Nutshell", "Swing on This"]
    # capa.* vence a primeira imagem em ordem alfabetica.
    assert jar.capa.name == "capa.webp"


def test_album_so_com_capa_aparece_sem_faixas(midia):
    nevermind = listar_albuns(midia)[1]
    assert nevermind.faixas == []
    assert nevermind.capa.name == "cover.jpg"


def test_pasta_inexistente_nao_quebra(tmp_path):
    assert listar_albuns(tmp_path / "nao-existe") == []


def test_capa_vira_data_url_e_grande_demais_nao(tmp_path, monkeypatch):
    capa = tmp_path / "capa.png"
    capa.write_bytes(b"\x89PNG")
    assert capa_como_data_url(capa) == "data:image/png;base64,iVBORw=="

    monkeypatch.setattr(td, "TAMANHO_MAXIMO_DA_CAPA", 2)
    assert capa_como_data_url(capa) is None
    assert capa_como_data_url(tmp_path / "sumiu.png") is None
    assert capa_como_data_url(None) is None


# ============================================================
# Controles
# ============================================================


def test_indice_fora_da_lista_e_recusado(app, midia):
    disco = TocaDiscos(midia)
    for album, faixa in [(-1, 0), (9, 0), (0, -1), (0, 3), (1, 0)]:
        assert disco.escolher(album, faixa, tocar=False) is False
    # Nada foi carregado por tentativa recusada.
    assert disco._player is None


def test_escolher_carrega_o_arquivo_certo(app, tmp_path):
    album = tmp_path / "Banda - Disco"
    album.mkdir()
    _wav(album / "01 - Um.wav")
    segunda = _wav(album / "02 - Dois.wav")

    disco = TocaDiscos(tmp_path)
    avisos = []
    disco.mudou.connect(avisos.append)
    assert disco.escolher(0, 1, tocar=False) is True
    assert Path(disco._player.source().toLocalFile()) == segunda
    assert json.loads(avisos[-1])["faixa"] == 1


def test_proxima_e_anterior_dao_a_volta_no_album(app, midia, monkeypatch):
    disco = TocaDiscos(midia)
    escolhidas = []
    monkeypatch.setattr(disco, "escolher", lambda a, f, tocar=True: escolhidas.append((a, f)))
    disco._faixa = 2
    disco.proxima()
    disco._faixa = 0
    disco.anterior()
    assert escolhidas == [(0, 0), (0, 2)]


def test_album_sem_faixas_nao_toca(app, midia):
    disco = TocaDiscos(midia)
    disco._album = 1
    disco.tocar()
    disco.proxima()
    disco.anterior()
    assert disco._player is None


def test_recarregar_mantem_a_faixa_atual(midia, app):
    disco = TocaDiscos(midia)
    disco._album, disco._faixa = 0, 1
    # Um album novo que entra antes na ordem alfabetica desloca os indices.
    novo = midia / "AAA - Primeiro"
    novo.mkdir()
    (novo / "faixa.mp3").write_bytes(b"x")
    disco.recarregar()
    assert (disco._album, disco._faixa) == (1, 1)
    assert disco.catalogo()["albuns"][disco._album]["faixas"][disco._faixa] == "Nutshell"


def test_volume_e_limitado(app, midia):
    disco = TocaDiscos(midia)
    disco.definir_volume(250)
    assert disco.estado()["volume"] == 100
    disco.definir_volume(-5)
    assert disco.estado()["volume"] == 0


def test_restaurar_volta_a_faixa_e_ignora_o_que_sumiu(app, midia, monkeypatch):
    disco = TocaDiscos(midia)
    tocou = []
    monkeypatch.setattr(disco, "tocar", lambda: tocou.append(True))

    disco.restaurar({"album": "Alice in Chains - Jar of Flies", "faixa": "2 - Nutshell.mp3", "tocando": False, "volume": 30})
    assert (disco._album, disco._faixa, disco._volume) == (0, 1, 30)
    assert tocou == []

    disco.restaurar({"album": "Alice in Chains - Jar of Flies", "faixa": "sumiu.mp3", "tocando": True})
    assert disco._faixa == 1 and tocou == []

    disco.restaurar({"album": "Alice in Chains - Jar of Flies", "faixa": "10 - Swing on This.mp3", "tocando": True, "posicao_ms": 5000})
    assert disco._faixa == 2 and tocou == [True] and disco._posicao_pendente == 5000

    # Lembranca corrompida nao quebra a abertura.
    disco.restaurar("lixo")
    disco.restaurar({"volume": "alto"})


def test_lembranca_sobrevive_ao_parar(app, midia):
    disco = TocaDiscos(midia)
    disco._faixa = 2
    disco.parar()
    disco._faixa = 0
    assert disco.lembranca()["faixa"] == "10 - Swing on This.mp3"


# ============================================================
# Ponte
# ============================================================


@pytest.fixture
def ponte(app, midia, monkeypatch):
    monkeypatch.setattr(td.TocaDiscos.__init__, "__defaults__", (midia, None))
    abertos = []
    monkeypatch.setattr(ponte_mod.QDesktopServices, "openUrl", lambda url: abertos.append(url) or True)
    p = ponte_mod.Ponte(QWidget())
    p.abertos = abertos
    return p


def test_ponte_entrega_catalogo_sem_caminho_de_arquivo(ponte, midia):
    catalogo = json.loads(ponte.discoCatalogo())
    assert catalogo["ok"] is True
    assert catalogo["albuns"][0]["faixas"] == ["Rotten Apple", "Nutshell", "Swing on This"]
    texto = json.dumps(catalogo["albuns"])
    # A pagina recebe titulos, nunca o caminho do arquivo de audio.
    assert ".mp3" not in texto and str(midia).replace("\\", "\\\\") not in texto


def test_ponte_recusa_faixa_inexistente(ponte):
    assert json.loads(ponte.discoEscolher(0, 99)) == {"ok": False, "erro": "faixa inexistente"}


def test_ponte_so_abre_a_pasta_de_musica(ponte, midia):
    assert json.loads(ponte.discoAbrirPasta())["ok"] is True
    assert [Path(u.toLocalFile()) for u in ponte.abertos] == [midia]
