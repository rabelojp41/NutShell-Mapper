"""
Toca-discos da interface: o album que fica tocando enquanto se analisa.

As musicas moram em `midia/`, na raiz do projeto, uma pasta por album:

    midia/
      Alice in Chains - Jar of Flies/
        capa.webp
        01 - Rotten Apple.mp3
        02 - Nutshell.mp3

O nome da pasta vira "artista - album"; a imagem `capa.*` (ou `cover.*`,
`folder.*`, ou a primeira imagem que houver) vira o selo do disco. A pasta
inteira fica fora do Git: musica e capa de album tem dono, e o repositorio
nao e lugar de redistribuir.

O audio toca aqui, pelo QtMultimedia, e nao dentro da pagina. Assim a
politica de seguranca da pagina continua sem nenhuma origem de midia
liberada, e o JavaScript nunca passa caminho de arquivo para o Python:
ele pede "album 0, faixa 3", e o indice e conferido contra a lista que o
proprio Python montou.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QUrl, Signal

logger = logging.getLogger(__name__)

PASTA_MIDIA = Path(__file__).resolve().parent.parent / "midia"

EXTENSOES_AUDIO = frozenset({".mp3", ".flac", ".ogg", ".opus", ".wav", ".m4a", ".aac"})
TIPOS_DE_CAPA = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}
NOMES_DE_CAPA = ("capa", "cover", "folder", "front")
# A capa vai para a pagina como data URL. Uma imagem de 20 MB tornaria cada
# carga do catalogo lenta sem nenhum ganho num selo de 70 px.
TAMANHO_MAXIMO_DA_CAPA = 3 * 2**20

# Com musica, positionChanged dispara varias vezes por segundo. A pagina so
# precisa andar a barra de progresso; meio segundo basta.
INTERVALO_DE_POSICAO = 0.5
# Voltar com mais de 3 s de faixa recomeca a faixa, como todo player faz.
RECOMECAR_DEPOIS_DE_MS = 3000
ALBUM_AVULSO = "Faixas avulsas"

# "01 - Nutshell", "01. Nutshell", "01_Nutshell", "02 Nutshell". Um numero
# solto seguido so de espaco so conta com dois digitos, senao "7 Years"
# perderia o 7.
RE_NUMERO_DA_FAIXA = re.compile(r"^\s*(?:\d{1,3}\s*[-._)]\s*|\d{2}\s+)")
# O que costuma vir no nome de arquivo baixado e nao e titulo.
RE_RUIDO = re.compile(
    r"\s*[(\[][^)\]]*(?:official|audio|video|lyric|visualizer|\bhd\b|\bhq\b)[^)\]]*[)\]]",
    re.IGNORECASE,
)
RE_NUMERO = re.compile(r"(\d+)")


def _ordem_natural(caminho: Path) -> list:
    """'2 - x' antes de '10 - x', como o explorador de arquivos ordena."""
    return [int(p) if p.isdigit() else p.lower() for p in RE_NUMERO.split(caminho.name)]


def titulo_da_faixa(nome_do_arquivo: str, artista: str = "") -> str:
    """O titulo legivel de uma faixa a partir do nome do arquivo."""
    titulo = Path(nome_do_arquivo).stem
    titulo = RE_NUMERO_DA_FAIXA.sub("", titulo, count=1)
    titulo = RE_RUIDO.sub("", titulo)
    # "Alice in Chains - Nutshell" dentro do album do Alice in Chains: o
    # artista ja aparece embaixo do titulo.
    if artista and " - " in titulo:
        antes, depois = titulo.split(" - ", 1)
        if antes.strip().lower() == artista.lower():
            titulo = depois
    return titulo.strip(" -_.") or Path(nome_do_arquivo).stem


def _separar_artista(nome_da_pasta: str) -> tuple[str, str]:
    if " - " in nome_da_pasta:
        artista, album = nome_da_pasta.split(" - ", 1)
        return artista.strip(), album.strip()
    return "", nome_da_pasta.strip()


def _achar_capa(pasta: Path, arquivos: list[Path]) -> Path | None:
    imagens = [a for a in arquivos if a.suffix.lower() in TIPOS_DE_CAPA]
    for preferido in NOMES_DE_CAPA:
        for imagem in imagens:
            if imagem.stem.lower() == preferido:
                return imagem
    return min(imagens, key=_ordem_natural) if imagens else None


def capa_como_data_url(caminho: Path | None) -> str | None:
    """A capa pronta para um <img>. None se nao houver ou for grande demais."""
    if caminho is None:
        return None
    tipo = TIPOS_DE_CAPA.get(caminho.suffix.lower())
    try:
        if tipo is None or caminho.stat().st_size > TAMANHO_MAXIMO_DA_CAPA:
            return None
        conteudo = caminho.read_bytes()
    except OSError:
        return None
    return f"data:{tipo};base64,{base64.b64encode(conteudo).decode('ascii')}"


@dataclass
class Album:
    nome: str
    artista: str
    pasta: Path
    faixas: list[Path] = field(default_factory=list)
    capa: Path | None = None

    @property
    def titulos(self) -> list[str]:
        return [titulo_da_faixa(f.name, self.artista) for f in self.faixas]


def listar_albuns(pasta: Path = PASTA_MIDIA) -> list[Album]:
    """
    Os albuns da pasta de midia, em ordem alfabetica.

    Subpasta com audio ou com capa vira album - so com a capa, o disco ja
    aparece no prato, esperando as faixas. Audio solto na raiz vira o album
    de faixas avulsas, no fim da lista.
    """
    if not pasta.is_dir():
        return []

    albuns: list[Album] = []
    avulsas: list[Path] = []
    try:
        itens = sorted(pasta.iterdir(), key=_ordem_natural)
    except OSError:
        return []

    for item in itens:
        if item.is_dir():
            try:
                arquivos = [a for a in item.iterdir() if a.is_file()]
            except OSError:
                continue
            faixas = sorted(
                (a for a in arquivos if a.suffix.lower() in EXTENSOES_AUDIO), key=_ordem_natural
            )
            capa = _achar_capa(item, arquivos)
            if not faixas and capa is None:
                continue
            artista, nome = _separar_artista(item.name)
            albuns.append(Album(nome, artista, item, faixas, capa))
        elif item.suffix.lower() in EXTENSOES_AUDIO:
            avulsas.append(item)

    if avulsas:
        albuns.append(Album(ALBUM_AVULSO, "", pasta, avulsas, None))
    return albuns


class TocaDiscos(QObject):
    """
    Um player de album: toca em ordem e, no fim, volta a primeira faixa.

    O QMediaPlayer so e criado no primeiro play. Carregar o backend de
    audio custa tempo na abertura da janela, e quem nunca aperta play nao
    precisa pagar isso.

    Sinal:
        mudou : JSON com o estado (album, faixa, tocando, posicao, ...)
    """

    mudou = Signal(str)

    def __init__(self, pasta: Path = PASTA_MIDIA, pai: QObject | None = None):
        super().__init__(pai)
        self._pasta = Path(pasta)
        self._albuns: list[Album] = []
        self._album = 0
        self._faixa = 0
        self._volume = 70
        self._erro = ""
        self._player = None
        self._saida = None
        self._carregada: Path | None = None
        self._posicao_pendente = 0
        self._ultimo_aviso = 0.0
        self._ao_parar: dict | None = None
        self.recarregar()

    # ------------------------------------------------------------
    # Catalogo
    # ------------------------------------------------------------

    @property
    def pasta(self) -> Path:
        return self._pasta

    def recarregar(self) -> None:
        """Rele a pasta, mantendo a faixa atual se ela ainda existir."""
        atual = self._caminho_atual()
        self._albuns = listar_albuns(self._pasta)
        self._album, self._faixa = 0, 0
        if atual is not None:
            for i, album in enumerate(self._albuns):
                if atual in album.faixas:
                    self._album, self._faixa = i, album.faixas.index(atual)
                    break

    def catalogo(self) -> dict:
        return {
            "pasta": str(self._pasta),
            "albuns": [
                {
                    "nome": a.nome,
                    "artista": a.artista,
                    "capa": capa_como_data_url(a.capa),
                    "faixas": a.titulos,
                }
                for a in self._albuns
            ],
        }

    def _caminho_atual(self) -> Path | None:
        if not self._albuns or not self._albuns[self._album].faixas:
            return None
        return self._albuns[self._album].faixas[self._faixa]

    # ------------------------------------------------------------
    # Estado
    # ------------------------------------------------------------

    @property
    def tocando(self) -> bool:
        if self._player is None:
            return False
        from PySide6.QtMultimedia import QMediaPlayer

        return self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState

    def estado(self) -> dict:
        player = self._player
        carregada = player is not None and self._carregada == self._caminho_atual()
        return {
            "album": self._album,
            "faixa": self._faixa,
            "tocando": self.tocando,
            "posicao_ms": player.position() if carregada else 0,
            "duracao_ms": player.duration() if carregada else 0,
            "volume": self._volume,
            "erro": self._erro,
        }

    def _avisar(self) -> None:
        self._ultimo_aviso = time.monotonic()
        self.mudou.emit(json.dumps(self.estado()))

    # ------------------------------------------------------------
    # Controles
    # ------------------------------------------------------------

    def escolher(self, album: int, faixa: int, tocar: bool = True) -> bool:
        """Poe a faixa no prato. Indice fora da lista e recusado."""
        if not (0 <= album < len(self._albuns)):
            return False
        if not (0 <= faixa < len(self._albuns[album].faixas)):
            return False
        self._album, self._faixa = album, faixa
        self._erro = ""
        self._carregar()
        if tocar:
            self._player.play()
        self._avisar()
        return True

    def tocar(self) -> None:
        if self._caminho_atual() is None:
            return
        if self._carregada != self._caminho_atual():
            self._carregar()
        self._player.play()

    def pausar(self) -> None:
        if self._player is not None:
            self._player.pause()

    def alternar(self) -> None:
        if self.tocando:
            self.pausar()
        else:
            self.tocar()

    def proxima(self) -> None:
        faixas = len(self._albuns[self._album].faixas) if self._albuns else 0
        if not faixas:
            return
        self.escolher(self._album, (self._faixa + 1) % faixas, tocar=True)

    def anterior(self) -> None:
        if self._caminho_atual() is None:
            return
        if self._player is not None and self._player.position() > RECOMECAR_DEPOIS_DE_MS:
            self._player.setPosition(0)
            return
        faixas = len(self._albuns[self._album].faixas)
        self.escolher(self._album, (self._faixa - 1) % faixas, tocar=self.tocando)

    def buscar(self, milissegundos: int) -> None:
        if self._player is not None and self._carregada == self._caminho_atual():
            duracao = self._player.duration()
            self._player.setPosition(max(0, min(int(milissegundos), duracao or 0)))

    def definir_volume(self, volume: int) -> None:
        self._volume = max(0, min(100, int(volume)))
        if self._saida is not None:
            self._saida.setVolume(self._volume / 100)
        self._avisar()

    def parar(self) -> None:
        """Para de vez, no fechamento da janela."""
        # stop() zera a posicao e o estado; a lembranca precisa do que
        # havia antes, para a proxima abertura continuar dali.
        self._ao_parar = self._lembranca_agora()
        if self._player is not None:
            self._player.stop()

    # ------------------------------------------------------------
    # Lembrar entre sessoes
    # ------------------------------------------------------------

    def lembranca(self) -> dict:
        """O que precisa para continuar de onde parou na proxima abertura."""
        return self._ao_parar or self._lembranca_agora()

    def _lembranca_agora(self) -> dict:
        atual = self._caminho_atual()
        return {
            "album": self._albuns[self._album].pasta.name if atual else "",
            "faixa": atual.name if atual else "",
            "posicao_ms": self._player.position() if self._player is not None else 0,
            "tocando": self.tocando,
            "volume": self._volume,
        }

    def restaurar(self, lembranca: dict) -> None:
        """
        Volta ao album e a faixa da ultima sessao, e volta a tocar se estava
        tocando quando a janela fechou. Faixa que sumiu da pasta e ignorada.
        """
        if not isinstance(lembranca, dict):
            return
        try:
            self._volume = max(0, min(100, int(lembranca.get("volume", self._volume))))
        except (TypeError, ValueError):
            pass
        for i, album in enumerate(self._albuns):
            if album.pasta.name != lembranca.get("album"):
                continue
            for j, faixa in enumerate(album.faixas):
                if faixa.name == lembranca.get("faixa"):
                    self._album, self._faixa = i, j
                    if lembranca.get("tocando"):
                        try:
                            self._posicao_pendente = max(0, int(lembranca.get("posicao_ms", 0)))
                        except (TypeError, ValueError):
                            self._posicao_pendente = 0
                        self.tocar()
                    return

    # ------------------------------------------------------------
    # QMediaPlayer
    # ------------------------------------------------------------

    def _criar_player(self) -> None:
        if self._player is not None:
            return
        from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer

        self._saida = QAudioOutput(self)
        self._saida.setVolume(self._volume / 100)
        self._player = QMediaPlayer(self)
        self._player.setAudioOutput(self._saida)
        self._player.playbackStateChanged.connect(lambda *_: self._avisar())
        self._player.durationChanged.connect(lambda *_: self._avisar())
        self._player.positionChanged.connect(self._ao_andar)
        self._player.mediaStatusChanged.connect(self._ao_mudar_midia)
        self._player.errorOccurred.connect(self._ao_errar)

    def _carregar(self) -> None:
        self._criar_player()
        caminho = self._caminho_atual()
        self._carregada = caminho
        self._player.setSource(QUrl.fromLocalFile(str(caminho)))

    def _ao_andar(self, _posicao: int) -> None:
        if time.monotonic() - self._ultimo_aviso >= INTERVALO_DE_POSICAO:
            self._avisar()

    def _ao_mudar_midia(self, status) -> None:
        from PySide6.QtMultimedia import QMediaPlayer

        if status == QMediaPlayer.MediaStatus.EndOfMedia:
            # O album segue sozinho e, acabando, recomeca.
            self.proxima()
        elif status in (QMediaPlayer.MediaStatus.LoadedMedia, QMediaPlayer.MediaStatus.BufferedMedia):
            if self._posicao_pendente:
                self._player.setPosition(self._posicao_pendente)
                self._posicao_pendente = 0

    def _ao_errar(self, _erro, mensagem: str) -> None:
        self._erro = mensagem or "nao foi possivel tocar esta faixa"
        logger.warning("toca-discos: %s", self._erro)
        self._avisar()
