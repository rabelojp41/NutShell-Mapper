"""
Infraestrutura comum dos clients de enriquecimento.

Concentra aqui o que VirusTotal e Shodan fazem igual: limitar a taxa de
requisicao, tratar erro de rede sem derrubar o pipeline, e - o mais
importante - nunca deixar a chave de API escapar para log ou mensagem de
erro.

Principio que vale para todos os clients: enriquecimento e opcional. Falha
de rede, chave ausente, cota estourada ou serviço fora do ar viram aviso no
resultado, nunca excecao que interrompe a analise. O que foi extraido
localmente continua valendo.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

logger = logging.getLogger(__name__)


# Quantas vezes repetir uma requisicao que falhou por causa transitoria.
TENTATIVAS_PADRAO = 3

# Espera inicial do backoff exponencial, em segundos.
ESPERA_INICIAL = 2.0

# Codigos HTTP que vale a pena repetir: limite de taxa e erro de servidor.
CODIGOS_REPETIVEIS = frozenset({429, 500, 502, 503, 504})


class LimitadorDeTaxa:
    """
    Limitador simples por janela deslizante.

    O plano gratuito do VirusTotal permite 4 requisicoes por minuto, e
    estourar isso devolve 429 para todas as seguintes. Esperar antes de
    enviar e mais confiavel do que reagir ao 429 depois.

    E seguro entre threads porque a GUI vai chamar os clients a partir de
    uma thread de trabalho.
    """

    def __init__(self, por_minuto: int):
        self.por_minuto = max(1, por_minuto)
        self._momentos: list[float] = []
        self._trava = threading.Lock()

    def aguardar(self) -> float:
        """
        Bloqueia ate ser seguro fazer a proxima requisicao.

        Returns:
            Quantos segundos foram esperados (0.0 se nao houve espera).
        """
        with self._trava:
            agora = time.monotonic()
            # Descarta o que saiu da janela de 60 segundos.
            self._momentos = [m for m in self._momentos if agora - m < 60.0]

            if len(self._momentos) < self.por_minuto:
                self._momentos.append(agora)
                return 0.0

            # A janela esta cheia: espera a requisicao mais antiga expirar.
            espera = 60.0 - (agora - self._momentos[0]) + 0.1

        if espera > 0:
            logger.info("limite de taxa: aguardando %.1fs", espera)
            time.sleep(espera)

        with self._trava:
            self._momentos.append(time.monotonic())

        return max(0.0, espera)


@dataclass
class RespostaEnriquecimento:
    """
    Resultado de uma consulta a um servico externo.

    Modela explicitamente os tres desfechos que importam, porque confundi-los
    leva a conclusao errada:
      - sucesso com dado     : o servico conhece o indicador
      - sucesso sem dado     : o servico respondeu que nao conhece
      - falha                : nao foi possivel perguntar

    "Nao encontrado no VirusTotal" e uma informacao real sobre o artefato.
    "Nao consegui consultar o VirusTotal" nao diz nada sobre ele. Um campo
    booleano unico apagaria essa diferenca.
    """

    consultado: bool = False
    encontrado: bool = False
    dados: dict[str, Any] = field(default_factory=dict)
    erro: str = ""
    # Indicador consultado (hash, IP, dominio).
    indicador: str = ""
    fonte: str = ""
    # Corpo da resposta sem interpretar, quando bruto=True (ex.: um ZIP).
    conteudo: bytes = b""

    @property
    def util(self) -> bool:
        """True quando a consulta ocorreu e trouxe dado."""
        return self.consultado and self.encontrado

    def to_dict(self) -> dict:
        return asdict(self)


class ErroCliente(Exception):
    """Falha que o chamador precisa saber, mas que nao interrompe o pipeline."""


def _limpar_segredo(texto: str, segredos: tuple[str, ...]) -> str:
    """
    Remove chaves de API de um texto antes de ele virar log ou mensagem.

    Necessario porque bibliotecas HTTP embutem a URL completa na excecao, e
    servicos que autenticam por query string (o Shodan e um deles) levam a
    chave na URL. Sem esta limpeza, um simples timeout vazaria a credencial
    para o log.
    """
    for segredo in segredos:
        if segredo and len(segredo) >= 8:
            texto = texto.replace(segredo, "<CHAVE_REMOVIDA>")
    # Rede de seguranca para formatos comuns em query string.
    return re.sub(
        r"(?i)(api[_-]?key|apikey|key|token)=([^&\s\"']+)",
        r"\1=<CHAVE_REMOVIDA>",
        texto,
    )


class ClienteBase:
    """Base dos clients HTTP de enriquecimento."""

    nome = "base"
    url_base = ""

    def __init__(
        self,
        api_key: str,
        timeout: int = 30,
        rate_limit_por_minuto: int = 60,
        tentativas: int = TENTATIVAS_PADRAO,
    ):
        self._api_key = api_key or ""
        self.timeout = timeout
        self.tentativas = max(1, tentativas)
        self.limitador = LimitadorDeTaxa(rate_limit_por_minuto)
        self.sessao = requests.Session()
        self.sessao.headers.update({"User-Agent": "NutShellMapper/1.0"})

    @property
    def habilitado(self) -> bool:
        """False quando nao ha chave: as consultas viram no-op com aviso."""
        return bool(self._api_key)

    def _sanitizar(self, texto: str) -> str:
        return _limpar_segredo(str(texto), (self._api_key,))

    def _requisitar(
        self,
        caminho: str,
        parametros: dict | None = None,
        cabecalhos: dict | None = None,
        metodo: str = "GET",
        formulario: dict | None = None,
        bruto: bool = False,
    ) -> RespostaEnriquecimento:
        """
        Faz uma requisicao com limite de taxa e repeticao.

        Args:
            metodo: "GET" ou "POST". O abuse.ch so aceita POST com
                form-data, diferente do VirusTotal e do Shodan.
            formulario: campos do form-data, para POST.
            bruto: quando True, guarda o corpo em `conteudo` sem tentar
                interpretar como JSON. Usado no download de amostra, que
                devolve um ZIP.

        Nunca levanta excecao de rede: devolve RespostaEnriquecimento com o
        erro ja sanitizado.
        """
        resposta = RespostaEnriquecimento(fonte=self.nome)

        if not self.habilitado:
            resposta.erro = f"chave de API do {self.nome} não configurada"
            return resposta

        url = f"{self.url_base.rstrip('/')}/{caminho.lstrip('/')}"
        espera = ESPERA_INICIAL

        for tentativa in range(1, self.tentativas + 1):
            self.limitador.aguardar()

            try:
                if metodo.upper() == "POST":
                    http = self.sessao.post(
                        url,
                        params=parametros,
                        data=formulario,
                        headers=cabecalhos,
                        timeout=self.timeout,
                    )
                else:
                    http = self.sessao.get(
                        url,
                        params=parametros,
                        headers=cabecalhos,
                        timeout=self.timeout,
                    )
            except requests.RequestException as erro:
                # O texto da excecao pode conter a URL inteira, com a chave.
                detalhe = self._sanitizar(erro)
                if tentativa < self.tentativas:
                    logger.debug(
                        "%s: falha de rede (%s), tentativa %d/%d",
                        self.nome, detalhe, tentativa, self.tentativas,
                    )
                    time.sleep(espera)
                    espera *= 2
                    continue
                resposta.erro = f"falha de rede: {detalhe}"
                return resposta

            # --- Resposta obtida ---

            if http.status_code == 404:
                # O servico respondeu que nao conhece o indicador. Isso e
                # uma consulta bem-sucedida, com resultado negativo.
                resposta.consultado = True
                resposta.encontrado = False
                return resposta

            if http.status_code in (401, 403):
                resposta.erro = (
                    f"chave do {self.nome} rejeitada (HTTP {http.status_code}): "
                    "verifique se ela é válida e tem permissão para esta consulta"
                )
                return resposta

            if http.status_code in CODIGOS_REPETIVEIS and tentativa < self.tentativas:
                # O 429 pode trazer Retry-After; respeitar e mais educado e
                # mais eficiente do que o backoff cego.
                sugerido = http.headers.get("Retry-After")
                atraso = espera
                if sugerido and sugerido.isdigit():
                    atraso = min(float(sugerido), 120.0)
                logger.info(
                    "%s: HTTP %d, aguardando %.0fs (tentativa %d/%d)",
                    self.nome, http.status_code, atraso, tentativa, self.tentativas,
                )
                time.sleep(atraso)
                espera *= 2
                continue

            if not http.ok:
                resposta.erro = f"HTTP {http.status_code}: {self._sanitizar(http.text)[:200]}"
                return resposta

            if bruto:
                resposta.conteudo = http.content
                resposta.consultado = True
                resposta.encontrado = True
                return resposta

            try:
                resposta.dados = http.json()
            except ValueError:
                resposta.erro = "resposta não é JSON válido"
                return resposta

            resposta.consultado = True
            resposta.encontrado = True
            return resposta

        resposta.erro = f"esgotadas {self.tentativas} tentativas"
        return resposta

    def fechar(self) -> None:
        self.sessao.close()

    def __enter__(self) -> "ClienteBase":
        return self

    def __exit__(self, *_) -> None:
        self.fechar()

    def __repr__(self) -> str:
        """Nunca inclui a chave."""
        estado = "com chave" if self.habilitado else "sem chave"
        return f"<{type(self).__name__} {estado}>"
