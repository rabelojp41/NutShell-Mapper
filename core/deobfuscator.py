"""
Deteccao e reversao de ofuscacao em strings e blobs.

Malware raramente deixa o C2 em texto claro. O padrao e esconder atras de
Base64, XOR de chave unica, hex, ROT13 ou compressao - as vezes encadeados
("stager" tipico: Base64 -> XOR -> zlib).

O problema central deste modulo nao e decodificar, e decidir *o que vale a
pena* tentar decodificar. Um binario gera centenas de strings; tentar Base64
em todas produz lixo binario que polui o resto do pipeline. Por isso:

  1. Triagem   - entropia de Shannon + razao de imprimiveis + formato.
                 Descarta de cara o que nao tem cara de dado codificado.
  2. Tentativa - aplica cada decodificador plausivel.
  3. Pontuacao - a saida so e aceita se parecer texto util. "CryptEncrypt"
                 e Base64 sintaticamente valido e decodifica em bytes sem
                 sentido; sem pontuacao, isso viraria um falso positivo.
  4. Cadeia    - repete sobre o resultado, ate um limite de profundidade.

Tudo que sai daqui volta para o detector de IOC do string_extractor: um C2
escondido atras de Base64 e exatamente o achado que mais importa.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import logging
import math
import re
import string as _string
import sys
import zlib
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Iterator, Sequence

from core.string_extractor import (
    IOC,
    StringExtraida,
    TipoString,
    detectar_iocs,
)

logger = logging.getLogger(__name__)


# ============================================================
# Parametros de heuristica
#
# Os limiares abaixo foram escolhidos para errar para o lado de tentar
# demais em vez de perder achado; o filtro de pontuacao na saida e quem
# faz o corte fino.
# ============================================================

# Abaixo disso nao ha informacao suficiente para valer uma tentativa.
TAMANHO_MINIMO_CANDIDATO = 8

# Texto em lingua natural fica por volta de 4.0-4.5 bits/byte. Dado
# codificado (Base64, hex) sobe; dado cifrado ou comprimido passa de 7.
ENTROPIA_MINIMA_CODIFICADO = 3.0

# Resultado precisa ser majoritariamente imprimivel para ser aceito.
RAZAO_IMPRIMIVEL_MINIMA = 0.85

# Nota minima (0.0-1.0) para um achado ser reportado.
PONTUACAO_MINIMA = 0.55

# Profundidade maxima da decodificacao encadeada.
PROFUNDIDADE_MAXIMA = 3

# Blob maior que isso nao e tentado byte a byte em XOR (custo x beneficio).
TAMANHO_MAXIMO_XOR = 1 << 20  # 1 MiB


# Palavras que, se aparecem no resultado, praticamente confirmam que a
# decodificacao foi correta. Sao os artefatos que malware costuma esconder.
ANCORAS = (
    "http://",
    "https://",
    "ftp://",
    "cmd.exe",
    "powershell",
    "rundll32",
    "regsvr32",
    "schtasks",
    "HKEY_",
    "HKCU",
    "HKLM",
    "SOFTWARE\\",
    "CurrentVersion\\Run",
    ".exe",
    ".dll",
    ".bat",
    ".ps1",
    ".php",
    ".vbs",
    "User-Agent",
    "Mozilla/",
    "POST ",
    "GET ",
    "Content-Type",
    "kernel32",
    "advapi32",
    "ws2_32",
    "wininet",
    "VirtualAlloc",
    "CreateProcess",
    "WriteProcessMemory",
    "LoadLibrary",
    "GetProcAddress",
    "AppData",
    "Temp\\",
    "System32",
    "SELECT ",
    "-----BEGIN",
)

# Charset valido de cada codificacao, para triagem rapida.
RE_BASE64 = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
RE_BASE64_URL = re.compile(r"^[A-Za-z0-9_-]{8,}={0,2}$")
RE_HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){4,}$")
RE_HEX_COM_SEPARADOR = re.compile(r"^(?:[0-9a-fA-F]{2}[\s:,\\x-]){4,}[0-9a-fA-F]{2}$")


# ============================================================
# Tipos
# ============================================================


class Tecnica(str, Enum):
    """Como o dado estava ofuscado."""

    BASE64 = "base64"
    BASE64_URL = "base64url"
    BASE32 = "base32"
    HEX = "hex"
    ROT13 = "rot13"
    XOR_1_BYTE = "xor_1_byte"
    ZLIB = "zlib"
    GZIP = "gzip"


@dataclass(frozen=True)
class Achado:
    """Uma decodificacao bem-sucedida."""

    original: str
    decodificado: str
    # Cadeia aplicada, na ordem. Ex.: [BASE64, XOR_1_BYTE]
    tecnicas: tuple[Tecnica, ...]
    # Chave usada, quando a tecnica tem uma (XOR). Formato "0x4d".
    chave: str | None
    # Nota 0.0-1.0 de quao plausivel e o resultado.
    pontuacao: float
    # Ancoras encontradas no resultado; e a evidencia mais concreta.
    ancoras: tuple[str, ...]
    # De onde veio a string original.
    tipo_string: TipoString = TipoString.STATIC

    @property
    def cadeia(self) -> str:
        """Representacao legivel da cadeia, ex.: 'base64 -> xor_1_byte(0x4d)'."""
        partes = [t.value for t in self.tecnicas]
        if self.chave:
            partes[-1] = f"{partes[-1]}({self.chave})"
        return " -> ".join(partes)


@dataclass
class ResultadoDesofuscacao:
    """Saida completa do modulo."""

    achados: list[Achado] = field(default_factory=list)
    # IOCs que so existiam atras da ofuscacao - o resultado mais valioso.
    iocs_revelados: list[IOC] = field(default_factory=list)
    # Quantas strings passaram pela triagem, para calibrar a heuristica.
    candidatos_avaliados: int = 0

    def por_tecnica(self, tecnica: Tecnica) -> list[Achado]:
        """Achados que usaram determinada tecnica em qualquer ponto da cadeia."""
        return [a for a in self.achados if tecnica in a.tecnicas]

    def resumo(self) -> dict[str, int]:
        contagem: Counter[str] = Counter()
        for a in self.achados:
            contagem[a.tecnicas[0].value] += 1
        return {
            "candidatos_avaliados": self.candidatos_avaliados,
            "achados": len(self.achados),
            "iocs_revelados": len(self.iocs_revelados),
            **{f"tecnica_{k}": v for k, v in sorted(contagem.items())},
        }

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# Metricas
# ============================================================


def entropia_shannon(dados: bytes | str) -> float:
    """
    Entropia de Shannon em bits por byte (0.0 a 8.0).

    Referencia pratica:
      < 3.0  texto repetitivo, preenchimento
      ~ 4.5  texto em lingua natural
      ~ 5.0  Base64 de dado binario
      > 7.0  comprimido, cifrado ou empacotado
    """
    if isinstance(dados, str):
        dados = dados.encode("utf-8", "replace")
    if not dados:
        return 0.0

    total = len(dados)
    return -sum(
        (n / total) * math.log2(n / total) for n in Counter(dados).values()
    )


def razao_imprimivel(dados: bytes) -> float:
    """Fracao dos bytes que sao ASCII imprimivel, tab, CR ou LF."""
    if not dados:
        return 0.0
    imprimiveis = sum(
        1 for b in dados if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return imprimiveis / len(dados)


# Caracteres que aparecem em texto, caminho, URL e linha de comando reais.
# Tudo fora daqui e sinal de que o "resultado" ainda e lixo.
CARACTERES_DE_TEXTO = frozenset(
    _string.ascii_letters + _string.digits + " ._-/\\:@?=&%+#'\"(),;!*~$[]{}<>\n\r\t"
)

# Fracao minima de caracteres de texto para um resultado ser considerado
# legivel. Vale so para as tecnicas que preservam a forma de texto.
LEGIBILIDADE_MINIMA = 0.90

# Comprimento minimo do texto decodificado para as tecnicas que preservam
# forma. Abaixo disso, acertar uma ancora por acaso e esperado: um PDF
# produziu ".bat(" - cinco caracteres, legiveis, com ancora dentro, e sem
# significado nenhum.
TAMANHO_MINIMO_DECODIFICADO = 12


def legibilidade(texto: str) -> float:
    """
    Fracao de caracteres que ocorrem em texto, caminho ou URL reais.

    Complementa a razao de imprimiveis, que e cega demais: "^A.DLLLOLL^" e
    100% imprimivel e contem a ancora ".dll", mas nao e texto nenhum.
    """
    if not texto:
        return 0.0
    return sum(1 for c in texto if c in CARACTERES_DE_TEXTO) / len(texto)


def _ancoras_em(texto: str) -> tuple[str, ...]:
    """Ancoras presentes no texto, comparadas sem diferenciar maiuscula."""
    minusculo = texto.lower()
    return tuple(a for a in ANCORAS if a.lower() in minusculo)


def pontuar(dados: bytes) -> tuple[float, tuple[str, ...]]:
    """
    Avalia se o resultado de uma decodificacao parece texto util.

    Este e o filtro que separa decodificacao real de coincidencia. Combina
    tres sinais:
      - razao de imprimiveis (peso maior: lixo binario morre aqui)
      - presenca de ancoras (evidencia forte e direta)
      - variedade de caracteres compativel com texto, nao com ruido

    Devolve (nota de 0.0 a 1.0, ancoras encontradas).
    """
    if len(dados) < 4:
        return 0.0, ()

    razao = razao_imprimivel(dados)
    if razao < RAZAO_IMPRIMIVEL_MINIMA:
        return 0.0, ()

    texto = dados.decode("utf-8", "replace")
    ancoras = _ancoras_em(texto)

    # Base: o quao imprimivel e, normalizado na faixa util (0.85-1.0).
    nota = (razao - RAZAO_IMPRIMIVEL_MINIMA) / (1.0 - RAZAO_IMPRIMIVEL_MINIMA)
    nota *= 0.45

    # Ancora e a evidencia mais forte: uma ja basta para aceitar o achado.
    if ancoras:
        nota += 0.45 + min(len(ancoras) - 1, 3) * 0.03

    # Texto real tem entropia moderada. Muito baixa indica preenchimento
    # ("AAAAAAAA"); muito alta indica que ainda e binario disfarcado.
    ent = entropia_shannon(dados)
    if 2.5 <= ent <= 5.5:
        nota += 0.15
    elif ent < 1.5:
        nota -= 0.20

    # Sequencia de letras/digitos separada por espaco ou pontuacao lembra
    # linguagem; sopa de simbolos, nao.
    alfanumericos = sum(1 for c in texto if c.isalnum() or c in " ._-/\\:")
    if alfanumericos / len(texto) > 0.80:
        nota += 0.10

    return max(0.0, min(1.0, nota)), ancoras


# ============================================================
# Triagem: vale a pena tentar?
# ============================================================


# Palavras muito frequentes em ingles e portugues. Duas delas numa string
# ja indicam prosa em texto claro - e prosa em claro nao tem o que
# desofuscar. Sem este corte, mensagens de erro do proprio compilador eram
# tratadas como candidatas a ROT13 e produziam achados falsos.
PALAVRAS_COMUNS = frozenset(
    """
    the and for not you your this that with from have has was were are is
    it in to of on at by or as be an if can could would should will
    error failed failure unable cannot invalid missing expected found
    file files open close read write create delete name value
    de do da dos das que nao para com uma como mais ser foi sao esta este
    erro falha arquivo nome valor
    """.split()
)

RE_PALAVRA = re.compile(r"[A-Za-z]{2,}")


def parece_texto_claro(valor: str) -> bool:
    """
    Detecta prosa que ja esta legivel.

    Serve de corte na triagem: "This indicates a bug in your application"
    e 100% alfabetica, entao a regra ingenua de "muita letra, pode ser
    ROT13" a aceitava. Rodar ROT13 e XOR sobre prosa gera lixo que, por
    coincidencia, as vezes contem uma ancora como ".dll" ou "HKLM".
    """
    palavras = {p.lower() for p in RE_PALAVRA.findall(valor)}
    return len(palavras & PALAVRAS_COMUNS) >= 2


def _limpar(valor: str) -> str:
    """Remove espacos em branco das bordas e aspas que cercam a string."""
    return valor.strip().strip("\"'`")


def parece_codificado(valor: str) -> bool:
    """
    Triagem barata antes de gastar CPU com decodificacao.

    Rejeita o obvio: string curta demais, texto em claro que ja e legivel e
    util, e sopa de caracteres sem estrutura de codificacao nenhuma.
    """
    valor = _limpar(valor)

    if len(valor) < TAMANHO_MINIMO_CANDIDATO:
        return False

    # Se a string ja contem uma ancora, ela ja esta em claro - nao ha o que
    # desofuscar. (O XOR ainda e tentado a parte, sobre o blob bruto.)
    if _ancoras_em(valor):
        return False

    # Prosa legivel tambem ja esta em claro.
    if parece_texto_claro(valor):
        return False

    # Formato reconhecivel de codificacao passa direto.
    compacto = re.sub(r"\s+", "", valor)
    if (
        RE_BASE64.match(compacto)
        or RE_BASE64_URL.match(compacto)
        or RE_HEX.match(compacto)
        or RE_HEX_COM_SEPARADOR.match(valor)
    ):
        return True

    # ROT13 preserva a forma de texto: aceita qualquer coisa alfabetica.
    if sum(1 for c in valor if c.isalpha()) / len(valor) > 0.6:
        return True

    return entropia_shannon(valor) >= ENTROPIA_MINIMA_CODIFICADO


# ============================================================
# Decodificadores
#
# Cada um recebe bytes e devolve (tecnica, chave, bytes) ou nada.
# Nenhum decide se o resultado presta - isso e trabalho da pontuacao.
# ============================================================


def _decodificar_base64(dados: bytes) -> Iterator[tuple[Tecnica, None, bytes]]:
    """Base64 padrao e URL-safe, com correcao de preenchimento ausente."""
    compacto = re.sub(rb"\s+", b"", dados)
    if len(compacto) < 8:
        return

    # Muito malware corta o "=" final; recoloca antes de tentar.
    faltando = (-len(compacto)) % 4
    if faltando == 3:
        return  # comprimento impossivel para Base64
    preenchido = compacto + b"=" * faltando

    if RE_BASE64.match(compacto.rstrip(b"=").decode("ascii", "ignore")):
        try:
            yield Tecnica.BASE64, None, base64.b64decode(preenchido, validate=True)
        except (binascii.Error, ValueError):
            pass

    if RE_BASE64_URL.match(compacto.rstrip(b"=").decode("ascii", "ignore")):
        try:
            yield Tecnica.BASE64_URL, None, base64.urlsafe_b64decode(preenchido)
        except (binascii.Error, ValueError):
            pass


def _decodificar_base32(dados: bytes) -> Iterator[tuple[Tecnica, None, bytes]]:
    """Base32, menos comum mas usado em DNS tunneling."""
    compacto = re.sub(rb"\s+", b"", dados).upper()
    if len(compacto) < 16 or not re.fullmatch(rb"[A-Z2-7]+=*", compacto):
        return
    preenchido = compacto + b"=" * ((-len(compacto)) % 8)
    try:
        yield Tecnica.BASE32, None, base64.b32decode(preenchido)
    except (binascii.Error, ValueError):
        pass


def _decodificar_hex(dados: bytes) -> Iterator[tuple[Tecnica, None, bytes]]:
    """Hex puro ou com separador (":", "-", " ", "\\x")."""
    texto = dados.decode("ascii", "ignore")
    compacto = re.sub(r"(?:0x|\\x|[\s:,-])", "", texto)
    if len(compacto) < 8 or len(compacto) % 2 or not RE_HEX.match(compacto):
        return
    try:
        yield Tecnica.HEX, None, bytes.fromhex(compacto)
    except ValueError:
        pass


def _decodificar_rot13(dados: bytes) -> Iterator[tuple[Tecnica, None, bytes]]:
    """ROT13. So faz sentido sobre texto alfabetico."""
    try:
        texto = dados.decode("ascii")
    except UnicodeDecodeError:
        return
    if sum(1 for c in texto if c.isalpha()) < 4:
        return
    yield Tecnica.ROT13, None, codecs.encode(texto, "rot_13").encode("ascii")


def _decodificar_zlib(dados: bytes) -> Iterator[tuple[Tecnica, None, bytes]]:
    """zlib com e sem cabecalho (raw deflate)."""
    for wbits, tecnica in ((zlib.MAX_WBITS, Tecnica.ZLIB), (-zlib.MAX_WBITS, Tecnica.ZLIB)):
        try:
            saida = zlib.decompress(dados, wbits)
        except zlib.error:
            continue
        if saida:
            yield tecnica, None, saida
            return


def _decodificar_gzip(dados: bytes) -> Iterator[tuple[Tecnica, None, bytes]]:
    """gzip, identificado pelo magic 1f 8b."""
    if not dados.startswith(b"\x1f\x8b"):
        return
    try:
        yield Tecnica.GZIP, None, gzip.decompress(dados)
    except (OSError, EOFError, zlib.error):
        pass


def _decodificar_xor_1_byte(dados: bytes) -> Iterator[tuple[Tecnica, str, bytes]]:
    """
    Forca bruta de XOR com chave de um byte (255 possibilidades).

    Testar todas e barato e o espaco e minusculo, entao nao ha heuristica
    para escolher chave - quem separa o resultado certo dos 254 errados e a
    pontuacao. A chave 0x00 e pulada porque seria a identidade.
    """
    if not (4 <= len(dados) <= TAMANHO_MAXIMO_XOR):
        return

    for chave in range(1, 256):
        saida = bytes(b ^ chave for b in dados)
        # Corte barato antes de pontuar: a esmagadora maioria das 255
        # chaves produz binario, e razao_imprimivel e muito mais rapida
        # que a pontuacao completa.
        if razao_imprimivel(saida) < RAZAO_IMPRIMIVEL_MINIMA:
            continue
        yield Tecnica.XOR_1_BYTE, f"0x{chave:02x}", saida


# Ordem importa: as codificacoes com formato reconhecivel vem antes do XOR,
# que e o mais propenso a falso positivo.
DECODIFICADORES = (
    _decodificar_base64,
    _decodificar_base32,
    _decodificar_hex,
    _decodificar_gzip,
    _decodificar_zlib,
    _decodificar_rot13,
    _decodificar_xor_1_byte,
)


# ============================================================
# Motor de decodificacao encadeada
# ============================================================


# Tecnicas que transformam texto em texto. Para elas, "a saida e imprimivel"
# nao prova nada: ROT13 de qualquer palavra e sempre imprimivel, e XOR de
# texto ASCII por uma chave pequena tambem costuma ser. So sao aceitas com
# ancora, isto e, com evidencia concreta no conteudo.
#
# As demais (Base64, hex, zlib, gzip) se autovalidam: decodificar dado
# aleatorio por esses caminhos quase nunca produz 85% de bytes imprimiveis.
TECNICAS_QUE_PRESERVAM_FORMA = frozenset({Tecnica.ROT13, Tecnica.XOR_1_BYTE})


def _aceitar(
    cadeia: tuple[Tecnica, ...],
    nota: float,
    ancoras: tuple[str, ...],
    saida: bytes,
) -> bool:
    """
    Decide se uma decodificacao vira achado reportado.

    Para ROT13 e XOR, exigir ancora nao basta: a ancora pode cair dentro de
    lixo por coincidencia. Um XOR de string binaria produziu "^A.DLLLOLL^",
    que contem ".dll" e passava. Dai a exigencia adicional de legibilidade,
    que olha a forma do resultado inteiro e nao so um trecho dele.
    """
    if nota < PONTUACAO_MINIMA:
        return False

    if TECNICAS_QUE_PRESERVAM_FORMA.intersection(cadeia):
        if not ancoras:
            return False

        texto = saida.decode("utf-8", "replace")

        if legibilidade(texto) < LEGIBILIDADE_MINIMA:
            return False

        # Resultado curto nao prova nada, mesmo contendo ancora. Um PDF
        # produziu ".bat(" por "rot13 -> xor -> rot13": cinco caracteres,
        # legiveis, com a ancora ".bat" dentro - e completamente sem
        # sentido. Com tao poucos bytes, acertar uma ancora por acaso e
        # esperado, nao notavel.
        if len(texto.strip()) < TAMANHO_MINIMO_DECODIFICADO:
            return False

        # ROT13 duas vezes na mesma cadeia e sinal de busca as cegas: a
        # transformacao e involutiva, entao o unico efeito de repeti-la e
        # mascarar que o resultado veio de coincidencia do que estiver no
        # meio.
        if cadeia.count(Tecnica.ROT13) > 1:
            return False

    return True


def _explorar(
    dados: bytes,
    vistos: set[bytes],
) -> Iterator[tuple[tuple[Tecnica, ...], str | None, bytes, float, tuple[str, ...]]]:
    """
    Explora as cadeias de decodificacao em largura.

    A busca e em largura, e nao em profundidade, de proposito: garante que o
    primeiro caminho encontrado ate um resultado seja o mais curto. Em
    profundidade, uma cadeia longa marcava o resultado como visto e
    bloqueava a cadeia curta equivalente - na pratica, "xor(0x22) ->
    xor(0x08)" era reportado no lugar de "xor(0x2a)", com a chave errada.

    `vistos` tambem evita laco: ROT13 aplicado duas vezes volta ao original.
    """
    fila: deque[tuple[bytes, tuple[Tecnica, ...], str | None, int]] = deque(
        [(dados, (), None, 0)]
    )

    while fila:
        atual, cadeia, chave, profundidade = fila.popleft()
        if profundidade >= PROFUNDIDADE_MAXIMA:
            continue

        for decodificador in DECODIFICADORES:
            # XOR encadeado com XOR e redundante: XOR(k1) seguido de XOR(k2)
            # equivale a XOR(k1^k2), entao a cadeia longa nunca revela nada
            # novo - so confunde qual e a chave real.
            if decodificador is _decodificar_xor_1_byte and Tecnica.XOR_1_BYTE in cadeia:
                continue

            for tecnica, chave_nova, saida in decodificador(atual):
                if not saida or saida in vistos:
                    continue
                vistos.add(saida)

                nova_cadeia = cadeia + (tecnica,)
                nota, ancoras = pontuar(saida)

                if _aceitar(nova_cadeia, nota, ancoras, saida):
                    yield nova_cadeia, chave_nova or chave, saida, nota, ancoras

                # Segue a cadeia mesmo com nota baixa: o estagio intermediario
                # de um stager (Base64 -> zlib) costuma ser binario e so faz
                # sentido no final.
                fila.append((saida, nova_cadeia, chave_nova or chave, profundidade + 1))


def desofuscar_valor(
    valor: str,
    tipo_string: TipoString = TipoString.STATIC,
    pular_triagem: bool = False,
) -> list[Achado]:
    """
    Tenta reverter a ofuscacao de uma unica string.

    Args:
        valor: a string a analisar.
        tipo_string: de onde ela veio (registrado no achado).
        pular_triagem: forca a tentativa mesmo que a heuristica descarte.
            Util em teste e quando o analista aponta a string na GUI.

    Returns:
        Achados ordenados por pontuacao, sem duplicata de conteudo.
    """
    limpo = _limpar(valor)
    if not pular_triagem and not parece_codificado(limpo):
        return []

    dados = limpo.encode("utf-8", "replace")
    melhores: dict[str, Achado] = {}

    for cadeia, chave, saida, nota, ancoras in _explorar(dados, {dados}):
        texto = saida.decode("utf-8", "replace")

        # O mesmo texto pode ser alcancado por caminhos diferentes; fica o
        # de maior pontuacao, e em empate o de cadeia mais curta.
        atual = melhores.get(texto)
        if atual is None or (nota, -len(cadeia)) > (atual.pontuacao, -len(atual.tecnicas)):
            melhores[texto] = Achado(
                original=limpo,
                decodificado=texto,
                tecnicas=cadeia,
                chave=chave,
                pontuacao=round(nota, 3),
                ancoras=ancoras,
                tipo_string=tipo_string,
            )

    return sorted(melhores.values(), key=lambda a: -a.pontuacao)


def desofuscar(
    strings: Sequence[StringExtraida],
    limite_por_string: int = 3,
) -> ResultadoDesofuscacao:
    """
    Roda a desofuscacao sobre todas as strings de um artefato.

    Args:
        strings: saida do string_extractor.
        limite_por_string: quantos achados manter por string de origem.
            Sem limite, o XOR brute-force pode devolver varias chaves
            plausiveis para o mesmo dado e inundar o relatorio.

    Returns:
        ResultadoDesofuscacao com os achados e os IOCs que estavam escondidos.
    """
    resultado = ResultadoDesofuscacao()
    vistas: set[str] = set()

    for s in strings:
        # A mesma string costuma aparecer varias vezes no binario.
        if s.valor in vistas:
            continue
        vistas.add(s.valor)

        if not parece_codificado(_limpar(s.valor)):
            continue

        resultado.candidatos_avaliados += 1
        achados = desofuscar_valor(s.valor, s.tipo, pular_triagem=True)
        resultado.achados.extend(achados[:limite_por_string])

    resultado.achados.sort(key=lambda a: -a.pontuacao)

    # O ponto do modulo: procurar IOC no conteudo revelado. Um C2 atras de
    # Base64 nao aparece na varredura do string_extractor.
    revelados = [
        StringExtraida(valor=a.decodificado, tipo=a.tipo_string)
        for a in resultado.achados
    ]
    resultado.iocs_revelados = detectar_iocs(revelados)

    logger.info("desofuscacao concluida: %s", resultado.resumo())
    return resultado


def desofuscar_blob(dados: bytes, rotulo: str = "<blob>") -> list[Achado]:
    """
    Aplica a desofuscacao sobre bytes crus (secao de PE, recurso embutido).

    Diferente de desofuscar_valor, nao ha triagem textual: o chamador ja
    decidiu que o blob interessa, tipicamente por ter entropia alta.
    """
    melhores: dict[str, Achado] = {}

    for cadeia, chave, saida, nota, ancoras in _explorar(dados, {dados}):
        texto = saida.decode("utf-8", "replace")
        atual = melhores.get(texto)
        if atual is None or nota > atual.pontuacao:
            melhores[texto] = Achado(
                original=rotulo,
                decodificado=texto,
                tecnicas=cadeia,
                chave=chave,
                pontuacao=round(nota, 3),
                ancoras=ancoras,
            )

    return sorted(melhores.values(), key=lambda a: -a.pontuacao)


# ============================================================
# Execucao direta
# ============================================================


def _main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import json

    from core.string_extractor import ErroExtracao, extrair

    parser = argparse.ArgumentParser(
        description="Detecta e reverte ofuscacao em strings (RabMapper)."
    )
    parser.add_argument("arquivo", nargs="?", help="artefato a analisar")
    parser.add_argument("-s", "--string", help="desofusca uma string solta")
    parser.add_argument("--sem-floss", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.string:
        achados = desofuscar_valor(args.string, pular_triagem=True)
        if not achados:
            print("nenhuma decodificacao plausivel")
            return 0
        for a in achados:
            print(f"[{a.pontuacao:.2f}] {a.cadeia}")
            print(f"        {a.decodificado!r}")
            if a.ancoras:
                print(f"        ancoras: {', '.join(a.ancoras)}")
        return 0

    if not args.arquivo:
        parser.error("informe um arquivo ou use --string")

    try:
        extracao = extrair(args.arquivo, usar_floss=not args.sem_floss)
    except ErroExtracao as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1

    resultado = desofuscar(extracao.strings)

    if args.json:
        print(json.dumps(resultado.to_dict(), indent=2, ensure_ascii=False))
        return 0

    print(f"\nResumo: {resultado.resumo()}")

    if resultado.achados:
        print(f"\nAchados ({len(resultado.achados)}):")
        for a in resultado.achados[:40]:
            print(f"  [{a.pontuacao:.2f}] {a.cadeia}")
            print(f"         de : {a.original[:70]}")
            print(f"         para: {a.decodificado[:70]!r}")
    else:
        print("\nNenhuma ofuscacao detectada.")

    if resultado.iocs_revelados:
        print(f"\nIOCs revelados ({len(resultado.iocs_revelados)}):")
        for i in resultado.iocs_revelados:
            print(f"  [{i.confianca.value:5}] {i.tipo.value:16} {i.valor}")

    return 0


if __name__ == "__main__":
    sys.exit(_main())
