"""
Extracao de strings e identificacao de IOCs.

Este e o modulo-base do RabMapper: todos os outros (deobfuscator,
yara_generator, mitre_mapper) consomem o que sai daqui.

Estrategia de extracao:

1. FLOSS (preferencial) - roda o binario num emulador e recupera quatro
   categorias de string:
     - static   : bytes literais no arquivo (ASCII / UTF-16LE)
     - stack    : montadas byte a byte na pilha em tempo de execucao
     - tight    : montadas dentro de um laco apertado
     - decoded  : produzidas por rotina de decodificacao do proprio malware
   As tres ultimas sao o diferencial do FLOSS: nao aparecem num `strings`
   comum, justamente porque so existem em memoria.

2. Extrator nativo (fallback) - varredura por regex em ASCII e UTF-16LE.
   Usado quando o FLOSS falha (arquivo nao-PE, timeout, emulacao travada).
   Recupera apenas strings estaticas, mas nunca deixa o pipeline sem dado.

Sobre os IOCs: a deteccao e por regex, e regex sozinha gera muito falso
positivo em binario. Cada candidato passa por um filtro de plausibilidade e
recebe um nivel de confianca, em vez de ser aceito ou descartado no grito.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Sequence

logger = logging.getLogger(__name__)

# Tamanho minimo padrao de uma string para ser considerada relevante.
TAMANHO_MINIMO_PADRAO = 4

# Emulacao do FLOSS pode demorar bastante em binario grande.
TIMEOUT_FLOSS_PADRAO = 300

# Formatos que o FLOSS sabe analisar. O "auto" dele so reconhece PE: para
# shellcode cru e preciso dizer a arquitetura explicitamente, porque nao ha
# cabecalho nenhum de onde deduzi-la.
FORMATOS_FLOSS = ("pe", "sc32", "sc64")

# Trecho da mensagem com que o FLOSS recusa um arquivo sem cabecalho de PE.
RECUSA_DE_SHELLCODE = "--format sc32|sc64"


# ============================================================
# Tipos
# ============================================================


class TipoString(str, Enum):
    """Origem da string, conforme a categorizacao do FLOSS."""

    STATIC = "static"
    STACK = "stack"
    TIGHT = "tight"
    DECODED = "decoded"


class TipoIOC(str, Enum):
    """Categoria do indicador de comprometimento."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMINIO = "dominio"
    URL = "url"
    EMAIL = "email"
    CAMINHO_WINDOWS = "caminho_windows"
    CAMINHO_UNC = "caminho_unc"
    CHAVE_REGISTRO = "chave_registro"
    HASH = "hash"
    BITCOIN = "bitcoin"


class Confianca(str, Enum):
    """
    Quao provavel e que o candidato seja mesmo um IOC.

    ALTA  - formato inequivoco (URL completa, chave de registro, UNC).
    MEDIA - formato valido, mas o contexto nao confirma.
    BAIXA - casa com a regex, porem ha razao concreta para desconfiar
            (ex.: "1.2.3.4" que na verdade e um numero de versao).
    """

    ALTA = "alta"
    MEDIA = "media"
    BAIXA = "baixa"


# Peso numerico das confiancas, usado para ordenar e deduplicar.
PESO_CONFIANCA = {Confianca.ALTA: 3, Confianca.MEDIA: 2, Confianca.BAIXA: 1}


@dataclass(frozen=True)
class StringExtraida:
    """Uma string recuperada do artefato."""

    valor: str
    tipo: TipoString
    encoding: str = "ASCII"
    # Offset no arquivo (static) ou endereco em memoria (stack/tight/decoded).
    endereco: int | None = None
    # Endereco da rotina que produziu a string (so para decoded/stack/tight).
    rotina: int | None = None

    def __len__(self) -> int:
        return len(self.valor)


@dataclass(frozen=True)
class IOC:
    """Um indicador de comprometimento e de onde ele veio."""

    valor: str
    tipo: TipoIOC
    confianca: Confianca
    # String completa em que o indicador foi encontrado, para dar contexto.
    origem: str
    tipo_string: TipoString
    # Explica por que a confianca nao e ALTA, quando for o caso.
    observacao: str = ""


@dataclass
class ResultadoExtracao:
    """Tudo que o modulo produziu para um artefato."""

    caminho: str
    tamanho_bytes: int
    md5: str
    sha256: str

    strings: list[StringExtraida] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)

    # Dados de execucao, uteis para o relatorio saber no que confiar.
    usou_floss: bool = False
    # Formato com que o FLOSS analisou: pe, sc32, sc64 ou auto.
    formato_floss: str = ""
    avisos: list[str] = field(default_factory=list)

    # --- Consultas de conveniencia ---

    def por_tipo(self, tipo: TipoString) -> list[StringExtraida]:
        """Strings de uma categoria especifica."""
        return [s for s in self.strings if s.tipo is tipo]

    def iocs_por_tipo(self, tipo: TipoIOC) -> list[IOC]:
        """IOCs de uma categoria especifica."""
        return [i for i in self.iocs if i.tipo is tipo]

    def valores_unicos(self) -> list[str]:
        """Texto das strings, sem repeticao, preservando a ordem."""
        vistos: set[str] = set()
        unicos: list[str] = []
        for s in self.strings:
            if s.valor not in vistos:
                vistos.add(s.valor)
                unicos.append(s.valor)
        return unicos

    def resumo(self) -> dict[str, int]:
        """Contagem por categoria, para log e cabecalho de relatorio."""
        return {
            "total_strings": len(self.strings),
            "static": len(self.por_tipo(TipoString.STATIC)),
            "stack": len(self.por_tipo(TipoString.STACK)),
            "tight": len(self.por_tipo(TipoString.TIGHT)),
            "decoded": len(self.por_tipo(TipoString.DECODED)),
            "iocs": len(self.iocs),
        }

    def to_dict(self) -> dict:
        """Serializa para JSON (consumido pelo report_generator e pela GUI)."""
        return asdict(self)


class ErroExtracao(Exception):
    """Falha irrecuperavel na extracao (arquivo ausente, vazio ou ilegivel)."""


# ============================================================
# Regex de IOC
# ============================================================

# IPv4 com validacao de faixa (0-255) na propria regex, para nao aceitar
# coisas como 999.1.1.1.
_OCTETO = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
RE_IPV4 = re.compile(rf"(?<![\w.]){_OCTETO}(?:\.{_OCTETO}){{3}}(?![\w.])")

# IPv6: forma completa ou comprimida com "::".
RE_IPV6 = re.compile(
    r"(?<![\w:])(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r")(?![\w:])"
)

RE_URL = re.compile(
    r"\b(?:https?|ftps?|wss?)://[^\s\"'<>|\\^`{}]{3,2048}",
    re.IGNORECASE,
)

RE_DOMINIO = re.compile(
    r"(?<![\w.@-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}(?![\w-])"
)

RE_EMAIL = re.compile(
    r"(?<![\w.-])[a-zA-Z0-9._%+-]{1,64}@"
    r"(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}(?![\w-])"
)

# C:\Users\...  (aceita barra normal tambem, comum em string de configuracao)
RE_CAMINHO_WINDOWS = re.compile(
    r"(?<![\w:])[A-Za-z]:[\\/](?:[^\\/:*?\"<>|\r\n]{1,255}[\\/])*"
    r"[^\\/:*?\"<>|\r\n]{0,255}"
)

# \\servidor\compartilhamento\...
RE_CAMINHO_UNC = re.compile(
    r"\\\\[A-Za-z0-9._-]{1,63}\\[^\\/:*?\"<>|\r\n]{1,255}"
    r"(?:\\[^\\/:*?\"<>|\r\n]{1,255})*"
)

RE_CHAVE_REGISTRO = re.compile(
    r"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
    r"|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"(?:[\\/][^\\/:*?\"<>|\r\n]{1,255})+",
    re.IGNORECASE,
)

# Chaves de persistencia sem o prefixo de hive, comuns em string de malware.
RE_CHAVE_REGISTRO_RELATIVA = re.compile(
    r"(?<![\w\\])(?:SOFTWARE|SYSTEM)\\[^\\/:*?\"<>|\r\n]{1,255}"
    r"(?:\\[^\\/:*?\"<>|\r\n]{1,255})*",
    re.IGNORECASE,
)

RE_HASH = re.compile(
    r"(?<![\w])(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})(?![\w])"
)

RE_BITCOIN = re.compile(
    r"(?<![\w])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})(?![\w])"
)


# ============================================================
# Listas de apoio para filtrar falso positivo
# ============================================================

# TLDs aceitos. Uma lista fechada evita que "kernel32.dll" ou "config.ini"
# sejam classificados como dominio - o erro mais comum de extrator ingenuo.
TLDS_VALIDOS = frozenset(
    """
    com net org edu gov mil int info biz name pro co io ai app dev xyz online
    site shop store tech cloud space website live life world today news blog
    click link top win men loan work party review country stream gdn
    ru cn br uk de fr jp it es nl pl se no fi dk cz ro gr pt hu at ch be ie
    ua kz by tr in id my sg th vn ph kr tw hk au nz za ng ke eg ma ar cl mx
    pe ve uy py bo ec cr pa gt hn ni sv do cu pr jm tt bs bb
    su cc tv me ws to tk ml ga cf gq pw st nu fm am fo gl is li lu mc sm va
    onion bit lib bazar coin emc
    """.split()
)

# Extensoes de arquivo que a regex de dominio casa por engano.
EXTENSOES_ARQUIVO = frozenset(
    """
    dll exe sys ocx drv cpl scr bat cmd ps1 vbs js jse vbe wsf hta msi
    txt log ini cfg conf xml json yaml yml csv dat db sqlite bin tmp bak
    png jpg jpeg gif bmp ico svg webp pdf doc docx xls xlsx ppt pptx rtf
    zip rar gz tar cab iso lnk url pif reg pdb map obj lib res rc
    html htm css php asp aspx jsp py rb pl sh c cpp h hpp cs java class
    mui nls chm hlp ttf otf fon wav mp3 mp4 avi mkv
    """.split()
)

# Hosts locais/reservados: sao IOCs fracos, quase sempre ruido.
IPS_RUIDO = frozenset(
    {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}
)

# Se a string contem uma destas palavras, um "IP" dentro dela provavelmente
# e um numero de versao.
PISTAS_DE_VERSAO = (
    "version",
    "versao",
    "build",
    "release",
    "assembly",
    "runtime",
)


# ============================================================
# Extracao via FLOSS
# ============================================================


def _localizar_floss() -> str | None:
    """
    Devolve o executavel do FLOSS.

    Prefere o floss do mesmo ambiente do interpretador em uso, para nao pegar
    por engano uma instalacao global de outra versao.
    """
    nome = "floss.exe" if sys.platform == "win32" else "floss"
    candidato = Path(sys.executable).parent / nome
    if candidato.exists():
        return str(candidato)
    return shutil.which("floss")


def _rodar_floss(
    caminho: Path,
    tamanho_minimo: int,
    timeout: int,
    formato: str | None = None,
) -> tuple[list[StringExtraida], list[str]]:
    """
    Executa o FLOSS e converte a saida JSON em StringExtraida.

    Args:
        formato: "pe", "sc32" ou "sc64". None deixa o FLOSS detectar, o que
            na pratica so funciona para PE.

    Devolve (strings, avisos). Levanta RuntimeError se o FLOSS nao puder ser
    usado - quem chama decide cair no fallback.
    """
    executavel = _localizar_floss()
    if executavel is None:
        raise RuntimeError("FLOSS nao encontrado no PATH nem no ambiente atual")

    comando = [executavel, "-j", "-n", str(tamanho_minimo)]
    if formato:
        comando += ["-f", formato]
    comando += ["--", str(caminho)]
    logger.debug("executando: %s", " ".join(comando))

    try:
        proc = subprocess.run(
            comando,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as erro:
        raise RuntimeError(f"FLOSS excedeu o timeout de {timeout}s") from erro
    except OSError as erro:
        raise RuntimeError(f"nao foi possivel executar o FLOSS: {erro}") from erro

    if proc.returncode == 0 and not proc.stdout.strip():
        # O FLOSS desiste da analise inteira, em silencio e com codigo 0,
        # quando o arquivo nao tem nenhuma string estatica - ha um
        # `if not static_strings: return 0` no main dele. Tratar isso como
        # "FLOSS falhou: codigo de saida 0" seria enganoso: ele rodou bem e
        # decidiu nao analisar.
        raise RuntimeError(
            "o FLOSS nao produziu saida; ele encerra sem analisar quando o "
            "arquivo nao contem nenhuma string estatica"
        )

    if proc.returncode != 0 or not proc.stdout.strip():
        detalhe = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        motivo = detalhe[-1] if detalhe else f"codigo de saida {proc.returncode}"
        raise RuntimeError(f"FLOSS falhou: {motivo}")

    try:
        dados = json.loads(proc.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError as erro:
        raise RuntimeError(f"saida do FLOSS nao e JSON valido: {erro}") from erro

    return _converter_json_floss(dados)


def _converter_json_floss(dados: dict) -> tuple[list[StringExtraida], list[str]]:
    """
    Normaliza o ResultDocument do FLOSS para o formato interno.

    Le o JSON de forma defensiva (.get em tudo) porque o esquema muda entre
    versoes do FLOSS e nao queremos quebrar o pipeline por um campo renomeado.
    """
    strings: list[StringExtraida] = []
    avisos: list[str] = []

    blocos = dados.get("strings", {})

    for item in blocos.get("static_strings", []):
        strings.append(
            StringExtraida(
                valor=item.get("string", ""),
                tipo=TipoString.STATIC,
                encoding=item.get("encoding", "ASCII"),
                endereco=item.get("offset"),
            )
        )

    for chave, tipo in (
        ("stack_strings", TipoString.STACK),
        ("tight_strings", TipoString.TIGHT),
    ):
        for item in blocos.get(chave, []):
            strings.append(
                StringExtraida(
                    valor=item.get("string", ""),
                    tipo=tipo,
                    encoding=item.get("encoding", "ASCII"),
                    endereco=item.get("program_counter"),
                    rotina=item.get("function"),
                )
            )

    for item in blocos.get("decoded_strings", []):
        strings.append(
            StringExtraida(
                valor=item.get("string", ""),
                tipo=TipoString.DECODED,
                encoding=item.get("encoding", "ASCII"),
                endereco=item.get("address"),
                rotina=item.get("decoding_routine"),
            )
        )

    # O FLOSS pode pular etapas (ex.: binario sem funcao reconhecida).
    # Registrar isso evita concluir "nao ha strings decodificadas" quando na
    # verdade a analise nem chegou a rodar.
    analise = dados.get("analysis", {})
    for campo, rotulo in (
        ("enable_stack_strings", "stack strings"),
        ("enable_tight_strings", "tight strings"),
        ("enable_decoded_strings", "strings decodificadas"),
    ):
        if analise.get(campo) is False:
            avisos.append(f"FLOSS nao analisou {rotulo}")

    return [s for s in strings if s.valor], avisos


# ============================================================
# Extrator nativo (fallback)
# ============================================================


def _extrair_nativo(dados: bytes, tamanho_minimo: int) -> list[StringExtraida]:
    """
    Varredura ASCII + UTF-16LE nos bytes crus.

    Equivale ao `strings` do Unix somado ao `strings -el`. Recupera so o que
    esta literal no arquivo - nada de stack ou decoded, que exigem emulacao.
    """
    strings: list[StringExtraida] = []

    padrao_ascii = re.compile(rb"[\x20-\x7e]{%d,}" % tamanho_minimo)
    for m in padrao_ascii.finditer(dados):
        strings.append(
            StringExtraida(
                valor=m.group().decode("ascii"),
                tipo=TipoString.STATIC,
                encoding="ASCII",
                endereco=m.start(),
            )
        )

    padrao_utf16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % tamanho_minimo)
    for m in padrao_utf16.finditer(dados):
        inicio, fim = m.start(), m.end()

        # Corrige desalinhamento. Quando uma string ASCII e seguida do seu
        # terminador nulo e logo depois vem uma string UTF-16LE, o ultimo
        # caractere da ASCII casa com o padrao e e roubado:
        #   "...VISIVEL\x00" + "U\x00N\x00..."  ->  "LUNICODE..."
        # Se o byte anterior ao casamento for ASCII imprimivel, o primeiro
        # caractere nao pertence a esta string. E o mesmo defeito do
        # `strings -el`.
        if inicio > 0 and 0x20 <= dados[inicio - 1] <= 0x7E:
            inicio += 2

        if (fim - inicio) // 2 < tamanho_minimo:
            continue

        strings.append(
            StringExtraida(
                valor=dados[inicio:fim].decode("utf-16-le"),
                tipo=TipoString.STATIC,
                encoding="UTF-16LE",
                endereco=inicio,
            )
        )

    strings.sort(key=lambda s: s.endereco or 0)
    return strings


# ============================================================
# Deteccao de IOC
# ============================================================


def _classificar_ipv4(texto: str, ip: str, dentro_de_url: bool) -> tuple[Confianca, str]:
    """
    Atribui confianca a um candidato a IPv4.

    Qualquer numero de versao com quatro campos casa com a regex de IPv4
    ("1.1.0.14" e a versao do simple_launcher, nao um C2). Como nao da para
    separar os dois casos com certeza, o candidato e mantido e rebaixado,
    com a observacao explicando o motivo - a decisao final fica com o analista.

    Devolve (confianca, observacao).
    """
    # Aparecer dentro de uma URL e a evidencia mais forte possivel.
    if dentro_de_url:
        return Confianca.ALTA, "aparece dentro de uma URL"

    if ip in IPS_RUIDO:
        return Confianca.BAIXA, "endereco reservado ou resolvedor publico conhecido"

    octetos = [int(o) for o in ip.split(".")]
    primeiro, segundo = octetos[0], octetos[1]

    # Faixas que nao podem ser um C2 na internet.
    if primeiro == 0:
        return Confianca.BAIXA, "faixa 0.0.0.0/8 (invalida como destino)"
    if primeiro == 127:
        return Confianca.BAIXA, "loopback"
    if primeiro == 169 and segundo == 254:
        return Confianca.BAIXA, "link-local (APIPA)"
    if primeiro >= 224:
        return Confianca.BAIXA, "multicast ou reservado"

    # Contexto textual explicito de versao.
    if any(pista in texto.lower() for pista in PISTAS_DE_VERSAO):
        return Confianca.BAIXA, "string menciona versao/build"

    # Primeiro octeto de um digito: quase sempre versao. Os blocos 1.0.0.0/8
    # a 9.0.0.0/8 existem e sao roteaveis, mas aparecem muito pouco como C2
    # em amostra real, enquanto "1.x.y.z" de versao aparece o tempo todo.
    if primeiro < 10:
        return Confianca.BAIXA, "primeiro octeto de um digito: provavel numero de versao"

    # RFC 1918: e um IOC legitimo (C2 interno, movimento lateral), mas nao
    # serve para busca externa - o Shodan nao vai ter nada sobre ele.
    if (
        primeiro == 10
        or (primeiro == 172 and 16 <= segundo <= 31)
        or (primeiro == 192 and segundo == 168)
    ):
        return Confianca.MEDIA, "endereco privado (RFC 1918)"

    return Confianca.MEDIA, ""


def _dominio_plausivel(dominio: str) -> tuple[bool, str]:
    """
    Valida um candidato a dominio.

    Devolve (aceito, motivo_da_rejeicao). O filtro que mais importa aqui e o
    de extensao de arquivo: sem ele, todo "kernel32.dll" vira dominio.
    """
    tld = dominio.rsplit(".", 1)[-1].lower()

    if tld in EXTENSOES_ARQUIVO:
        return False, f"'{tld}' e extensao de arquivo, nao TLD"
    if tld not in TLDS_VALIDOS:
        return False, f"TLD '{tld}' desconhecido"
    if len(dominio) > 253:
        return False, "excede o tamanho maximo de um FQDN"

    return True, ""


def _detectar_em_string(s: StringExtraida) -> Iterator[IOC]:
    """Aplica todas as regras de IOC sobre uma unica string."""
    texto = s.valor

    def ioc(
        valor: str,
        tipo: TipoIOC,
        confianca: Confianca,
        obs: str = "",
    ) -> IOC:
        return IOC(
            valor=valor,
            tipo=tipo,
            confianca=confianca,
            origem=texto,
            tipo_string=s.tipo,
            observacao=obs,
        )

    # --- URL: formato inequivoco, confianca alta ---
    urls = [m.group().rstrip(".,;:)]}\"'") for m in RE_URL.finditer(texto)]
    for url in urls:
        yield ioc(url, TipoIOC.URL, Confianca.ALTA)

    # --- E-mail ---
    emails = [m.group() for m in RE_EMAIL.finditer(texto)]
    for email in emails:
        yield ioc(email, TipoIOC.EMAIL, Confianca.ALTA)

    # --- IPv4 ---
    for m in RE_IPV4.finditer(texto):
        endereco = m.group()
        dentro_de_url = any(endereco in url for url in urls)
        confianca, observacao = _classificar_ipv4(texto, endereco, dentro_de_url)
        yield ioc(endereco, TipoIOC.IPV4, confianca, observacao)

    # --- IPv6 ---
    for m in RE_IPV6.finditer(texto):
        valor = m.group()
        # Fragmentos muito curtos nao dizem nada.
        if len(valor.replace(":", "")) >= 4:
            yield ioc(valor, TipoIOC.IPV6, Confianca.MEDIA)

    # --- Dominio ---
    for m in RE_DOMINIO.finditer(texto):
        dominio = m.group()
        if any(dominio in email for email in emails):
            continue  # ja contabilizado como e-mail
        aceito, _motivo = _dominio_plausivel(dominio)
        if not aceito:
            continue
        if any(dominio in url for url in urls):
            yield ioc(dominio, TipoIOC.DOMINIO, Confianca.ALTA, "aparece dentro de uma URL")
        else:
            yield ioc(dominio, TipoIOC.DOMINIO, Confianca.MEDIA)

    # --- Chave de registro ---
    for m in RE_CHAVE_REGISTRO.finditer(texto):
        yield ioc(m.group(), TipoIOC.CHAVE_REGISTRO, Confianca.ALTA)
    for m in RE_CHAVE_REGISTRO_RELATIVA.finditer(texto):
        yield ioc(
            m.group(),
            TipoIOC.CHAVE_REGISTRO,
            Confianca.MEDIA,
            "sem prefixo de hive",
        )

    # --- Caminho UNC (antes do local: "\\host\share" e evidencia mais forte) ---
    for m in RE_CAMINHO_UNC.finditer(texto):
        yield ioc(m.group(), TipoIOC.CAMINHO_UNC, Confianca.ALTA)

    # --- Caminho local ---
    for m in RE_CAMINHO_WINDOWS.finditer(texto):
        caminho = m.group()
        if len(caminho) > 3:  # descarta "C:\" solto
            yield ioc(caminho, TipoIOC.CAMINHO_WINDOWS, Confianca.MEDIA)

    # --- Hash embutido ---
    for m in RE_HASH.finditer(texto):
        yield ioc(m.group(), TipoIOC.HASH, Confianca.MEDIA, "hash embutido no binario")

    # --- Carteira Bitcoin (tipico de ransomware) ---
    for m in RE_BITCOIN.finditer(texto):
        yield ioc(m.group(), TipoIOC.BITCOIN, Confianca.MEDIA)


def detectar_iocs(strings: Sequence[StringExtraida]) -> list[IOC]:
    """
    Varre todas as strings e devolve os IOCs sem duplicata.

    A deduplicacao e por (valor, tipo), mantendo a ocorrencia de maior
    confianca: o mesmo IP pode aparecer solto numa string e dentro de uma URL
    em outra, e a segunda e a evidencia que vale.
    """
    melhores: dict[tuple[str, TipoIOC], IOC] = {}

    for s in strings:
        for candidato in _detectar_em_string(s):
            chave = (candidato.valor, candidato.tipo)
            atual = melhores.get(chave)
            if atual is None or PESO_CONFIANCA[candidato.confianca] > PESO_CONFIANCA[atual.confianca]:
                melhores[chave] = candidato

    return sorted(
        melhores.values(),
        key=lambda i: (i.tipo.value, -PESO_CONFIANCA[i.confianca], i.valor),
    )


# ============================================================
# API principal
# ============================================================


def _hashes(dados: bytes) -> tuple[str, str]:
    """Calcula MD5 e SHA256 do artefato (o MD5 e so para lookup no VirusTotal)."""
    return hashlib.md5(dados).hexdigest(), hashlib.sha256(dados).hexdigest()


def _rodar_floss_com_deteccao(
    caminho: Path,
    dados: bytes,
    tamanho_minimo: int,
    timeout: int,
    formato: str,
) -> tuple[list[StringExtraida], list[str], str]:
    """
    Roda o FLOSS escolhendo o formato adequado ao artefato.

    O "auto" do proprio FLOSS so reconhece PE: shellcode cru nao tem
    cabecalho de onde deduzir a arquitetura, e ele recusa o arquivo pedindo
    --format. Como shellcode e artefato comum em CTI (beacon, payload de
    exploit, dropper ja extraido), vale tentar as duas arquiteturas em vez
    de desistir.

    Devolve (strings, avisos, formato efetivamente usado).
    """
    if formato in FORMATOS_FLOSS:
        strings, avisos = _rodar_floss(caminho, tamanho_minimo, timeout, formato)
        return strings, avisos, formato

    # Arquivo com cabecalho de PE: o caminho normal resolve.
    if dados[:2] == b"MZ":
        strings, avisos = _rodar_floss(caminho, tamanho_minimo, timeout)
        return strings, avisos, "pe"

    try:
        strings, avisos = _rodar_floss(caminho, tamanho_minimo, timeout)
        return strings, avisos, "auto"
    except RuntimeError as erro:
        if RECUSA_DE_SHELLCODE not in str(erro):
            raise

    # O FLOSS pediu o formato: tenta as duas arquiteturas e fica com a que
    # recuperar mais strings de runtime, que sao o motivo de usar o FLOSS.
    melhor: tuple[list[StringExtraida], list[str], str] | None = None
    melhor_pontuacao = -1

    for arquitetura in ("sc32", "sc64"):
        try:
            strings, avisos = _rodar_floss(
                caminho, tamanho_minimo, timeout, arquitetura
            )
        except RuntimeError as erro:
            logger.debug("FLOSS com %s falhou: %s", arquitetura, erro)
            continue

        de_runtime = sum(1 for s in strings if s.tipo is not TipoString.STATIC)
        if de_runtime > melhor_pontuacao:
            melhor_pontuacao = de_runtime
            melhor = (strings, avisos, arquitetura)

    if melhor is None:
        raise RuntimeError(
            "o artefato nao e PE e o FLOSS nao conseguiu analisa-lo como "
            "shellcode de 32 nem de 64 bits"
        )

    strings, avisos, arquitetura = melhor
    avisos.append(
        f"artefato analisado como shellcode {arquitetura}: nao ha cabecalho "
        "de PE, entao a arquitetura foi deduzida por tentativa"
    )
    return strings, avisos, arquitetura


def extrair(
    caminho: str | Path,
    tamanho_minimo: int = TAMANHO_MINIMO_PADRAO,
    usar_floss: bool = True,
    timeout: int = TIMEOUT_FLOSS_PADRAO,
    formato: str = "auto",
) -> ResultadoExtracao:
    """
    Extrai strings e IOCs de um artefato.

    Args:
        caminho: arquivo a analisar.
        tamanho_minimo: descarta strings menores que isso.
        usar_floss: se False, pula direto para o extrator nativo (util em
            teste, onde a emulacao custa caro e nao acrescenta nada).
        timeout: limite em segundos para o FLOSS.
        formato: "auto", "pe", "sc32" ou "sc64". Em "auto", artefato sem
            cabecalho de PE e tentado como shellcode nas duas arquiteturas.

    Returns:
        ResultadoExtracao com strings, IOCs, hashes e avisos.

    Raises:
        ErroExtracao: arquivo inexistente, vazio ou ilegivel.
    """
    caminho = Path(caminho)

    if not caminho.is_file():
        raise ErroExtracao(f"arquivo nao encontrado: {caminho}")

    try:
        dados = caminho.read_bytes()
    except OSError as erro:
        raise ErroExtracao(f"nao foi possivel ler {caminho}: {erro}") from erro

    if not dados:
        raise ErroExtracao(f"arquivo vazio: {caminho}")

    md5, sha256 = _hashes(dados)
    resultado = ResultadoExtracao(
        caminho=str(caminho.resolve()),
        tamanho_bytes=len(dados),
        md5=md5,
        sha256=sha256,
    )

    if usar_floss:
        try:
            strings, avisos, usado = _rodar_floss_com_deteccao(
                caminho, dados, tamanho_minimo, timeout, formato
            )
            resultado.strings = strings
            resultado.avisos.extend(avisos)
            resultado.usou_floss = True
            resultado.formato_floss = usado
        except RuntimeError as erro:
            # Nao e fatal: o extrator nativo ainda entrega strings estaticas.
            logger.warning("FLOSS indisponivel, usando extrator nativo (%s)", erro)
            resultado.avisos.append(
                f"FLOSS nao pode ser usado ({erro}); apenas strings estaticas"
            )

    if not resultado.usou_floss:
        resultado.strings = _extrair_nativo(dados, tamanho_minimo)

    resultado.iocs = detectar_iocs(resultado.strings)

    logger.info("extracao concluida: %s", resultado.resumo())
    return resultado


# ============================================================
# Execucao direta (teste rapido do modulo)
# ============================================================


def _main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extrai strings e IOCs de um artefato (RabMapper)."
    )
    parser.add_argument("arquivo", help="caminho do artefato")
    parser.add_argument(
        "-n", "--min", type=int, default=TAMANHO_MINIMO_PADRAO,
        help="tamanho minimo da string",
    )
    parser.add_argument(
        "--sem-floss", action="store_true", help="usa apenas o extrator nativo"
    )
    parser.add_argument("--json", action="store_true", help="saida em JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        resultado = extrair(args.arquivo, args.min, usar_floss=not args.sem_floss)
    except ErroExtracao as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(resultado.to_dict(), indent=2, ensure_ascii=False))
        return 0

    print(f"\nArquivo : {resultado.caminho}")
    print(f"Tamanho : {resultado.tamanho_bytes} bytes")
    print(f"SHA256  : {resultado.sha256}")
    print(f"MD5     : {resultado.md5}")
    print(f"FLOSS   : {'sim' if resultado.usou_floss else 'nao (extrator nativo)'}")

    for aviso in resultado.avisos:
        print(f"  aviso: {aviso}")

    print(f"\nStrings : {resultado.resumo()}")

    if resultado.iocs:
        print(f"\nIOCs ({len(resultado.iocs)}):")
        for i in resultado.iocs:
            obs = f"  <- {i.observacao}" if i.observacao else ""
            print(f"  [{i.confianca.value:5}] {i.tipo.value:16} {i.valor}{obs}")
    else:
        print("\nNenhum IOC identificado.")

    return 0


if __name__ == "__main__":
    sys.exit(_main())
