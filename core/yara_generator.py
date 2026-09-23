"""
Geracao e validacao de regras YARA.

Uma regra YARA util precisa acertar dois alvos ao mesmo tempo: casar com a
familia de malware e nao casar com software legitimo. Regra gerada
automaticamente costuma falhar no segundo, porque as strings mais frequentes
de um binario sao justamente as menos distintivas - "kernel32.dll",
"GetProcAddress", faixas de copyright do compilador. Essas casariam com meio
Windows.

Por isso a selecao de strings e o coracao do modulo:

  1. Descarte    - lista de bloqueio de artefato de compilador e runtime,
                   nomes de API que ja estao na tabela de imports.
  2. Pontuacao   - premia o que e improvavel de aparecer em software normal:
                   comprimento, variedade de caracteres, strings vindas de
                   IOC, e principalmente strings stack/decoded, que sao do
                   proprio malware e nao do compilador.
  3. Validacao   - a regra e compilada e testada contra o proprio artefato
                   antes de ser salva. Se nao casar, o limiar e afrouxado e
                   testado de novo. Regra que nao pega o proprio sample nao
                   sai daqui.
  4. Verificacao - opcionalmente testada contra binarios benignos; se casar
                   com algum, isso vira aviso explicito na regra.
"""

from __future__ import annotations

import logging
import re
import string as _string
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

import yara

from core.deobfuscator import ResultadoDesofuscacao, entropia_shannon
from core.pe_analyzer import InfoPE
from core.string_extractor import ResultadoExtracao, StringExtraida, TipoString

logger = logging.getLogger(__name__)


# Quantidade de strings na regra. Poucas demais e a regra fica fraca;
# muitas demais e ela fica presa a uma amostra so.
MAXIMO_DE_STRINGS = 20

# Fracao das strings que precisa casar. 0.4 de 20 = 8 strings: exige
# evidencia real sem quebrar com pequena variacao entre versoes da familia.
FRACAO_PARA_CASAR = 0.4

# Comprimento aceitavel. Curta demais casa com qualquer coisa; longa demais
# costuma ser dado especifico daquele build (caminho de PDB, GUID).
COMPRIMENTO_MINIMO = 6
COMPRIMENTO_MAXIMO = 120

# Margem do filesize na condicao, para tolerar variacao entre amostras.
FATOR_FILESIZE = 3


# ============================================================
# Lista de bloqueio
# ============================================================

# Trechos que, se aparecem na string, a desqualificam. Sao artefatos de
# compilador, runtime e do proprio Windows - presentes em tanto software
# legitimo que so gerariam falso positivo.
TRECHOS_GENERICOS = (
    "microsoft", "windows nt", "copyright", "visual c++", "msvcrt",
    "api-ms-win-", "ucrtbase", "vcruntime", "mscoree", "kernel32",
    "advapi32", "user32", "gdi32", "shell32", "ole32", "oleaut32",
    "ntdll", "rpcrt4", "shlwapi", "comctl32", "comdlg32", "ws2_32",
    "runtime error", "assertion failed", "invalid argument",
    "operator new", "bad_alloc", "std::", "__cxa", "_purecall",
    "getprocaddress", "loadlibrary", "virtualalloc", "virtualprotect",
    "getmodulehandle", "exitprocess", "gettickcount", "closehandle",
    "this program cannot be run in dos mode",
    "richedit", ".?av", "?.?a", "mingw", "gcc:", "glibc",
    "python3", "site-packages", "\\program files\\",
    "openssl", "zlib", "libcrypto", "boost",
)

# Strings exatas que nao dizem nada, mesmo quando longas.
STRINGS_EXATAS_BLOQUEADAS = frozenset(
    {
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789abcdef",
        "0123456789ABCDEF",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    }
)

# Padroes inteiros sem valor distintivo.
RE_SO_DIGITOS = re.compile(r"^[\d\s.,:_-]+$")
RE_SO_SIMBOLOS = re.compile(r"^[^\w]+$")
RE_VERSAO = re.compile(r"^\d+(\.\d+){1,3}$")
RE_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$")

# APIs cuja combinacao e indicativa. Usadas na condicao da regra via modulo
# pe, e nao como string, porque o nome pode estar so na tabela de imports.
APIS_DE_INTERESSE = (
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "VirtualAllocEx",
    "QueueUserAPC",
    "CryptEncrypt",
    "CryptGenKey",
    "InternetOpenUrl",
    "HttpSendRequest",
    "URLDownloadToFile",
    "WinHttpConnect",
    "RegSetValueEx",
    "CreateServiceA",
    "CreateServiceW",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "CreateToolhelp32Snapshot",
    "Process32First",
)


# ============================================================
# Tipos
# ============================================================


@dataclass(frozen=True)
class StringCandidata:
    """Uma string avaliada para entrar na regra."""

    valor: str
    pontuacao: float
    origem: TipoString
    motivo: str
    # True quando a string tambem aparece em UTF-16LE no binario.
    tambem_wide: bool = False


@dataclass
class RegraYara:
    """A regra gerada e o resultado da sua validacao."""

    nome: str
    texto: str
    strings_usadas: list[StringCandidata] = field(default_factory=list)
    minimo_para_casar: int = 0

    # Validacao
    compila: bool = False
    casa_com_a_amostra: bool = False
    falsos_positivos: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    @property
    def valida(self) -> bool:
        """Regra so e utilizavel se compila e pega o proprio artefato."""
        return self.compila and self.casa_com_a_amostra

    def to_dict(self) -> dict:
        return asdict(self)


class ErroGeracaoYara(Exception):
    """Nao foi possivel gerar uma regra utilizavel."""


# ============================================================
# Selecao de strings
# ============================================================


def _descartar(valor: str) -> str:
    """
    Decide se a string deve ser descartada.

    Devolve o motivo do descarte, ou string vazia se ela passa.
    """
    if not (COMPRIMENTO_MINIMO <= len(valor) <= COMPRIMENTO_MAXIMO):
        return "comprimento fora da faixa útil"

    if valor in STRINGS_EXATAS_BLOQUEADAS:
        return "alfabeto ou tabela conhecida"

    minusculo = valor.lower()
    for trecho in TRECHOS_GENERICOS:
        if trecho in minusculo:
            return f"contém artefato genérico '{trecho}'"

    if RE_SO_DIGITOS.match(valor):
        return "apenas dígitos e pontuação"
    if RE_SO_SIMBOLOS.match(valor):
        return "apenas símbolos"
    if RE_VERSAO.match(valor):
        return "número de versão"
    if RE_GUID.match(valor):
        return "GUID (específico deste build)"

    # Precisa ser majoritariamente imprimivel e conter alguma letra.
    if not any(c.isalpha() for c in valor):
        return "sem nenhuma letra"

    imprimiveis = sum(1 for c in valor if c in _string.printable)
    if imprimiveis / len(valor) < 0.95:
        return "contém caracteres não imprimíveis"

    # Sequencia de um caractere so repetido nao identifica nada.
    if len(set(valor)) <= 2:
        return "variedade de caracteres insuficiente"

    return ""


def _pontuar_string(
    s: StringExtraida,
    valores_de_ioc: set[str],
    apis_importadas: set[str],
) -> tuple[float, str]:
    """
    Nota de "unicidade" da string: quao improvavel e encontra-la em
    software legitimo.

    Devolve (nota, motivo principal da nota).
    """
    valor = s.valor
    nota = 0.0
    motivos: list[str] = []

    # Origem e o sinal mais forte. Stack, tight e decoded existem porque o
    # malware as montou em runtime - compilador nao produz isso.
    if s.tipo in (TipoString.STACK, TipoString.TIGHT, TipoString.DECODED):
        nota += 0.40
        motivos.append(f"string {s.tipo.value} (construída em runtime)")

    # String que gerou IOC e o que se quer caçar.
    if valor in valores_de_ioc:
        nota += 0.30
        motivos.append("origem de IOC")

    # Nome de API que ja esta na tabela de imports nao acrescenta nada como
    # string: a condicao da regra cobre isso pelo modulo pe.
    if valor in apis_importadas:
        nota -= 0.35
        motivos.append("já coberta pela tabela de imports")

    # Comprimento: mais longa, mais especifica - ate o ponto em que vira
    # dado exclusivo daquele build.
    if 16 <= len(valor) <= 64:
        nota += 0.20
        motivos.append("comprimento específico")
    elif len(valor) >= 10:
        nota += 0.10

    # Entropia moderada indica texto real e distintivo. Muito baixa e
    # repeticao; muito alta costuma ser dado codificado, que muda entre
    # amostras da mesma familia.
    ent = entropia_shannon(valor)
    if 3.2 <= ent <= 5.0:
        nota += 0.15
        motivos.append("entropia de texto distintivo")
    elif ent > 5.5:
        nota -= 0.15
        motivos.append("entropia alta: provável dado codificado")

    # Mistura de maiuscula, minuscula, digito e simbolo e rara em texto de
    # compilador e comum em nome de mutex, chave e user-agent de malware.
    classes = sum(
        [
            any(c.isupper() for c in valor),
            any(c.islower() for c in valor),
            any(c.isdigit() for c in valor),
            any(not c.isalnum() for c in valor),
        ]
    )
    if classes >= 3:
        nota += 0.10

    # Espaco indica frase; frase costuma ser mensagem do proprio malware
    # (nota de resgate, log interno).
    if " " in valor.strip():
        nota += 0.05

    return max(0.0, min(1.0, nota)), "; ".join(motivos) or "string estática comum"


def selecionar_strings(
    extracao: ResultadoExtracao,
    desofuscacao: ResultadoDesofuscacao | None = None,
    info_pe: InfoPE | None = None,
    maximo: int = MAXIMO_DE_STRINGS,
) -> list[StringCandidata]:
    """
    Escolhe as strings mais distintivas para a regra.

    Args:
        extracao: saida do string_extractor.
        desofuscacao: se informada, o conteudo revelado tambem concorre -
            string decodificada e excelente material para regra, porque
            identifica a familia e nao a amostra.
        info_pe: usada para nao repetir como string o que ja esta na
            tabela de imports.
        maximo: quantas strings entram na regra.
    """
    valores_de_ioc = {i.origem for i in extracao.iocs}
    apis_importadas = set(info_pe.todas_as_apis()) if info_pe else set()

    candidatas: dict[str, StringCandidata] = {}
    wide: set[str] = {
        s.valor for s in extracao.strings if s.encoding.upper().startswith("UTF-16")
    }

    fontes: list[StringExtraida] = list(extracao.strings)
    if desofuscacao:
        # O conteudo decodificado entra como se fosse string do binario.
        fontes.extend(
            StringExtraida(valor=a.decodificado, tipo=a.tipo_string)
            for a in desofuscacao.achados
        )

    for s in fontes:
        valor = s.valor.strip()
        if valor in candidatas:
            continue
        if _descartar(valor):
            continue

        nota, motivo = _pontuar_string(s, valores_de_ioc, apis_importadas)
        if nota <= 0.0:
            continue

        candidatas[valor] = StringCandidata(
            valor=valor,
            pontuacao=round(nota, 3),
            origem=s.tipo,
            motivo=motivo,
            tambem_wide=valor in wide,
        )

    ordenadas = sorted(candidatas.values(), key=lambda c: (-c.pontuacao, -len(c.valor)))
    return ordenadas[:maximo]


# ============================================================
# Montagem do texto da regra
# ============================================================


def _escapar(valor: str) -> str:
    """Escapa a string para o formato de texto do YARA."""
    return valor.replace("\\", "\\\\").replace('"', '\\"')


def _sem_acento(texto: str) -> str:
    """
    Remove os acentos de um texto nosso que vai para dentro da regra.

    Avisos e motivos sao mensagens ao usuario, acentuadas, mas tambem entram
    no meta e nos comentarios do .yar. A regra e feita para ser compartilhada
    e processada por outras ferramentas; mante-la em ASCII preserva o texto
    que ela sempre teve. Nao se aplica as strings do artefato ($s*).
    """
    decomposto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in decomposto if not unicodedata.combining(c))


def _nome_de_regra(base: str) -> str:
    """
    Converte um nome qualquer em identificador valido de YARA.

    Identificador nao pode comecar com digito nem conter caractere fora de
    [A-Za-z0-9_].
    """
    limpo = re.sub(r"[^A-Za-z0-9_]", "_", base).strip("_") or "artefato"
    if limpo[0].isdigit():
        limpo = f"r_{limpo}"
    return limpo


def _montar_condicao(
    quantidade: int,
    minimo: int,
    tamanho: int,
    info_pe: InfoPE | None,
) -> tuple[list[str], bool]:
    """
    Monta as clausulas da condicao.

    Devolve (clausulas, usa_modulo_pe). A condicao vai do mais barato para o
    mais caro de avaliar: magic number, depois filesize, e so entao as
    strings - o YARA curto-circuita e isso acelera varredura em massa.
    """
    clausulas: list[str] = []
    usa_pe = False

    if info_pe and info_pe.e_pe:
        clausulas.append("uint16(0) == 0x5A4D")

    clausulas.append(f"filesize < {max(1, (tamanho * FATOR_FILESIZE) // 1024)}KB")

    if info_pe and info_pe.e_pe and info_pe.imphash:
        # O imphash e uma pista forte de familia, mas muda se o autor
        # reordenar os imports. Entra como alternativa, nunca como
        # exigencia, para nao tornar a regra fragil.
        usa_pe = True
        clausulas.append(
            f"(pe.imphash() == \"{info_pe.imphash}\" or {minimo} of ($s*))"
        )
    else:
        clausulas.append(f"{minimo} of ($s*)")

    return clausulas, usa_pe


def _montar_texto(
    nome: str,
    sha256: str,
    md5: str,
    strings: list[StringCandidata],
    minimo: int,
    tamanho: int,
    info_pe: InfoPE | None,
    avisos: list[str],
) -> str:
    """Monta o texto final da regra."""
    clausulas, usa_pe = _montar_condicao(len(strings), minimo, tamanho, info_pe)

    linhas: list[str] = []

    if usa_pe:
        linhas.append('import "pe"')
        linhas.append("")

    linhas.append(f"rule {nome}")
    linhas.append("{")

    # --- meta ---
    linhas.append("    meta:")
    linhas.append('        autor = "Nut-Shell Mapper (gerada automaticamente)"')
    linhas.append(f'        data = "{date.today().isoformat()}"')
    linhas.append(
        '        descricao = "Regra derivada das strings mais distintivas do artefato"'
    )
    linhas.append(f'        sha256 = "{sha256}"')
    linhas.append(f'        md5 = "{md5}"')
    if info_pe and info_pe.e_pe:
        if info_pe.imphash:
            linhas.append(f'        imphash = "{info_pe.imphash}"')
        linhas.append(f'        arquitetura = "{info_pe.arquitetura}"')
    linhas.append(
        '        aviso = "Revisar antes de usar em producao: regra gerada '
        'a partir de uma unica amostra"'
    )
    for i, aviso in enumerate(avisos):
        linhas.append(f'        aviso_{i + 1} = "{_escapar(_sem_acento(aviso))}"')

    # --- strings ---
    linhas.append("")
    linhas.append("    strings:")
    for i, c in enumerate(strings):
        modificadores = " ascii"
        if c.tambem_wide:
            modificadores = " ascii wide"
        # O comentario registra por que a string foi escolhida: sem isso a
        # regra e uma lista opaca e ninguem consegue revisa-la.
        linhas.append(
            f'        $s{i} = "{_escapar(c.valor)}"{modificadores}'
            f"  // {c.pontuacao:.2f} | {c.origem.value} | {_sem_acento(c.motivo)}"
        )

    # --- condicao ---
    linhas.append("")
    linhas.append("    condition:")
    linhas.append("        " + " and\n        ".join(clausulas))
    linhas.append("}")

    return "\n".join(linhas) + "\n"


def _avisar_dado_do_analista(candidatas: list[StringCandidata]) -> list[str]:
    """
    Avisa quando uma string selecionada contem o caminho da propria maquina
    de analise.

    Regra YARA existe para ser compartilhada. Um caminho como
    "C:\\Users\\<seu_usuario>\\..." pode entrar na regra quando o artefato
    foi gerado ou desempacotado localmente, e ai o nome de usuario do
    analista vai junto para o repositorio publico. O aviso fica na propria
    regra, para ser visto na revisao.
    """
    from pathlib import Path as _Path

    avisos: list[str] = []
    casa = str(_Path.home())
    usuario = _Path.home().name

    for c in candidatas:
        if casa.lower() in c.valor.lower():
            avisos.append(
                f"string contém o caminho da máquina de análise "
                f"('{usuario}'): remover antes de publicar a regra"
            )
            break

    return avisos


# ============================================================
# Validacao
# ============================================================


def _compilar(texto: str) -> tuple[yara.Rules | None, str]:
    """Compila a regra. Devolve (regras, mensagem de erro)."""
    try:
        return yara.compile(source=texto), ""
    except yara.SyntaxError as erro:
        return None, str(erro)
    except yara.Error as erro:
        return None, str(erro)


def _casa_com(regras: yara.Rules, caminho: Path) -> bool:
    """Testa a regra contra um arquivo."""
    try:
        return bool(regras.match(str(caminho), timeout=60))
    except yara.Error as erro:
        logger.warning("falha ao testar a regra contra %s: %s", caminho, erro)
        return False


# ============================================================
# API principal
# ============================================================


def gerar(
    caminho: str | Path,
    extracao: ResultadoExtracao,
    desofuscacao: ResultadoDesofuscacao | None = None,
    info_pe: InfoPE | None = None,
    nome_regra: str | None = None,
    maximo_de_strings: int = MAXIMO_DE_STRINGS,
    amostras_benignas: list[str | Path] | None = None,
) -> RegraYara:
    """
    Gera e valida uma regra YARA para o artefato.

    A regra e compilada e testada contra o proprio artefato. Se nao casar, o
    limiar de strings e reduzido progressivamente ate casar - regra que nao
    pega a propria amostra nao e devolvida como valida.

    Args:
        caminho: o artefato que originou a regra.
        extracao: saida do string_extractor.
        desofuscacao: saida do deobfuscator (opcional, melhora muito a regra).
        info_pe: saida do pe_analyzer (opcional).
        nome_regra: nome do identificador YARA. Padrao: derivado do arquivo.
        maximo_de_strings: quantas strings entram na regra.
        amostras_benignas: arquivos legitimos para testar falso positivo.

    Returns:
        RegraYara. Verifique `.valida` antes de salvar.

    Raises:
        ErroGeracaoYara: nenhuma string sobreviveu a selecao.
    """
    caminho = Path(caminho)
    avisos: list[str] = []

    candidatas = selecionar_strings(extracao, desofuscacao, info_pe, maximo_de_strings)

    if not candidatas:
        raise ErroGeracaoYara(
            "nenhuma string distintiva sobreviveu à seleção; "
            "o artefato pode estar empacotado ou ter poucas strings próprias"
        )

    if len(candidatas) < 4:
        avisos.append(
            f"apenas {len(candidatas)} strings distintivas: regra fraca, "
            "propensa a falso positivo"
        )

    avisos.extend(_avisar_dado_do_analista(candidatas))

    nome = _nome_de_regra(nome_regra or f"NutShell_{caminho.stem}")
    minimo = max(1, int(len(candidatas) * FRACAO_PARA_CASAR))

    # Uma lista so de avisos. Ela alimenta tanto o bloco meta da regra
    # quanto o objeto devolvido - se fossem duas, cada lado ficaria com
    # metade dos avisos e quem inspeciona o objeto perderia os que so
    # aparecem no texto.
    regra = RegraYara(nome=nome, texto="", strings_usadas=candidatas, avisos=avisos)

    def montar(limiar: int) -> str:
        return _montar_texto(
            nome=nome,
            sha256=extracao.sha256,
            md5=extracao.md5,
            strings=candidatas,
            minimo=limiar,
            tamanho=extracao.tamanho_bytes,
            info_pe=info_pe,
            avisos=avisos,
        )

    # Afrouxa o limiar ate a regra pegar o proprio artefato. Strings wide,
    # truncamento do FLOSS e strings decodificadas que nao existem literais
    # no arquivo fazem o limiar inicial falhar com frequencia.
    for tentativa_minimo in range(minimo, 0, -1):
        texto = montar(tentativa_minimo)

        regras, erro = _compilar(texto)
        if regras is None:
            regra.texto = texto
            avisos.append(f"erro de compilação: {erro}")
            return regra

        regra.compila = True
        regra.texto = texto
        regra.minimo_para_casar = tentativa_minimo

        if _casa_com(regras, caminho):
            regra.casa_com_a_amostra = True
            if tentativa_minimo < minimo:
                avisos.append(
                    f"limiar reduzido de {minimo} para {tentativa_minimo} "
                    "strings para casar com a própria amostra"
                )
            break

    else:
        avisos.append(
            "a regra não casa com o próprio artefato nem com limiar 1; "
            "as strings selecionadas provavelmente vêm de conteúdo "
            "decodificado que não existe literalmente no arquivo"
        )
        regra.texto = montar(1)
        return regra

    if amostras_benignas:
        regras, _ = _compilar(regra.texto)
        if regras is not None:
            for benigno in amostras_benignas:
                benigno = Path(benigno)
                if benigno.is_file() and _casa_com(regras, benigno):
                    regra.falsos_positivos.append(str(benigno))

            if regra.falsos_positivos:
                avisos.append(
                    f"casou com {len(regra.falsos_positivos)} arquivo(s) benigno(s): "
                    "a regra está genérica demais"
                )

    # Remonta com a lista completa de avisos, para que o bloco meta da regra
    # gravada em disco contenha exatamente o que o objeto reporta.
    regra.texto = montar(regra.minimo_para_casar)

    logger.info(
        "regra '%s' gerada: %d strings, limiar %d, valida=%s",
        regra.nome,
        len(candidatas),
        regra.minimo_para_casar,
        regra.valida,
    )
    return regra


def salvar(regra: RegraYara, destino: str | Path, forcar: bool = False) -> Path:
    """
    Grava a regra em um arquivo .yar.

    Por padrao recusa gravar regra invalida: uma regra que nao compila ou
    nao pega a propria amostra so atrapalha quem for usa-la depois.

    Args:
        regra: a regra gerada.
        destino: caminho do arquivo .yar.
        forcar: grava mesmo assim (util para inspecionar o que deu errado).

    Raises:
        ErroGeracaoYara: regra invalida e forcar=False.
    """
    if not regra.valida and not forcar:
        motivos = "; ".join(regra.avisos) or "motivo desconhecido"
        raise ErroGeracaoYara(f"regra inválida, não será salva ({motivos})")

    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(regra.texto, encoding="utf-8")

    logger.info("regra salva em %s", destino)
    return destino
