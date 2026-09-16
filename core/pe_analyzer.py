"""
Parsing de binarios PE (Portable Executable).

Modulo compartilhado: o yara_generator usa os imports e as secoes de alta
entropia para montar a regra, e o mitre_mapper mapeia as mesmas API calls
para tecnicas ATT&CK. Manter isso num lugar so evita duas implementacoes
divergentes de "quais funcoes este binario importa".

O que sai daqui e descritivo, nao conclusivo. "Secao com entropia 7.9" e um
fato; "esta empacotado com UPX" seria uma conclusao, e cabe ao analista.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pefile

from core.deobfuscator import entropia_shannon

logger = logging.getLogger(__name__)


# Acima disso a secao esta comprimida, cifrada ou empacotada. 7.0 e o valor
# usado pela maioria das ferramentas de triagem; texto e codigo normal
# raramente passam de 6.5.
ENTROPIA_SECAO_ALTA = 7.0

# Secoes com nome fora do padrao sao sinal de empacotador.
NOMES_DE_SECAO_COMUNS = frozenset(
    {
        ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata",
        ".rsrc", ".reloc", ".tls", ".debug", ".didat", ".sdata", ".xdata",
        "CODE", "DATA", "BSS", "INIT", "PAGE",
    }
)


@dataclass(frozen=True)
class Secao:
    """Uma secao do PE."""

    nome: str
    endereco_virtual: int
    tamanho_virtual: int
    tamanho_bruto: int
    entropia: float
    executavel: bool
    gravavel: bool

    @property
    def alta_entropia(self) -> bool:
        """Indica compressao, cifragem ou empacotamento."""
        return self.entropia >= ENTROPIA_SECAO_ALTA

    @property
    def nome_incomum(self) -> bool:
        """Nome fora do conjunto que compiladores normais produzem."""
        return self.nome not in NOMES_DE_SECAO_COMUNS

    @property
    def gravavel_e_executavel(self) -> bool:
        """
        Combinacao classica de codigo automodificavel ou desempacotador.

        Compilador legitimo praticamente nunca produz secao W+X.
        """
        return self.gravavel and self.executavel


@dataclass
class InfoPE:
    """Tudo que foi extraido do cabecalho PE."""

    e_pe: bool = False
    # Motivo de nao ter sido possivel parsear, quando e_pe e False.
    erro: str = ""

    arquitetura: str = ""
    tipo: str = ""  # EXE, DLL, SYS
    timestamp_compilacao: str = ""
    # Hash da tabela de imports. Mesmo compilador + mesma ordem de imports
    # produzem o mesmo imphash: e uma das melhores pistas de familia.
    imphash: str = ""

    # dll (minusculo) -> funcoes importadas
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    secoes: list[Secao] = field(default_factory=list)
    # Tipos de recurso embutidos (RT_RCDATA costuma esconder payload).
    tipos_de_recurso: list[str] = field(default_factory=list)

    # Observacoes objetivas, sem concluir nada.
    indicios: list[str] = field(default_factory=list)

    def todas_as_apis(self) -> list[str]:
        """Todas as funcoes importadas, sem separar por DLL."""
        return [funcao for funcoes in self.imports.values() for funcao in funcoes]

    def importa(self, funcao: str) -> bool:
        """Se o binario importa determinada API (sem diferenciar maiuscula)."""
        alvo = funcao.lower()
        return any(f.lower() == alvo for f in self.todas_as_apis())

    def secoes_suspeitas(self) -> list[Secao]:
        """Secoes que merecem atencao: alta entropia, nome incomum ou W+X."""
        return [
            s
            for s in self.secoes
            if s.alta_entropia or s.nome_incomum or s.gravavel_e_executavel
        ]

    def resumo(self) -> dict:
        return {
            "e_pe": self.e_pe,
            "arquitetura": self.arquitetura,
            "tipo": self.tipo,
            "dlls": len(self.imports),
            "apis": len(self.todas_as_apis()),
            "secoes": len(self.secoes),
            "secoes_suspeitas": len(self.secoes_suspeitas()),
            "indicios": len(self.indicios),
        }

    def to_dict(self) -> dict:
        return asdict(self)


def _formatar_timestamp(bruto: int) -> str:
    """
    Converte o TimeDateStamp do PE para ISO 8601.

    O valor e frequentemente falsificado por malware, entao vale como
    indicio e nao como fato - por isso ele so e registrado, nunca usado
    para decidir nada.
    """
    try:
        return datetime.fromtimestamp(bruto, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _ler_secoes(pe: pefile.PE) -> list[Secao]:
    """Extrai as secoes com entropia calculada sobre os bytes brutos."""
    secoes: list[Secao] = []

    for s in pe.sections:
        nome = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        dados = s.get_data()
        caracteristicas = s.Characteristics

        secoes.append(
            Secao(
                nome=nome,
                endereco_virtual=s.VirtualAddress,
                tamanho_virtual=s.Misc_VirtualSize,
                tamanho_bruto=s.SizeOfRawData,
                entropia=round(entropia_shannon(dados), 3),
                executavel=bool(caracteristicas & 0x20000000),  # MEM_EXECUTE
                gravavel=bool(caracteristicas & 0x80000000),  # MEM_WRITE
            )
        )

    return secoes


def _ler_imports(pe: pefile.PE) -> dict[str, list[str]]:
    """
    Extrai a tabela de imports.

    Funcao importada apenas por ordinal (sem nome) vira "ordinal_N": o numero
    ainda identifica a funcao dentro daquela DLL, e algumas, como ws2_32, sao
    quase sempre importadas assim.
    """
    imports: dict[str, list[str]] = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entrada in pe.DIRECTORY_ENTRY_IMPORT:
        dll = (entrada.dll or b"").decode("ascii", "replace").lower()
        if not dll:
            continue

        funcoes = imports.setdefault(dll, [])
        for simbolo in entrada.imports:
            if simbolo.name:
                funcoes.append(simbolo.name.decode("ascii", "replace"))
            elif simbolo.ordinal is not None:
                funcoes.append(f"ordinal_{simbolo.ordinal}")

    return imports


def _ler_exports(pe: pefile.PE) -> list[str]:
    """Funcoes exportadas (relevante em DLL maliciosa)."""
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []

    return [
        s.name.decode("ascii", "replace")
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols
        if s.name
    ]


def _ler_tipos_de_recurso(pe: pefile.PE) -> list[str]:
    """Tipos de recurso embutidos. RT_RCDATA costuma carregar payload."""
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return []

    tipos: set[str] = set()
    for entrada in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entrada.name is not None:
            tipos.add(str(entrada.name))
        elif entrada.id is not None:
            tipos.add(pefile.RESOURCE_TYPE.get(entrada.id, f"id_{entrada.id}"))

    return sorted(tipos)


def _levantar_indicios(info: InfoPE) -> list[str]:
    """
    Registra observacoes objetivas sobre o cabecalho.

    Cada item e um fato verificavel, nao um veredito. "Nenhuma DLL
    importada" e um fato; "esta empacotado" seria conclusao.
    """
    indicios: list[str] = []

    for s in info.secoes:
        if s.alta_entropia:
            indicios.append(
                f"secao '{s.nome}' com entropia {s.entropia} "
                f"(>= {ENTROPIA_SECAO_ALTA}): comprimida, cifrada ou empacotada"
            )
        if s.nome_incomum:
            indicios.append(f"secao '{s.nome}' com nome fora do padrao de compilador")
        if s.gravavel_e_executavel:
            indicios.append(
                f"secao '{s.nome}' e gravavel e executavel (W+X): "
                "codigo automodificavel ou desempacotador"
            )
        # Secao declarada muito maior na memoria do que no arquivo indica
        # espaco reservado para desempacotar em runtime.
        if s.tamanho_bruto == 0 and s.tamanho_virtual > 0:
            indicios.append(
                f"secao '{s.nome}' sem dado no arquivo mas com {s.tamanho_virtual} "
                "bytes reservados em memoria"
            )

    if not info.imports:
        indicios.append(
            "nenhuma DLL importada: tabela de imports destruida ou "
            "resolvida em runtime"
        )
    elif len(info.todas_as_apis()) < 10:
        indicios.append(
            f"apenas {len(info.todas_as_apis())} funcoes importadas: "
            "poucas para um programa funcional, sugere resolucao dinamica"
        )

    if "RT_RCDATA" in info.tipos_de_recurso:
        indicios.append("recurso RT_RCDATA presente: pode conter payload embutido")

    return indicios


def analisar(caminho: str | Path) -> InfoPE:
    """
    Analisa o cabecalho PE de um arquivo.

    Nao levanta excecao para arquivo nao-PE: devolve InfoPE(e_pe=False) com
    o motivo. O pipeline precisa seguir mesmo quando o artefato e um script,
    um documento ou um dump de memoria.
    """
    caminho = Path(caminho)

    try:
        pe = pefile.PE(str(caminho), fast_load=False)
    except pefile.PEFormatError as erro:
        logger.debug("%s nao e um PE: %s", caminho, erro)
        return InfoPE(e_pe=False, erro=str(erro))
    except OSError as erro:
        return InfoPE(e_pe=False, erro=f"nao foi possivel ler o arquivo: {erro}")

    try:
        cabecalho = pe.FILE_HEADER
        opcional = pe.OPTIONAL_HEADER

        if opcional.Magic == 0x20B:
            arquitetura = "x64"
        elif opcional.Magic == 0x10B:
            arquitetura = "x86"
        else:
            arquitetura = f"desconhecida (0x{opcional.Magic:x})"

        if cabecalho.Characteristics & 0x2000:
            tipo = "DLL"
        elif cabecalho.Characteristics & 0x1000:
            tipo = "SYS"
        else:
            tipo = "EXE"

        info = InfoPE(
            e_pe=True,
            arquitetura=arquitetura,
            tipo=tipo,
            timestamp_compilacao=_formatar_timestamp(cabecalho.TimeDateStamp),
            imphash=pe.get_imphash(),
            imports=_ler_imports(pe),
            exports=_ler_exports(pe),
            secoes=_ler_secoes(pe),
            tipos_de_recurso=_ler_tipos_de_recurso(pe),
        )
        info.indicios = _levantar_indicios(info)

    finally:
        pe.close()

    logger.info("PE analisado: %s", info.resumo())
    return info
